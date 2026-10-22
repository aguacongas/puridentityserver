"""Routes FastAPI de la Fédération (OpenID Federation 1.1).

L'OP publie son **entity configuration** (son entity statement auto-signé)
à ``/.well-known/openid-federation`` (spec §9), reçoit les demandes
d'enregistrement explicite des RP sur ``/federation/register`` (spec §12.2)
et joue le rôle de supérieur de ses subordonnés (fetch §8.1, list §8.2,
resolve §8.3).

Les routes ne sont montées que si le support de la Fédération est activé
(``federation_enabled``) : sans lui, aucun chemin n'est exposé.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from puridentityserver.application.federation import (
    FETCH_PATH,
    LIST_PATH,
    RESOLVE_PATH,
    FederationUseCase,
)
from puridentityserver.domain.federation import (
    ENTITY_STATEMENT_MEDIA_TYPE,
    EXPLICIT_REGISTRATION_RESPONSE_MEDIA_TYPE,
    RESOLVE_RESPONSE_MEDIA_TYPE,
    TRUST_CHAIN_MEDIA_TYPE,
    FederationRegistrationError,
)

#: Statut HTTP de chaque code d'erreur (spec §8.9, §12.2.4, §8.2.1 ;
#: ``invalid_client_metadata`` et ``invalid_redirect_uri`` suivent
#: OpenID.Registration §3.3).
_ERROR_STATUS: dict[str, int] = {
    "invalid_request": 400,
    "invalid_client_metadata": 400,
    "invalid_redirect_uri": 400,
    "invalid_trust_chain": 400,
    "invalid_client": 401,
    "not_found": 404,
    "unsupported_parameter": 400,
}

#: Paramètres de filtre du endpoint list, non supportés (spec §8.2.1).
_LIST_PARAMETERS = frozenset({"entity_type", "trust_marked", "trust_mark_type", "intermediate"})


def federation_router(usecase: FederationUseCase) -> APIRouter:
    """Construit le routeur FastAPI de la Fédération (spec §8, §9, §12.2)."""
    router = APIRouter(tags=["federation"])

    @router.get(
        "/.well-known/openid-federation",
        summary="Entity statement de l'OP (entity configuration)",
        response_model=None,
    )
    async def entity_statement() -> Response:
        return await _entity_statement_response(usecase)

    @router.post(
        "/federation/register",
        summary="Enregistrement explicite d'un RP (fédération)",
        response_model=None,
    )
    async def explicit_registration(request: Request) -> Response:
        return await _explicit_registration_response(usecase, request)

    @router.get(
        FETCH_PATH,
        summary="Subordinate statement d'une entité (fédération)",
        response_model=None,
    )
    async def fetch_subordinate(sub: str | None = None) -> Response:
        return await _fetch_subordinate_response(usecase, sub)

    @router.get(
        LIST_PATH,
        summary="Liste des subordonnés immédiats (fédération)",
        response_model=None,
    )
    async def list_subordinates(request: Request) -> Response:
        return await _list_subordinates_response(usecase, request)

    @router.get(
        RESOLVE_PATH,
        summary="Résolution de chaîne de confiance (fédération)",
        response_model=None,
    )
    async def resolve_chain(sub: str | None = None, trust_anchor: str | None = None) -> Response:
        return await _resolve_chain_response(usecase, sub, trust_anchor)

    return router


async def _entity_statement_response(usecase: FederationUseCase) -> Response:
    """Retourne l'entity statement auto-signé de l'OP (spec §9.2).

    Le corps est un JWT en texte (``application/entity-statement+jwt``) :
    l'en-tête ``typ`` vaut ``entity-statement+jwt`` et le ``kid`` désigne
    la clé de signature, publiée dans le claim ``jwks`` du statement.
    """
    statement = await usecase.entity_statement()
    return Response(content=statement, media_type=ENTITY_STATEMENT_MEDIA_TYPE)


async def _explicit_registration_response(usecase: FederationUseCase, request: Request) -> Response:
    """Enregistre un RP à partir de son entity configuration (spec §12.2).

    Le corps est l'entity configuration du RP
    (``application/entity-statement+jwt``) ou une chaîne de confiance JSON
    (``application/trust-chain+json``, spec §12.2.1) ; la réponse 200 porte
    la registration signée au type dédié
    (``application/explicit-registration-response+jwt``). Les refus suivent
    le format d'erreur de §8.9 : ``error`` + ``error_description``.
    """
    try:
        body = (await request.body()).decode("utf-8")
        entity_configuration = _registration_body(request.headers.get("content-type", ""), body)
        statement = await usecase.explicit_register(entity_configuration)
    except FederationRegistrationError as error:
        return _error_response(error)
    return Response(content=statement, media_type=EXPLICIT_REGISTRATION_RESPONSE_MEDIA_TYPE)


async def _fetch_subordinate_response(usecase: FederationUseCase, sub: str | None) -> Response:
    """Retourne le subordinate statement de l'entité ``sub`` (spec §8.1).

    Réponses : ``200`` avec le statement en
    ``application/entity-statement+jwt`` ; ``400`` ``invalid_request`` si
    ``sub`` manque ou vaut l'Entity Identifier de l'OP (§8.1.2) ; ``404``
    ``not_found`` si l'entité n'est pas un subordonné immédiat. Les erreurs
    sont des objets JSON (§8.9).
    """
    if not sub:
        return _json_error("invalid_request", "Missing required sub parameter in request")
    if sub.casefold() == usecase.config.entity_identifier.casefold():
        return _json_error(
            "invalid_request",
            "The sub parameter references the Entity Identifier of the Issuing Entity",
        )
    statement = await usecase.subordinate_statement(sub)
    if statement is None:
        return _json_error("not_found", f"{sub} is not configured as an immediate subordinate")
    return Response(content=statement, media_type=ENTITY_STATEMENT_MEDIA_TYPE)


async def _list_subordinates_response(usecase: FederationUseCase, request: Request) -> Response:
    """Liste les Entity Identifier des subordonnés immédiats (spec §8.2).

    Réponse ``200`` : tableau JSON des identifiants (§8.2.2). Les paramètres
    de filtre ne sont pas supportés : leur présence répond ``400``
    ``unsupported_parameter`` (§8.2.1).
    """
    unsupported = _LIST_PARAMETERS & request.query_params.keys()
    if unsupported:
        return _json_error(
            "unsupported_parameter", f"Unsupported parameter: {sorted(unsupported)[0]}"
        )
    identifiers = await usecase.subordinate_identifiers()
    return JSONResponse(content=identifiers)


async def _resolve_chain_response(
    usecase: FederationUseCase, sub: str | None, trust_anchor: str | None
) -> Response:
    """Résout la chaîne de ``sub`` vers ``trust_anchor`` (spec §8.3).

    Réponse ``200`` : résolution signée en
    ``application/resolve-response+jwt`` (claims ``metadata`` résolues et
    ``trust_chain``, §8.3.2). Erreurs (§8.9) : ``400`` ``invalid_request`` si
    un paramètre obligatoire manque, ``404`` ``not_found`` si la chaîne n'est
    pas résoluble ou si l'ancre demandée échappe au périmètre de l'OP.
    """
    if not sub or not trust_anchor:
        return _json_error("invalid_request", "Missing required sub and trust_anchor parameters")
    response = await usecase.resolve_entity(sub, trust_anchor)
    if response is None:
        return _json_error("not_found", "Trust chain could not be resolved")
    return Response(content=response, media_type=RESOLVE_RESPONSE_MEDIA_TYPE)


def _registration_body(content_type: str, body: str) -> str:
    """Extrait l'entity configuration du corps d'une demande explicite.

    Le corps est soit l'entity configuration elle-même (§12.2.1), soit une
    chaîne de confiance JSON dont le premier statement est l'entity
    configuration du RP (§12.2.2, étape 4). L'en-tête ``trust_chain`` n'est
    pas exploité : la demande est alors traitée à partir de l'EC de son corps,
    ce que la spec autorise explicitement (§12.2.2, étape 5).
    """
    media_type = content_type.split(";")[0].strip().lower()
    if media_type == ENTITY_STATEMENT_MEDIA_TYPE:
        return body.strip()
    if media_type == TRUST_CHAIN_MEDIA_TYPE:
        return _first_statement_of_chain(body)
    raise FederationRegistrationError(
        "invalid_request",
        f"Content-Type non supporté : {media_type or 'absent'} "
        f"(attendu : {ENTITY_STATEMENT_MEDIA_TYPE} ou {TRUST_CHAIN_MEDIA_TYPE})",
    )


def _first_statement_of_chain(body: str) -> str:
    """Premier statement — l'entity configuration du RP — d'une chaîne JSON."""
    try:
        chain = json.loads(body)
    except json.JSONDecodeError:
        raise FederationRegistrationError("invalid_request", "Corps JSON invalide") from None
    if not isinstance(chain, list) or not chain:
        raise FederationRegistrationError(
            "invalid_request", "La chaîne de confiance doit être un tableau non vide de JWT"
        )
    first = chain[0]
    if not isinstance(first, str) or not first.strip():
        raise FederationRegistrationError(
            "invalid_request", "La chaîne de confiance doit être un tableau non vide de JWT"
        )
    return first.strip()


def _error_response(error: FederationRegistrationError) -> JSONResponse:
    """Réponse d'erreur au format §8.9 (``error`` + ``error_description``)."""
    return _json_error(error.code, error.description)


def _json_error(code: str, description: str, status_code: int | None = None) -> JSONResponse:
    """Réponse d'erreur au format §8.9, statut dérivé du code si omis."""
    return JSONResponse(
        status_code=_ERROR_STATUS.get(code, 400) if status_code is None else status_code,
        content={"error": code, "error_description": description},
    )
