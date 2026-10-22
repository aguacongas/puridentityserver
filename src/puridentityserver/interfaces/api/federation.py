"""Routes FastAPI de la Fédération (OpenID Federation 1.1).

L'OP publie son **entity configuration** (son entity statement auto-signé)
à ``/.well-known/openid-federation`` (spec §9) et reçoit les demandes
d'enregistrement explicite des RP sur ``/federation/register`` (spec §12.2).

Les routes ne sont montées que si le support de la Fédération est activé
(``federation_enabled``) : sans lui, aucun chemin n'est exposé.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from puridentityserver.application.federation import FederationUseCase
from puridentityserver.domain.federation import (
    ENTITY_STATEMENT_MEDIA_TYPE,
    EXPLICIT_REGISTRATION_RESPONSE_MEDIA_TYPE,
    TRUST_CHAIN_MEDIA_TYPE,
    FederationRegistrationError,
)

#: Statut HTTP de chaque code d'erreur d'enregistrement (spec §8.9 et §12.2.4 ;
#: ``invalid_client_metadata`` et ``invalid_redirect_uri`` suivent
#: OpenID.Registration §3.3).
_ERROR_STATUS: dict[str, int] = {
    "invalid_request": 400,
    "invalid_client_metadata": 400,
    "invalid_redirect_uri": 400,
    "invalid_trust_chain": 400,
    "invalid_client": 401,
}


def federation_router(usecase: FederationUseCase) -> APIRouter:
    """Construit le routeur FastAPI de la Fédération (spec §9, §12.2)."""
    router = APIRouter(tags=["federation"])

    @router.get(
        "/.well-known/openid-federation",
        summary="Entity statement de l'OP (entity configuration)",
        response_model=None,
    )
    async def entity_statement() -> Response:
        """Retourne l'entity statement auto-signé de l'OP (spec §9.2).

        Le corps est un JWT en texte (``application/entity-statement+jwt``) :
        l'en-tête ``typ`` vaut ``entity-statement+jwt`` et le ``kid`` désigne
        la clé de signature, publiée dans le claim ``jwks`` du statement.
        """
        statement = await usecase.entity_statement()
        return Response(content=statement, media_type=ENTITY_STATEMENT_MEDIA_TYPE)

    @router.post(
        "/federation/register",
        summary="Enregistrement explicite d'un RP (fédération)",
        response_model=None,
    )
    async def explicit_registration(request: Request) -> Response:
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

    return router


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
    return JSONResponse(
        status_code=_ERROR_STATUS.get(error.code, 400),
        content={"error": error.code, "error_description": error.description},
    )
