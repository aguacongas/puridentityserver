"""Routes FastAPI de l'OP pour l'émission de credentials OID4VCI (OIDF, slice 0)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from puridentityserver.application.oid4vci import (
    CREDENTIAL_VCT_PATH,
    CredentialError,
    CredentialOfferUseCase,
    credential_vct,
    issuer_metadata_payload,
)
from puridentityserver.interfaces.api.forwarded import public_url

if TYPE_CHECKING:
    from puridentityserver.application.discovery import DiscoveryUseCase
    from puridentityserver.application.oid4vci import OID4VCIIssuerUseCase

_JSON_MEDIA_TYPE = "application/json"

#: En-têtes des réponses d'offre : ni cache, ni historique navigateur.
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def oid4vci_router(
    *,
    issuer: str,
    oid4vci_usecase: OID4VCIIssuerUseCase | None = None,
    offer_usecase: CredentialOfferUseCase | None = None,
    discovery_usecase: DiscoveryUseCase,
    trust_proxy_headers: bool = False,
) -> APIRouter:
    """Construit le routeur FastAPI de l'émetteur OID4VCI."""
    router = APIRouter(tags=["oid4vci"])
    normalized = issuer.rstrip("/")
    usecase = oid4vci_usecase

    _mount_metadata(router, normalized, usecase)
    _mount_oauth_metadata(router, discovery_usecase)
    _mount_nonce(router, usecase)
    _mount_credential(router, usecase, trust_proxy_headers)
    _mount_credential_offers(router, offer_usecase)
    _mount_deferred(router, usecase, trust_proxy_headers)
    _mount_notification(router, usecase, trust_proxy_headers)
    return router


def _mount_metadata(
    router: APIRouter, normalized: str, usecase: OID4VCIIssuerUseCase | None
) -> None:
    @router.get(
        "/.well-known/openid-credential-issuer",
        summary="Métadonnées de l'émetteur OID4VCI (OIDF 1.0 §9.1)",
        response_model=None,
    )
    @router.get(
        "/.well-known/openid-credential-issuer/",
        include_in_schema=False,
        response_model=None,
    )
    async def credential_issuer_metadata(request: Request) -> Response:
        # OID4VCI 1.0 §12.2.2 : le client peut demander des métadonnées
        # signées en envoyant ``Accept: application/jwt``. Sinon on garde le
        # comportement historique en ``application/json`` non signé.
        accept = request.headers.get("accept", "").lower()
        if usecase is not None and "application/jwt" in accept:
            token = await usecase.signed_issuer_metadata()
            return Response(content=token, media_type="application/jwt")
        return JSONResponse(issuer_metadata_payload(normalized), media_type=_JSON_MEDIA_TYPE)

    @router.get(
        CREDENTIAL_VCT_PATH,
        summary="Type metadata SD-JWT VC du credential publié",
        response_model=None,
    )
    async def credential_type_metadata() -> JSONResponse:
        # SD-JWT VC §6.3.1 : quand ``vct`` est une URL https, la Type
        # Metadata est récupérée à cette même URL.
        return JSONResponse(
            {
                "vct": credential_vct(normalized),
                "name": "PurIdentityServer Example Credential",
                "description": "Credential de demonstration emis par PurIdentityServer",
                "claims": [
                    {
                        "path": ["given_name"],
                        "display": [{"locale": "fr", "label": "Prenom"}],
                    },
                    {
                        "path": ["family_name"],
                        "display": [{"locale": "fr", "label": "Nom"}],
                    },
                ],
            }
        )


def _mount_oauth_metadata(router: APIRouter, discovery_usecase: DiscoveryUseCase) -> None:
    @router.get(
        "/.well-known/oauth-authorization-server",
        summary="Métadonnées OAuth 2.0 AS (OID4VCI)",
        response_model=None,
    )
    async def oauth_authorization_server_metadata() -> JSONResponse:
        # Le serveur d'autorisation est l'OP lui-même : le document de
        # découverte OpenID Connect porte déjà tous les endpoints exigés par
        # RFC 8414 (dont ``pushed_authorization_request_endpoint`` et les
        # algorithmes DPoP). Le republier évite deux sources divergentes.
        return JSONResponse(await discovery_usecase.execute(), media_type=_JSON_MEDIA_TYPE)


def _mount_nonce(router: APIRouter, usecase: OID4VCIIssuerUseCase | None) -> None:
    @router.post(
        "/nonce",
        summary="Endpoint nonce OID4VCI",
        response_model=None,
    )
    async def nonce() -> JSONResponse:
        if usecase is None:
            return _error(
                501,
                "not_implemented",
                "issuance OID4VCI pas encore cablee dans ce deploiement.",
            )
        return JSONResponse(
            await usecase.issue_nonce(),
            media_type=_JSON_MEDIA_TYPE,
            # OID4VCI 1.0 §7 : la réponse nonce ne doit pas être mise en cache.
            headers={"Cache-Control": "no-store"},
        )


def _mount_credential(
    router: APIRouter,
    usecase: OID4VCIIssuerUseCase | None,
    trust_proxy_headers: bool,
) -> None:
    @router.post(
        "/credential",
        summary="Endpoint `/credential` OID4VCI (issuance SD-JWT)",
        response_model=None,
    )
    async def credential(request: Request) -> JSONResponse:
        scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() not in {"bearer", "dpop"} or not bearer.strip():
            return _error(401, "invalid_token", "jeton porteur ou DPoP requis")
        if usecase is None:
            return _error(
                501,
                "not_implemented",
                "issuance OID4VCI pas encore cablee dans ce deploiement.",
            )
        payload = await _json_object(request)
        result = await usecase.issue_credential(
            bearer.strip(),
            credential_configuration_id=_optional_str(payload.get("credential_configuration_id")),
            credential_identifier=_optional_str(payload.get("credential_identifier")),
            requested_format=_optional_str(payload.get("format")),
            proofs=_proof_jwts(payload.get("proofs")),
            auth_scheme=scheme.lower(),
            dpop_proof=request.headers.get("dpop", ""),
            htu=public_url(request, trust_proxy_headers=trust_proxy_headers),
            method=request.method,
        )
        if isinstance(result, CredentialError):
            return _error(result.status_code, result.error, result.error_description)
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)


def _mount_credential_offers(router: APIRouter, usecase: CredentialOfferUseCase | None) -> None:
    @router.post(
        "/credential-offer",
        summary="Creation d'une offre de credential (OID4VCI 1.0 §4.1.1)",
        response_model=None,
    )
    async def create_credential_offer(request: Request) -> JSONResponse:
        scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() not in {"bearer", "dpop"} or not bearer.strip():
            return _error(401, "invalid_token", "jeton porteur ou DPoP requis")
        if usecase is None:
            return _error(
                501,
                "not_implemented",
                "offres de credential pas encore cablees dans ce deploiement.",
            )
        payload = await _json_object(request)
        result = await usecase.create(
            bearer.strip(),
            credential_configuration_ids=_string_list(payload.get("credential_configuration_ids")),
            subject=_optional_str(payload.get("subject")) or "",
            tx_code=payload.get("tx_code") is True,
        )
        if isinstance(result, CredentialError):
            return _error(result.status_code, result.error, result.error_description)
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE, headers=_NO_STORE)

    @router.get(
        "/credential-offer/{offer_id}",
        summary="Dereferencement d'une offre de credential (OID4VCI 1.0 §4.1.2)",
        response_model=None,
    )
    async def resolve_credential_offer(offer_id: str) -> JSONResponse:
        if usecase is None:
            return _error(
                501,
                "not_implemented",
                "offres de credential pas encore cablees dans ce deploiement.",
            )
        result = await usecase.resolve(offer_id)
        if isinstance(result, CredentialError):
            return _error(result.status_code, result.error, result.error_description)
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE, headers=_NO_STORE)


def _mount_deferred(
    router: APIRouter,
    usecase: OID4VCIIssuerUseCase | None,
    trust_proxy_headers: bool,
) -> None:
    @router.post("/deferred_credential", summary="Endpoint deferred OID4VCI", response_model=None)
    async def deferred(request: Request) -> JSONResponse:
        scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() not in {"bearer", "dpop"} or not bearer.strip():
            return _error(401, "invalid_token", "jeton porteur ou DPoP requis")
        if usecase is None:
            return _error(501, "not_implemented", "issuance OID4VCI pas encore cablee.")
        payload = await _json_object(request)
        transaction_id = payload.get("transaction_id")
        tid = transaction_id if isinstance(transaction_id, str) else ""
        result = await usecase.deferred_credential(
            bearer.strip(),
            tid,
            auth_scheme=scheme.lower(),
            dpop_proof=request.headers.get("dpop", ""),
            htu=public_url(request, trust_proxy_headers=trust_proxy_headers),
            method=request.method,
        )
        if isinstance(result, CredentialError):
            return _error(result.status_code, result.error, result.error_description)
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)


def _mount_notification(
    router: APIRouter,
    usecase: OID4VCIIssuerUseCase | None,
    trust_proxy_headers: bool,
) -> None:
    @router.post("/notification", summary="Endpoint notification OID4VCI", response_model=None)
    async def notification(request: Request) -> Response:
        scheme, _, bearer = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() not in {"bearer", "dpop"} or not bearer.strip():
            return _error(401, "invalid_token", "jeton porteur ou DPoP requis")
        if usecase is None:
            return _error(501, "not_implemented", "issuance OID4VCI pas encore cablee.")
        payload = await _json_object(request)
        nid = payload.get("notification_id")
        event = payload.get("event")
        desc = payload.get("event_description")
        notification_id = nid if isinstance(nid, str) else ""
        event_value = event if isinstance(event, str) else ""
        description = desc if isinstance(desc, str) else ""
        err = await usecase.notify(bearer.strip(), notification_id, event_value, description)
        if err is not None:
            return _error(err.status_code, err.error, err.error_description)
        return Response(status_code=204)


async def _json_object(request: Request) -> dict[str, object]:
    """Lit le corps JSON de la requête, ou un objet vide s'il est illisible."""
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _optional_str(value: object) -> str | None:
    """Ramène une valeur JSON optionnelle à une chaîne non vide."""
    return value if isinstance(value, str) and value else None


def _string_list(value: object) -> list[str]:
    """Ramène une valeur JSON optionnelle à une liste de chaînes non vides."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _proof_jwts(proofs: object) -> list[str]:
    """Extrait les preuves JWT de ``proofs.jwt`` (OID4VCI 1.0 §8.2)."""
    if not isinstance(proofs, dict):
        return []
    values = proofs.get("jwt")
    if isinstance(values, str):
        return [values]
    if isinstance(values, list):
        return [value for value in values if isinstance(value, str)]
    return []


def _error(status_code: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
        media_type=_JSON_MEDIA_TYPE,
    )
