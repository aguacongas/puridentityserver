"""Routes FastAPI de l'OP pour l'émission de credentials OID4VCI (OIDF, slice 1).

Surface montée uniquement lorsque le flag ``oid4vci_enabled`` est actif.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

if TYPE_CHECKING:
    from puridentityserver.application.oid4vci import OID4VCIIssuerUseCase

_JSON_MEDIA_TYPE = "application/json"


def oid4vci_router(
    *,
    issuer: str,
    oid4vci_usecase: OID4VCIIssuerUseCase | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI de l'émetteur OID4VCI.

    ``issuer`` est la valeur du claim ``credential_issuer`` ; sans le flag
    d'activation, aucune route n'est montée. ``oid4vci_usecase`` porte
    l'issuance effectif ; sans lui, ``/credential`` reste ``501``.
    """
    router = APIRouter(tags=["oid4vci"])
    normalized = issuer.rstrip("/")
    usecase = oid4vci_usecase

    @router.get(
        "/.well-known/openid-credential-issuer",
        summary="Métadonnées de l'émetteur OID4VCI (OIDF 1.0 §9.1)",
        response_model=None,
    )
    async def credential_issuer_metadata() -> JSONResponse:
        return JSONResponse(
            {
                "credential_issuer": normalized,
                "authorization_servers": [normalized],
                "credential_endpoint": (f"{normalized}/credential"),
                "credential_configurations_supported": {
                    "puridentityserver-sdjwt-vc": {
                        "format": "vc+sd-jwt",
                        "scope": "openid4vci",
                        "cryptographic_binding_methods_supported": ["jwk"],
                        "credential_signing_alg_values_supported": ["RS256"],
                        "proof_types_supported": {
                            "jwt": {"proof_signing_alg_values_supported": ["RS256"]}
                        },
                    }
                },
            }
        )

    @router.post(
        "/credential",
        summary="Endpoint `/credential` OID4VCI (issuance SD-JWT)",
        response_model=None,
    )
    async def credential(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            return _error(401, "invalid_token", "bearer token requis")
        if usecase is None:
            return _error(
                501,
                "not_implemented",
                "issuance OID4VCI pas encore cablee dans ce deploiement.",
            )
        bearer = authorization[len("Bearer ") :].strip()
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        requested_format = str(payload.get("format") or "vc+sd-jwt")
        proof = payload.get("proof")
        proof_jwt = proof.get("jwt") if isinstance(proof, dict) else None
        if not isinstance(proof_jwt, str):
            proof_jwt = None
        result = await usecase.issue_credential(bearer, requested_format, proof_jwt)
        if result is None:
            return _error(401, "invalid_token", "access token invalide ou scope manquant")
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)

    return router


def _error(status_code: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={"WWW-Authenticate": "Bearer"} if status_code == 401 else None,
        media_type=_JSON_MEDIA_TYPE,
    )
