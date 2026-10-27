"""Routes FastAPI Minimale de l'OP pour l'émission de credentials OID4VCI (OIDF, slice 1).

L'intégration complète de l'issuance (grants, preuves de possession, etc.)
est déclinée par sous-issue #172 ; ici on expose :
- la métadonnée de l'issuer (`/.well-known/openid-credential-issuer`) ;
- `/credential`, qui, dans cet état de développement, répond `501` (point
  d'ancrage pour l'implémentation de l'émission).

Les routes ne sont montées que si le support est activé
(``oid4vci_enabled``).
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

_JSON_MEDIA_TYPE = "application/json"


def oid4vci_router(*, issuer: str) -> APIRouter:
    """Construit le routeur FastAPI de l'émetteur OID4VCI (slice 0 / issue #222).

    ``issuer`` est la valeur du claim ``credential_issuer`` ; sans le flag
    d'activation, aucune route n'est montée. Seule la métadonnée est servie
    actuellement : `/credential` répond `501`.
    """
    router = APIRouter(tags=["oid4vci"])
    normalized = issuer.rstrip("/")

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
        summary="Endpoint `/credential` OID4VCI (protection bearer/token)",
        response_model=None,
    )
    async def credential(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("bearer "):
            return JSONResponse(
                {"error": "invalid_token", "error_description": "bearer token requis"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
                media_type=_JSON_MEDIA_TYPE,
            )
        # Slice 0 : issuance implémentée dans la sous-issue #222 (PID4VCI).
        return JSONResponse(
            {
                "error": "not_implemented",
                "error_description": "issuance OID4VCI pas encore implémentée (slice 0).",
            },
            status_code=501,
            media_type=_JSON_MEDIA_TYPE,
        )

    return router
