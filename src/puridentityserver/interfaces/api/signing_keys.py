"""Route FastAPI de rotation à la demande des clés de signature.

L'endpoint d'administration ``POST /signing-keys/rotate`` force la rotation
des clés de signature de l'OP (OIDC Core 1.0 §10.1) : chaque algorithme
géré reçoit une nouvelle paire, l'ancienne est retirée mais reste publiée
au JWKS pendant la rétention (transition en douceur) et continue de valider
les jetons qu'elle a signés.

La route est protégée par la même autorisation que les autres routes
d'administration (JWT portant le claim configuré, ``scope=admin`` par
défaut) : c'est une opération d'exploitation, pas une operation de
protocole.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Response

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer
from puridentityserver.application.jwks import JWKSetUseCase
from puridentityserver.interfaces.api.security import authorization_dependencies

_JSON_MEDIA_TYPE = "application/json"


def signing_keys_router(
    usecase: JWKSetUseCase,
    *,
    authorizer: BearerClaimAuthorizer | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI exposant la rotation des clés de signature.

    Si ``authorizer`` est fourni, la route exige un JWT portant le claim
    configuré (401 sinon).
    """
    router = APIRouter(tags=["signing-keys"], dependencies=authorization_dependencies(authorizer))

    @router.post(
        "/signing-keys/rotate",
        summary="Rotation des clés de signature",
        response_model=None,
    )
    async def rotate_signing_keys() -> Response:
        """Fait pivoter les clés de signature et renvoie les ``kid`` concernés."""
        keys = await usecase.rotate_signing_keys()
        return Response(
            content=json.dumps(
                {"rotated": [{"kid": key.kid, "alg": key.algorithm.value} for key in keys]}
            ),
            media_type=_JSON_MEDIA_TYPE,
        )

    return router
