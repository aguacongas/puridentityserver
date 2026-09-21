"""API protégée de démonstration (sample ApiResources).

Resource server échantillon qui valide l'access token reçu dans l'en-tête
``Authorization: Bearer`` contre le serveur PurIdentityServer :

- le token est extrait par la dépendance ``HTTPBearer`` de FastAPI (le schéma
  apparaît dans Swagger/OpenAPI) ;
- signature **vérifiée** contre les JWKS de l'issuer (RFC 7517) : le client
  ``PyJWT.PyJWKClient`` récupère et met en cache les clés, sélectionne celle
  correspondant au ``kid`` du token et gère la rotation (rafraîchissement du
  JWKS) ;
- claims contrôlés : ``iss`` (issuer exact), ``exp`` (non expiré),
  ``aud`` (contient le nom de la ApiResource) ;
- scope requis : le claim ``scope`` doit contenir ``api.read``.

Lancement (depuis la racine du dépôt, serveur PurIdentityServer déjà démarré
sur le port ``8000`` par défaut) :

    uv run python samples/api-resources-client/api_server.py

Puis appelez ``GET http://127.0.0.1:8120/api/data`` avec l'en-tête
``Authorization: Bearer <access_token>`` (voir ``client.py`` et la démo SPA).

Configuration via l'environnement : ``API_RES_ISSUER`` (défaut
``http://127.0.0.1:8000``), ``API_RES_PORT`` (défaut ``8120``), ``API_RES_API``
(nom de la ApiResource attendue dans ``aud``, défaut ``sample-api``) et
``API_RES_SCOPE`` (scope requis, défaut ``api.read``).
"""

from __future__ import annotations

import logging
import os
from typing import Annotated
from urllib.parse import urljoin

import jwt as pyjwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("API_RES_ISSUER", "http://127.0.0.1:8000")
_API_NAME = os.environ.get("API_RES_API", "sample-api")
_REQUIRED_SCOPE = os.environ.get("API_RES_SCOPE", "api.read")

_LOGGER = logging.getLogger("puridentityserver.sample.api-resources")

_JWKS_URL = urljoin(_ISSUER.rstrip("/") + "/", ".well-known/jwks.json")

_bearer = HTTPBearer(auto_error=False)
_jwk_client = pyjwt.PyJWKClient(
    _JWKS_URL,
    cache_keys=True,
    lifespan=300,
    timeout=_HTTP_TIMEOUT,
)

app = FastAPI(title="PurIdentityServer — API protégée (échantillon)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["Authorization"],
)


@app.exception_handler(HTTPException)
def oauth_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Sérialise les erreurs au format OAuth (RFC 6750) : ``detail`` à plat."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
        headers=exc.headers,
    )


def _invalid_token() -> HTTPException:
    """Exception 401 au format RFC 6750 (Bearer scheme)."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"},
        detail={
            "error": "invalid_token",
            "error_description": "Le token est invalide, expiré ou non signé par l'issuer",
        },
    )


def required_claims(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, object]:
    """Valide le Bearer token et retourne ses claims, ou lève une 401/403.

    Utilisé comme dépendance des routes protégées : l'authentification ne se
    fait plus à la main dans le handler, et le schéma ``HTTPBearer`` est
    déclaré dans l'OpenAPI de l'API.
    """
    if credentials is None or not credentials.credentials:
        raise _invalid_token()
    token = credentials.credentials
    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        claims = pyjwt.decode(
            token,
            signing_key,
            audience=_API_NAME,
            issuer=_ISSUER,
        )
    except pyjwt.PyJWTError as error:
        _LOGGER.warning("Token rejeté : %s", error)
        raise _invalid_token() from error
    scope = str(claims.get("scope", ""))
    if _REQUIRED_SCOPE not in scope.split():
        _LOGGER.warning(
            "403 insufficient_scope : sub=%s aud=%s scope=%s (requis %s)",
            claims.get("sub"),
            claims.get("aud"),
            scope or "(vide)",
            _REQUIRED_SCOPE,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_scope",
                "error_description": f"Scope {_REQUIRED_SCOPE!r} requis",
                "required_scope": _REQUIRED_SCOPE,
            },
        )
    _LOGGER.info(
        "200 token accepté : sub=%s aud=%s scope=%s (signature JWKS, iss, exp vérifiés)",
        claims.get("sub"),
        claims.get("aud"),
        scope,
    )
    return claims


@app.get("/api/data")
async def protected_data(
    claims: Annotated[dict[str, object], Depends(required_claims)],
) -> dict[str, object]:
    """Données protégées : servies uniquement à un token valide et du bon scope."""
    return {
        "resource": _API_NAME,
        "message": (
            "Données protégées : token valide (signature JWKS, iss, exp, aud) "
            f"et scope {_REQUIRED_SCOPE!r} présent"
        ),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "scope": claims.get("scope"),
    }


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    port = int(os.environ.get("API_RES_PORT", "8120"))
    _LOGGER.info(
        "API protégée prête sur http://127.0.0.1:%d/api/data (issuer=%s, aud=%s, scope requis=%s)",
        port,
        _ISSUER,
        _API_NAME,
        _REQUIRED_SCOPE,
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
