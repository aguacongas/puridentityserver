"""Client de démonstration : obtient un jeton de scope d'API puis appelle l'API protégée.

Scénario *machine à machine* complet du sample ApiResources : le client
confidentiel demande un access token au serveur PurIdentityServer avec le
grand ``client_credentials`` et le scope d'API ``api.read``, puis appelle
l'API protégée (``api_server.py``) qui **valide le token** (signature JWKS,
``iss``, ``exp``, ``aud`` = ``sample-api``, scope ``api.read``) et renvoie
les données protégées.

Usage (depuis la racine du dépôt) :

    # terminal 1 — serveur PurIdentityServer (port par défaut 8000)
    uv run python -m puridentityserver

    # terminal 2 — API protégée échantillon (port 8120)
    uv run python samples/api-resources-client/api_server.py

    # terminal 3 — client machine à machine
    uv run python samples/api-resources-client/client.py
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urljoin

import httpx
import jwt as pyjwt

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("API_RES_ISSUER", "http://127.0.0.1:8000")
_CLIENT_ID = os.environ.get("API_RES_CLIENT_ID", "sample-api-client")
_CLIENT_SECRET = os.environ.get("API_RES_CLIENT_SECRET", "api-demo-secret")
_SCOPE = os.environ.get("API_RES_SCOPE", "api.read")
_API_BASE_URL = os.environ.get("API_RES_API_URL", "http://127.0.0.1:8120")


def _discovery() -> dict[str, object]:
    """Charge le document de discovery du serveur."""
    response = httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", ".well-known/openid-configuration"),
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _fetch_token(endpoint: str) -> httpx.Response:
    """Demande un access token avec le grand client_credentials."""
    return httpx.post(
        endpoint,
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "scope": _SCOPE,
        },
        timeout=_HTTP_TIMEOUT,
    )


def _call_protected_api(token: str) -> dict[str, object]:
    """Appelle l'API protégée échantillon avec le jeton en ``Authorization``."""
    response = httpx.get(
        urljoin(_API_BASE_URL.rstrip("/") + "/", "api/data"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_TIMEOUT,
    )
    if response.status_code != 200:
        return {
            "status_code": response.status_code,
            "body": response.json() if response.content else None,
        }
    return response.json()


def main() -> None:
    """Récupère un jeton de scope d'API puis l'utilise contre l'API protégée."""
    metadata = _discovery()
    response = _fetch_token(metadata["token_endpoint"])  # type: ignore[arg-type]
    if response.status_code != 200:
        print(f"Échec de l'échange : HTTP {response.status_code} — {response.text}")
        return
    body = response.json()
    token = body["access_token"]

    print(f"Grant client_credentials contre {_ISSUER}")
    print(f"  client_id : {_CLIENT_ID}")
    print(f"  scope     : {body['scope']}")
    print(f"  expires_in: {body['expires_in']} s")
    claims = pyjwt.decode(token, options={"verify_signature": False})
    print(
        "  claims (décodés sans vérification — la vérification est le rôle de "
        f"l'API protégée) : sub={claims.get('sub')!r} aud={claims.get('aud')!r} "
        f"scope={claims.get('scope')!r}"
    )

    api_response = _call_protected_api(token)
    print(f"\nGET {_API_BASE_URL}/api/data (Bearer) :")
    print(json.dumps(api_response, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
