"""Client de démonstration : appelle les CRUD d'administration avec un jeton JWT.

Le client confidentiel obtient un access token ``client_credentials`` portant
le claim ``scope`` attendu (``admin`` par défaut), puis l'utilise en Bearer
contre les endpoints de gestion ``/api-resources`` et ``/identity-resources``,
protégés par défaut. Sans jeton (ou avec un jeton sans le claim), les CRUD
répondent ``401``.

Usage (depuis la racine du dépôt) :

    # terminal 1 — serveur PurIdentityServer (port par défaut 8000)
    uv run python -m puridentityserver

    # terminal 2 — client d'administration
    uv run python samples/admin-api-client/client.py
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urljoin

import httpx

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("ADMIN_API_ISSUER", "http://127.0.0.1:8000")
_CLIENT_ID = os.environ.get("ADMIN_API_CLIENT_ID", "sample-admin-client")
_CLIENT_SECRET = os.environ.get("ADMIN_API_CLIENT_SECRET", "admin-demo-secret")
_SCOPE = os.environ.get("ADMIN_API_SCOPE", "admin")


def _fetch_token() -> httpx.Response:
    """Demande un access token ``client_credentials`` avec le scope admin."""
    return httpx.post(
        urljoin(_ISSUER.rstrip("/") + "/", "token"),
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "scope": _SCOPE,
        },
        timeout=_HTTP_TIMEOUT,
    )


def _list_api_resources(token: str) -> httpx.Response:
    """Liste les ApiResources avec le jeton en Bearer."""
    return httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", "api-resources"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_TIMEOUT,
    )


def main() -> None:
    """Obtient un jeton admin, puis compare l'accès CRUD avec et sans jeton."""
    without_token = _list_api_resources("")
    print(f"GET {_ISSUER}/api-resources sans jeton -> HTTP {without_token.status_code}")

    response = _fetch_token()
    if response.status_code != 200:
        print(f"Échec de l'échange : HTTP {response.status_code} — {response.text}")
        return
    token = response.json()["access_token"]
    print(f"Grant client_credentials contre {_ISSUER} (scope={_SCOPE})")

    with_token = _list_api_resources(token)
    print(f"GET {_ISSUER}/api-resources avec jeton -> HTTP {with_token.status_code}")
    if with_token.status_code == 200:
        print(json.dumps(with_token.json(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
