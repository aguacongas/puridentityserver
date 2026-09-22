"""Client de démonstration : partage de stockage entre deux instances.

Un serveur « protocole » (``role = protocol``) et un serveur
« administration » (``role = admin``) tournent sur le **même stockage SQL**
(``storage_type = sql``, ``storage_dsn`` commun). Ce client obtient un jeton
``scope=admin`` émis par le protocole, lit les ApiResources seedées par le
protocole sur l'administration, y crée des resources, puis vérifie qu'elles
apparaissent immédiatement dans le discovery du protocole (état partagé sans
redémarrage), avant de les retirer.

Usage (depuis la racine du dépôt) :

    # terminal 1 — serveur protocole (port 8111, base SQL partagée)
    $env:PURIDENTITYSERVER_ROLE = "protocol"
    $env:PURIDENTITYSERVER_PORT = "8111"
    $env:PURIDENTITYSERVER_ISSUER = "http://127.0.0.1:8111"
    $env:PURIDENTITYSERVER_STORAGE_TYPE = "sql"
    $env:PURIDENTITYSERVER_STORAGE_DSN = "sqlite:///C:/tmp/shared.db"
    uv run python -m puridentityserver

    # terminal 2 — serveur administration (port 8112, même base)
    $env:PURIDENTITYSERVER_ROLE = "admin"
    $env:PURIDENTITYSERVER_PORT = "8112"
    $env:PURIDENTITYSERVER_ISSUER = "http://127.0.0.1:8112"
    $env:PURIDENTITYSERVER_STORAGE_TYPE = "sql"
    $env:PURIDENTITYSERVER_STORAGE_DSN = "sqlite:///C:/tmp/shared.db"
    $env:PURIDENTITYSERVER_MANAGEMENT_JWT_ISSUER = "http://127.0.0.1:8111"
    $env:PURIDENTITYSERVER_MANAGEMENT_JWT_JWKS_URL = "http://127.0.0.1:8111/.well-known/jwks.json"
    uv run python -m puridentityserver

    # terminal 3 — client
    uv run python samples/shared-storage-client/client.py
"""

from __future__ import annotations

import os
import sys

import httpx

_HTTP_TIMEOUT = 10

_PROTOCOL_URL = os.environ.get("SHARED_PROTOCOL_URL", "http://127.0.0.1:8111")
_ADMIN_URL = os.environ.get("SHARED_ADMIN_URL", "http://127.0.0.1:8112")
_CLIENT_ID = os.environ.get("SHARED_CLIENT_ID", "sample-admin-client")
_CLIENT_SECRET = os.environ.get("SHARED_CLIENT_SECRET", "admin-demo-secret")
_SCOPE = os.environ.get("SHARED_SCOPE", "admin")


def _request(method: str, url: str, **kwargs: object) -> httpx.Response:
    """Exécute une requête HTTP et affiche son statut."""
    response = httpx.request(method, url, timeout=_HTTP_TIMEOUT, **kwargs)
    print(f"{method.upper()} {url} -> HTTP {response.status_code}")
    return response


def main() -> None:
    """Joue la démonstration du stockage partagé contre les deux serveurs."""
    discovery = httpx.get(
        f"{_PROTOCOL_URL}/.well-known/openid-configuration", timeout=_HTTP_TIMEOUT
    )
    scopes_before = sorted(discovery.json()["scopes_supported"])
    print(f"Discovery {_PROTOCOL_URL} : scopes_supported = {scopes_before}")

    token_response = _request(
        "POST",
        f"{_PROTOCOL_URL}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "scope": _SCOPE,
        },
    )
    if token_response.status_code != 200:
        sys.exit(f"Échec du grant : {token_response.text}")
    token = token_response.json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}

    _request("GET", f"{_ADMIN_URL}/api-resources")
    listed = _request("GET", f"{_ADMIN_URL}/api-resources", headers=auth)
    print(f"  ApiResources lues côté administration : {[r['name'] for r in listed.json()]}")

    created_id = _request(
        "POST",
        f"{_ADMIN_URL}/identity-resources",
        json={"name": "cli-shared-identity", "user_claims": ["cli_shared_claim"]},
        headers=auth,
    )
    created_api = _request(
        "POST",
        f"{_ADMIN_URL}/api-resources",
        json={"name": "cli-shared-api", "display_name": "API partagée", "scopes": ["cli.read"]},
        headers=auth,
    )
    if created_id.status_code != 201 or created_api.status_code != 201:
        sys.exit("Création impossible côté administration.")

    discovery = httpx.get(
        f"{_PROTOCOL_URL}/.well-known/openid-configuration", timeout=_HTTP_TIMEOUT
    )
    scopes_after = sorted(discovery.json()["scopes_supported"])
    print(f"Discovery {_PROTOCOL_URL} : scopes_supported = {scopes_after}")
    added = sorted(set(scopes_after) - set(scopes_before))
    print(f"  Nouveaux scopes apparus côté protocole (état partagé) : {added}")

    _request("DELETE", f"{_ADMIN_URL}/identity-resources/cli-shared-identity", headers=auth)
    _request("DELETE", f"{_ADMIN_URL}/api-resources/cli-shared-api", headers=auth)
    print("  Resources retirées côté administration.")


if __name__ == "__main__":
    main()
