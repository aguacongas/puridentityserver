"""Smoke test du sample ``admin-api-client`` (administration protégée par JWT).

Lance **deux** serveurs PurIdentityServer :

- un serveur « protocole + administration » (``role = full``, port 8107) qui
  émet les jetons ``client_credentials`` et expose les CRUD ;
- un serveur « administration seule » (``role = admin``, port 8108) qui
  **ne connaît pas** les clés du premier : il valide les jetons à distance
  via le JWKS publié par le premier (``management_jwt_issuer`` +
  ``management_jwt_jwks_url``), ce qui illustre un déploiement séparé.

Scénario :

1. le serveur A publie son discovery et son JWKS ;
2. ``GET /api-resources`` sans jeton -> ``401`` + ``WWW-Authenticate: Bearer`` ;
3. ``GET /api-resources`` avec un jeton sans le claim admin -> ``401`` ;
4. ``GET /api-resources`` avec un jeton ``scope=admin`` -> ``200`` ;
5. CRUD ``POST``/``DELETE /identity-resources`` avec ce même jeton -> ``201``/``204`` ;
6. le serveur B (``role=admin``) n'expose ni discovery ni ``/token`` (``404``) ;
7. ``GET /api-resources`` sur B sans jeton -> ``401`` ;
8. ``GET /api-resources`` sur B avec le jeton émis par A -> ``200``
   (signature validée via le JWKS distant) ;
9. ``GET /api-resources`` sur B avec un jeton non admin -> ``401``.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/admin-api-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

PROTOCOL_PORT = 8107
ADMIN_PORT = 8108
PROTOCOL_URL = f"http://{HOST}:{PROTOCOL_PORT}"
ADMIN_URL = f"http://{HOST}:{ADMIN_PORT}"

ADMIN_CLIENT = "admin-app"
ADMIN_SECRET = "admin-demo-secret"
PLAIN_CLIENT = "plain-app"
PLAIN_SECRET = "plain-demo-secret"

_CLIENTS = (
    {
        "client_id": ADMIN_CLIENT,
        "client_secret": ADMIN_SECRET,
        "scopes": "openid admin",
        "client_type": "confidential",
    },
    {
        "client_id": PLAIN_CLIENT,
        "client_secret": PLAIN_SECRET,
        "scopes": "openid api.read",
        "client_type": "confidential",
    },
)

_API_RESOURCES = (
    {"name": "management", "display_name": "API de gestion", "scopes": ["admin"]},
    {"name": "sample-api", "display_name": "API de démonstration", "scopes": ["api.read"]},
)

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _token(base_url: str, *, client_id: str, client_secret: str, scope: str) -> str:
    """Obtient un access token ``client_credentials`` et retourne sa valeur."""
    response = httpx.post(
        f"{base_url}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
        timeout=_HTTP_TIMEOUT,
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _bearer(token: str) -> dict[str, str]:
    """En-tête ``Authorization`` Bearer."""
    return {"Authorization": f"Bearer {token}"}


def _run_scenario() -> None:
    """Joue le scénario administration protégée de bout en bout."""
    admin_token = _token(
        PROTOCOL_URL, client_id=ADMIN_CLIENT, client_secret=ADMIN_SECRET, scope="admin"
    )
    plain_token = _token(
        PROTOCOL_URL, client_id=PLAIN_CLIENT, client_secret=PLAIN_SECRET, scope="api.read"
    )

    with httpx.Client(timeout=_HTTP_TIMEOUT) as http:
        assert http.get(f"{PROTOCOL_URL}/.well-known/openid-configuration").status_code == 200
        assert http.get(f"{PROTOCOL_URL}/.well-known/jwks.json").status_code == 200
        print(f"  [1/9] serveur A (role=full) : discovery + JWKS publiés sur {PROTOCOL_URL}")

        response = http.get(f"{PROTOCOL_URL}/api-resources")
        assert response.status_code == 401, response.text
        assert response.headers["www-authenticate"] == "Bearer"
        print("  [2/9] A : GET /api-resources sans jeton -> 401 (WWW-Authenticate: Bearer)")

        response = http.get(f"{PROTOCOL_URL}/api-resources", headers=_bearer(plain_token))
        assert response.status_code == 401, response.text
        print("  [3/9] A : jeton sans claim admin -> 401")

        response = http.get(f"{PROTOCOL_URL}/api-resources", headers=_bearer(admin_token))
        assert response.status_code == 200, response.text
        names = [resource["name"] for resource in response.json()]
        assert names == ["management", "sample-api"], names
        print(f"  [4/9] A : jeton scope=admin -> 200 (resources {names})")

        created = http.post(
            f"{PROTOCOL_URL}/identity-resources",
            json={"name": "admin-demo", "user_claims": ["admin_demo_claim"]},
            headers=_bearer(admin_token),
        )
        assert created.status_code == 201, created.text
        deleted = http.delete(
            f"{PROTOCOL_URL}/identity-resources/admin-demo", headers=_bearer(admin_token)
        )
        assert deleted.status_code == 204, deleted.text
        print("  [5/9] A : CRUD /identity-resources avec le jeton admin -> 201 puis 204")

        assert http.get(f"{ADMIN_URL}/.well-known/openid-configuration").status_code == 404
        assert (
            http.post(
                f"{ADMIN_URL}/token",
                data={"grant_type": "client_credentials", "client_id": "x"},
            ).status_code
            == 404
        )
        print(f"  [6/9] serveur B (role=admin) : ni discovery ni /token sur {ADMIN_URL}")

        response = http.get(f"{ADMIN_URL}/api-resources")
        assert response.status_code == 401, response.text
        print("  [7/9] B : GET /api-resources sans jeton -> 401")

        response = http.get(f"{ADMIN_URL}/api-resources", headers=_bearer(admin_token))
        assert response.status_code == 200, response.text
        print("  [8/9] B : jeton émis par A accepté (signature validée via JWKS distant)")

        response = http.get(f"{ADMIN_URL}/api-resources", headers=_bearer(plain_token))
        assert response.status_code == 401, response.text
        print("  [9/9] B : jeton non admin -> 401")
    print()


def main() -> None:
    """Lance les deux serveurs puis le scénario administration protégée."""
    started_at = time.monotonic()
    remote_settings = {
        "role": "admin",
        "management_jwt_issuer": PROTOCOL_URL,
        "management_jwt_jwks_url": f"{PROTOCOL_URL}/.well-known/jwks.json",
        "admin_required_claim_values": ["admin"],
    }
    with (
        watchdog(_DEADLINE),
        run_server(
            port=PROTOCOL_PORT,
            clients=_CLIENTS,
            api_resources=_API_RESOURCES,
            extra_settings={"admin_required_claim_values": ["admin"]},
        ) as _protocol_url,
        run_server(
            port=ADMIN_PORT,
            clients=(),
            extra_settings=remote_settings,
        ) as _admin_url,
    ):
        print(f"\nScénario administration protégée (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
