"""Smoke test du sample ``shared-storage-client`` (stockage SQL partagé).

Lance **deux** serveurs PurIdentityServer en processus séparés sur le **même
fichier SQLite** (``storage_type = "sql"``, ``storage_dsn`` commun) :

- un serveur « protocole seul » (``role = protocol``, port 8111) qui émet les
  jetons ``client_credentials``, publie discovery et JWKS, mais **n'expose pas
  les CRUD** ;
- un serveur « administration seule » (``role = admin``, port 8112) qui
  **ne connaît pas les clés** du premier (validation JWT distante via son JWKS)
  et applique les écritures sur la **même base**.

Ce scénario prouve qu'un déploiement séparé (processus distincts) partage bien
le même état : une resource créée par l'administration est immédiatement
visible par le protocole (sans redémarrage), et réciproquement ce que le
protocole a seedé au démarrage est lisible par l'administration.

Scénario :

1. le serveur A (role=protocol, SQL) publie discovery + JWKS ; le scopé
   ``billing.read`` (seedé par A) figure déjà dans ``scopes_supported`` ;
2. ``GET /api-resources`` sur A -> ``404`` (pas de CRUD en mode protocole) ;
3. obtention d'un jeton ``scope=admin`` émis par A ;
4. ``GET /api-resources`` sur B sans jeton -> ``401`` ;
5. ``GET /api-resources`` sur B avec le jeton admin -> ``200`` : B lit la
   resource ``billing`` seedée par A dans la base partagée ;
6. ``GET /api-resources`` sur B avec un jeton non admin -> ``401`` ;
7. B (role=admin) reste sans discovery ni ``/token`` (``404``) ;
8. B crée ``shared-identity`` et ``shared-api`` (scopes ``shared.read``,
   ``shared.write``) -> ``201`` ;
9. A : nouveau discovery -> ``shared-identity`` et ``shared.read`` apparaissent
   dans ``scopes_supported`` (écriture de B visible sans redémarrage) ;
10. B supprime ces deux resources -> ``204`` ; un dernier discovery sur A montre
    ``shared.read`` disparu et ``billing.read`` toujours présent.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/shared-storage-client/smoke_test.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

PROTOCOL_PORT = 8111
ADMIN_PORT = 8112
PROTOCOL_URL = f"http://{HOST}:{PROTOCOL_PORT}"
ADMIN_URL = f"http://{HOST}:{ADMIN_PORT}"

ADMIN_CLIENT = "admin-app"
ADMIN_SECRET = "shared-demo-secret"
READER_CLIENT = "reader-app"
READER_SECRET = "reader-demo-secret"

_CLIENTS = (
    {
        "client_id": ADMIN_CLIENT,
        "client_secret": ADMIN_SECRET,
        "scopes": "openid admin",
        "client_type": "confidential",
    },
    {
        "client_id": READER_CLIENT,
        "client_secret": READER_SECRET,
        "scopes": "openid billing.read",
        "client_type": "confidential",
    },
)

_API_RESOURCES = (
    {"name": "management", "display_name": "API de gestion", "scopes": ["admin"]},
    {"name": "billing", "display_name": "API de facturation", "scopes": ["billing.read"]},
)

_HTTP_TIMEOUT = 10
_DEADLINE = 120


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


def _scopes_supported(http: httpx.Client, base_url: str) -> list[str]:
    """Scopes publiés par le discovery de ``base_url``."""
    response = http.get(f"{base_url}/.well-known/openid-configuration")
    assert response.status_code == 200, response.text
    return sorted(response.json()["scopes_supported"])


def _api_names(http: httpx.Client, base_url: str, token: str) -> list[str]:
    """Noms des ApiResources visibles sur ``base_url`` avec le jeton admin."""
    response = http.get(f"{base_url}/api-resources", headers=_bearer(token))
    assert response.status_code == 200, response.text
    return sorted(resource["name"] for resource in response.json())


def _run_scenario() -> None:
    """Joue le scénario de partage de stockage entre les deux processus."""
    admin_token = _token(
        PROTOCOL_URL, client_id=ADMIN_CLIENT, client_secret=ADMIN_SECRET, scope="admin"
    )
    reader_token = _token(
        PROTOCOL_URL, client_id=READER_CLIENT, client_secret=READER_SECRET, scope="billing.read"
    )

    with httpx.Client(timeout=_HTTP_TIMEOUT) as http:
        discovery = http.get(f"{PROTOCOL_URL}/.well-known/openid-configuration")
        assert discovery.status_code == 200, discovery.text
        assert http.get(f"{PROTOCOL_URL}/.well-known/jwks.json").status_code == 200
        initial_scopes = _scopes_supported(http, PROTOCOL_URL)
        assert "billing.read" in initial_scopes, initial_scopes
        print(
            "  [1/10] serveur A (role=protocol, stockage SQL partagé) : discovery + JWKS ; "
            f"billing.read seedé -> {initial_scopes}"
        )

        assert http.get(f"{PROTOCOL_URL}/api-resources").status_code == 404
        print("  [2/10] A : GET /api-resources -> 404 (pas de CRUD en mode protocol)")

        assert admin_token
        print("  [3/10] A : émission du jeton scope=admin (client_credentials)")

        response = http.get(f"{ADMIN_URL}/api-resources")
        assert response.status_code == 401, response.text
        assert response.headers["www-authenticate"] == "Bearer"
        print("  [4/10] B : GET /api-resources sans jeton -> 401 (WWW-Authenticate: Bearer)")

        names = _api_names(http, ADMIN_URL, admin_token)
        assert names == ["billing", "management"], names
        print(f"  [5/10] B : lit la resource seedée par A via la base partagée -> {names}")

        response = http.get(f"{ADMIN_URL}/api-resources", headers=_bearer(reader_token))
        assert response.status_code == 401, response.text
        print("  [6/10] B : jeton non admin (billing.read) -> 401")

        assert http.get(f"{ADMIN_URL}/.well-known/openid-configuration").status_code == 404
        assert (
            http.post(
                f"{ADMIN_URL}/token",
                data={"grant_type": "client_credentials", "client_id": "x"},
            ).status_code
            == 404
        )
        print(f"  [7/10] serveur B (role=admin, même SQL) : ni discovery ni /token sur {ADMIN_URL}")

        created_id = http.post(
            f"{ADMIN_URL}/identity-resources",
            json={"name": "shared-identity", "user_claims": ["shared_claim"]},
            headers=_bearer(admin_token),
        )
        assert created_id.status_code == 201, created_id.text
        created_api = http.post(
            f"{ADMIN_URL}/api-resources",
            json={
                "name": "shared-api",
                "display_name": "API créée côté administration",
                "scopes": ["shared.read", "shared.write"],
            },
            headers=_bearer(admin_token),
        )
        assert created_api.status_code == 201, created_api.text
        print("  [8/10] B : création shared-identity (201) et shared-api (201)")

        protocol_scopes = _scopes_supported(http, PROTOCOL_URL)
        assert "shared-identity" in protocol_scopes, protocol_scopes
        assert "shared.read" in protocol_scopes, protocol_scopes
        assert "shared.write" in protocol_scopes, protocol_scopes
        print(
            "  [9/10] A : discovery mis à jour sans redémarrage -> "
            f"shared-identity + shared.read/shared.write présents : {protocol_scopes}"
        )

        deleted_id = http.delete(
            f"{ADMIN_URL}/identity-resources/shared-identity", headers=_bearer(admin_token)
        )
        assert deleted_id.status_code == 204, deleted_id.text
        deleted_api = http.delete(
            f"{ADMIN_URL}/api-resources/shared-api", headers=_bearer(admin_token)
        )
        assert deleted_api.status_code == 204, deleted_api.text
        final_scopes = _scopes_supported(http, PROTOCOL_URL)
        assert "shared.read" not in final_scopes, final_scopes
        assert "billing.read" in final_scopes, final_scopes
        print(f"  [10/10] A : suppression visible côté protocole -> {final_scopes}")
    print()


def main() -> None:
    """Lance les deux serveurs sur une base SQLite partagée puis le scénario."""
    started_at = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix="puridentity-shared-", ignore_cleanup_errors=True
    ) as tmp:
        storage = {
            "storage_type": "sql",
            "storage_dsn": f"sqlite:///{Path(tmp).as_posix()}/shared.db",
        }
        with (
            watchdog(_DEADLINE),
            run_server(
                port=PROTOCOL_PORT,
                clients=_CLIENTS,
                api_resources=_API_RESOURCES,
                extra_settings={"role": "protocol", **storage},
            ) as _protocol_url,
            run_server(
                port=ADMIN_PORT,
                clients=(),
                extra_settings={
                    "role": "admin",
                    "management_jwt_issuer": PROTOCOL_URL,
                    "management_jwt_jwks_url": f"{PROTOCOL_URL}/.well-known/jwks.json",
                    "admin_required_claim_values": ["admin"],
                    **storage,
                },
            ) as _admin_url,
        ):
            print(f"\nScénario partage de stockage SQL (deadline={_DEADLINE}s)...")
            _run_scenario()
            print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
