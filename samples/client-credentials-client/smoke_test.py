"""Test manuel du grand client_credentials (RFC 6749 §4.4).

Smoke test du sample ``client-credentials-client``.

Lance un serveur PurIdentityServer en sous-processus avec une
configuration **spécifique à ce test** (générée par ``smoke_common.py`` :
port 8102, client confidentiel ``sample-cc-client``, scopes
``openid profile``), puis joue le scénario :

1. le discovery annonce ``grant_types_supported`` incluant ``client_credentials`` ;
2. ``/token`` (client_credentials + secret) -> access_token seul (scope
   ``openid profile``, aucun ``id_token``) ;
3. scop restreint ``openid`` -> access_token au scop ``openid`` ;
4. scop non enregistré pour le client (``email``) -> ``400 invalid_scope`` ;
5. secret erroné -> ``400 invalid_client`` ;
6. secret absent -> ``400 invalid_client`` ;
7. client inconnu -> ``400 invalid_client``.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/client-credentials-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8102
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-cc-client"
CLIENT_SECRET = "cc-demo-secret"
_SCOPE = "openid profile"

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "scopes": _SCOPE,
        "client_type": "confidential",
        "client_secret": CLIENT_SECRET,
    },
)

_HTTP_TIMEOUT = 10
_DEADLINE = 60


def _token(
    http: httpx.Client,
    *,
    secret: str = CLIENT_SECRET,
    client_id: str = CLIENT_ID,
    scope: str | None = None,
) -> httpx.Response:
    """Appelle ``/token`` avec le grand client_credentials."""
    data: dict[str, object] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    }
    if scope is not None:
        data["scope"] = scope
    return http.post(f"{SERVER_URL}/token", data=data)


def _run_scenario() -> None:
    """Joue le scénario client_credentials de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "client_credentials" in metadata["grant_types_supported"]
        print(f"  [1/7] discovery OK (grant_types_supported={metadata['grant_types_supported']})")

        response = _token(http)
        assert response.status_code == 200, response.text
        first = response.json()
        assert first["access_token"]
        assert first["token_type"] == "Bearer"
        assert first["scope"] == "openid profile"
        assert "id_token" not in first
        print(
            f"  [2/7] client_credentials -> access_token seul "
            f"(scope={first['scope']}, expires_in={first['expires_in']}) OK"
        )

        response = _token(http, scope="openid")
        assert response.status_code == 200, response.text
        assert response.json()["scope"] == "openid"
        print("  [3/7] scope restreint (openid) OK")

        response = _token(http, scope="email")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_scope"
        print("  [4/7] scope non enregistré -> 400 invalid_scope OK")

        response = _token(http, secret="mauvais-secret")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [5/7] secret erroné -> 400 invalid_client OK")

        response = _token(http, secret="")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [6/7] secret absent -> 400 invalid_client OK")

        response = _token(http, client_id="ghost")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [7/7] client inconnu -> 400 invalid_client OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with watchdog(_DEADLINE), run_server(port=SERVER_PORT, clients=_CLIENTS):
        print(f"\nScénario client_credentials (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
