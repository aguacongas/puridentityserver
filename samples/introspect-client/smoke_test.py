"""Test manuel des endpoints d'introspection (RFC 7662) et de révocation (RFC 7009).

Smoke test du sample ``introspect-client``.

Lance un serveur PurIdentityServer en sous-processus avec une
configuration **spécifique à ce test** (générée par ``smoke_common.py`` :
port 8100, client confidentiel ``sample-introspect-client``), puis joue
le scénario :

1. le discovery annonce ``introspection_endpoint`` et ``revocation_endpoint`` ;
2. ``/authorize`` émet un code d'autorisation (appel anonyme) ;
3. ``/token`` l'échange contre un access_token (client confidentiel) ;
4. ``/introspect`` sur le token valide -> ``active: true`` + métadonnées ;
5. ``/introspect`` sur un token inconnu -> ``active: false`` (HTTP 200) ;
6. ``/introspect`` avec un secret client erroné -> ``401 invalid_client`` ;
7. ``/introspect`` avec un token vide -> ``400 invalid_request`` ;
8. ``/revoke`` sur le token valide -> HTTP 200, corps vide ;
9. ``/introspect`` sur le token révoqué -> ``active: false`` ;
10. ``/revoke`` sur un token inconnu -> HTTP 200, corps vide ;
11. ``/revoke`` avec un secret client erroné -> ``401 invalid_client``.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/introspect-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8100
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-introspect-client"
CLIENT_SECRET = "introspect-demo-secret"
REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": "openid profile",
        "client_type": "confidential",
        "client_secret": CLIENT_SECRET,
    },
)

_HTTP_TIMEOUT = 10
_DEADLINE = 60


def _introspect(http: httpx.Client, *, token: str, secret: str = CLIENT_SECRET) -> httpx.Response:
    """Appelle ``/introspect`` avec les identifiants du client confidentiel."""
    return http.post(
        f"{SERVER_URL}/introspect",
        data={"token": token, "client_id": CLIENT_ID, "client_secret": secret},
    )


def _revoke(http: httpx.Client, *, token: str, secret: str = CLIENT_SECRET) -> httpx.Response:
    """Appelle ``/revoke`` avec les identifiants du client confidentiel."""
    return http.post(
        f"{SERVER_URL}/revoke",
        data={"token": token, "client_id": CLIENT_ID, "client_secret": secret},
    )


def _run_scenario() -> None:
    """Joue le scénario d'introspection et de révocation de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["introspection_endpoint"] == f"{SERVER_URL}/introspect"
        assert metadata["revocation_endpoint"] == f"{SERVER_URL}/revoke"
        print(
            f"  [1/11] discovery OK (introspection_endpoint={metadata['introspection_endpoint']}, "
            f"revocation_endpoint={metadata['revocation_endpoint']})"
        )

        response = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile",
            },
        )
        assert response.status_code == 302, response.text
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        print(f"  [2/11] code d'autorisation émis ({code[:8]}...)")

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        assert response.status_code == 200, response.text
        access_token = response.json()["access_token"]
        assert response.json()["token_type"] == "Bearer"
        print("  [3/11] échange code -> access_token OK")

        response = _introspect(http, token=access_token)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["active"] is True
        assert body["client_id"] == CLIENT_ID
        assert body["scope"] == "openid profile"
        assert body["token_type"] == "Bearer"
        assert "sub" in body
        assert body["exp"] > body["iat"]
        print(
            "  [4/11] introspection token valide OK "
            f"(sub={body['sub']!r}, exp-iat={body['exp'] - body['iat']}s)"
        )

        response = _introspect(http, token="token-inconnu")
        assert response.status_code == 200, response.text
        assert response.json() == {"active": False}
        print("  [5/11] introspection token inconnu -> active=false OK")

        response = _introspect(http, token=access_token, secret="mauvais-secret")
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [6/11] secret client erroné -> 401 invalid_client OK")

        response = _introspect(http, token="")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request"
        print("  [7/11] token vide -> 400 invalid_request OK")

        response = _revoke(http, token=access_token)
        assert response.status_code == 200, response.text
        assert response.content == b""
        print("  [8/11] révocation du token valide -> HTTP 200 corps vide OK")

        response = _introspect(http, token=access_token)
        assert response.status_code == 200, response.text
        assert response.json() == {"active": False}
        print("  [9/11] introspection token révoqué -> active=false OK")

        response = _revoke(http, token="token-inconnu")
        assert response.status_code == 200, response.text
        assert response.content == b""
        print("  [10/11] révocation token inconnu -> HTTP 200 corps vide OK")

        response = _revoke(http, token=access_token, secret="mauvais-secret")
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [11/11] secret client erroné -> 401 invalid_client OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with watchdog(_DEADLINE), run_server(port=SERVER_PORT, clients=_CLIENTS):
        print(f"\nScénario d'introspection et de révocation (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
