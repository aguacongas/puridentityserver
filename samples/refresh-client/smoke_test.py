"""Test manuel du refresh token (RFC 6749 §6) avec rotation.

Smoke test du sample ``refresh-client``.

Lance un serveur PurIdentityServer en sous-processus avec une
configuration **spécifique à ce test** (générée par ``smoke_common.py`` :
port 8101, client public ``sample-refresh-client`` avec le scop
``offline_access``), puis joue le scénario :

1. le discovery annonce ``grant_types_supported`` incluant ``refresh_token`` ;
2. ``/authorize`` émet un code d'autorisation (PKCE S256, client public) ;
3. ``/token`` échange le code → access_token, id_token **et refresh_token** ;
4. ``/token`` avec `grant_type=refresh_token` → nouveaux access_token et
   refresh_token (rotation : les valeurs diffèrent de celles du pas 3) ;
5. rejeu de l'ancien refresh token → ``400 invalid_grant`` (rotation) ;
6. ``/token`` avec un refresh token inconnu → ``400 invalid_grant`` ;
7. ``/token`` avec scope restreint ``openid email`` → access_token au
   scope ``email openid`` (sous-ensemble accordé).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/refresh-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8101
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-refresh-client"
REDIRECT_URI = "http://127.0.0.1:5174/callback"
_SCOPE = "openid profile email offline_access"

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": _SCOPE,
        "client_type": "public",
    },
)

_VERIFIER = "smoke-refresh-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(_VERIFIER.encode("ascii")).digest())
    .rstrip(b"=")
    .decode("ascii")
)

_HTTP_TIMEOUT = 10
_DEADLINE = 60


def _authorize(http: httpx.Client) -> str:
    """Appelle ``/authorize`` (PKCE S256) et retourne le ``code`` émis."""
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": _SCOPE,
            "code_challenge": _CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def _token(
    http: httpx.Client,
    *,
    grant_type: str,
    refresh_token: str | None = None,
    scope: str | None = None,
    code: str | None = None,
) -> httpx.Response:
    """Appelle ``/token`` avec le grant type demandé pour le client public."""
    data: dict[str, object] = {
        "grant_type": grant_type,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
    }
    if refresh_token is not None:
        data["refresh_token"] = refresh_token
    if code is not None:
        data["code"] = code
        data["code_verifier"] = _VERIFIER
    if scope is not None:
        data["scope"] = scope
    return http.post(f"{SERVER_URL}/token", data=data)


def _run_scenario() -> None:
    """Joue le scénario de rotation du refresh token de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "refresh_token" in metadata["grant_types_supported"]
        print(f"  [1/7] discovery OK (grant_types_supported={metadata['grant_types_supported']})")

        code = _authorize(http)
        print(f"  [2/7] code d'autorisation émis ({code[:8]}...)")

        response = _token(http, grant_type="authorization_code", code=code)
        assert response.status_code == 200, response.text
        first = response.json()
        assert first["access_token"]
        assert first["id_token"]
        assert first["refresh_token"], "le code grant doit émettre un refresh_token"
        print("  [3/7] échange code -> access_token + refresh_token OK")

        # rotation : deux émissions dans la même seconde produiraient des
        # access tokens identiques (iat/exp identiques, signature déterministe)
        time.sleep(1.1)
        response = _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
        assert response.status_code == 200, response.text
        second = response.json()
        assert second["access_token"] != first["access_token"]
        assert second["refresh_token"] != first["refresh_token"]
        assert second["id_token"]
        print("  [4/7] refresh -> nouveaux jetons (rotation) OK")

        response = _token(http, grant_type="refresh_token", refresh_token=first["refresh_token"])
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_grant"
        print("  [5/7] rejeu de l'ancien refresh token -> 400 invalid_grant OK")

        response = _token(http, grant_type="refresh_token", refresh_token="jeton-inconnu")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_grant"
        print("  [6/7] refresh token inconnu -> 400 invalid_grant OK")

        response = _token(
            http,
            grant_type="refresh_token",
            refresh_token=second["refresh_token"],
            scope="openid email",
        )
        assert response.status_code == 200, response.text
        assert response.json()["access_token"] != second["access_token"]
        assert response.json()["scope"] == "email openid"
        print("  [7/7] refresh avec scope restreint (openid email) OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with watchdog(_DEADLINE), run_server(port=SERVER_PORT, clients=_CLIENTS):
        print(f"\nScénario de rotation du refresh token (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
