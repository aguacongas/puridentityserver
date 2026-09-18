r"""Test manuel de la Pushed Authorization Request (RFC 9126).

Smoke test du sample ``par-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8105,
un client seed public **avec ``par_required = true``**) puis joue le
scénario :

1. le discovery annonce ``pushed_authorization_request_endpoint`` (``/par``) ;
2. ``/authorize`` **sans** ``request_uri`` (demande directe) -> ``400
   invalid_request`` : le client exige PAR (RFC 9126 §6.1) ;
3. ``POST /par`` (form) -> ``201`` ``{request_uri, expires_in}`` ; le
   ``request_uri`` est opaque (``urn:ietf:params:oauth:request_uri:<…>``) ;
4. ``/authorize?client_id=…&request_uri=…`` -> ``302`` code d'autorisation
   (seuls ces deux paramètres sont acceptés) ;
5. ``/token`` échange du code (PKCE) -> ``200`` access_token ;
6. réutilisation du même ``request_uri`` -> ``400 invalid_request`` (usage
   unique, RFC 9126 §4) ;
7. ``/authorize`` avec ``request_uri`` + paramètre supplémentaire (ex.
   ``scope``) -> ``400 invalid_request`` (RFC 9126 §6.2).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/par-client/smoke_test.py
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

SERVER_PORT = 8105
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-par-client"

REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid profile email",
    "client_type": "public",
    "par_required": True,
}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _push(http: httpx.Client, *, code_challenge: str) -> httpx.Response:
    """Pousse une demande d'autorisation à ``POST /par`` (corps form)."""
    data: dict[str, str] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": "st-par",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return http.post(f"{SERVER_URL}/par", data=data)


def _run_scenario() -> None:
    """Joue le scénario PAR (RFC 9126) de bout en bout."""
    verifier = "par-verifier-0123456789"
    challenge = _s256_challenge(verifier)
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["pushed_authorization_request_endpoint"] == f"{SERVER_URL}/par"
        print(
            "  [1/7] discovery OK "
            f"(pushed_authorization_request_endpoint={metadata['pushed_authorization_request_endpoint']})"
        )

        response = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
            },
        )
        assert response.status_code == 400, response.text
        body = response.json()["detail"]
        assert body["error"] == "invalid_request"
        assert "Pushed Authorization Request" in body["error_description"]
        print("  [2/7] /authorize direct sans request_uri -> 400 invalid_request (PAR requis) OK")

        response = _push(http, code_challenge=challenge)
        assert response.status_code == 201, response.text
        pushed = response.json()
        request_uri = pushed["request_uri"]
        assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")
        assert pushed["expires_in"] == 90
        print(f"  [3/7] POST /par -> 201 (request_uri={request_uri[:38]}..., expires_in=90) OK")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params={"client_id": CLIENT_ID, "request_uri": request_uri},
        )
        assert response.status_code == 302, response.text
        redirect_query = parse_qs(urlparse(response.headers["location"]).query)
        code = redirect_query["code"][0]
        assert redirect_query["state"] == ["st-par"]
        print("  [4/7] /authorize?client_id+request_uri -> 302 (code émis, state conservé) OK")

        verifier = "par-verifier-0123456789"
        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["token_type"] == "Bearer"
        assert response.json()["access_token"]
        print("  [5/7] échange du code au /token (PKCE) -> 200 access_token OK")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params={"client_id": CLIENT_ID, "request_uri": request_uri},
        )
        assert response.status_code == 400, response.text
        assert response.json()["detail"]["error"] == "invalid_request"
        print("  [6/7] réutilisation du request_uri -> 400 invalid_request (usage unique) OK")

        response = _push(http, code_challenge=challenge)
        assert response.status_code == 201, response.text
        request_uri = response.json()["request_uri"]
        response = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "client_id": CLIENT_ID,
                "request_uri": request_uri,
                "scope": "openid",
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["detail"]["error"] == "invalid_request"
        print(
            "  [7/7] /authorize avec un paramètre supplémentaire -> 400 "
            "invalid_request (RFC 9126 §6.2) OK"
        )
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(port=SERVER_PORT, clients=(_CLIENT,)),
    ):
        print(f"\nScénario PAR (RFC 9126) - client par_required (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
