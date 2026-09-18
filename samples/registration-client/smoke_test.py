r"""Test manuel de la Dynamic Client Registration (RFC 7591) et du client management (RFC 7592).

Smoke test du sample ``registration-client``.

Lance un serveur PurIdentityServer en sous-processus avec une
configuration **spécifique à ce test** (générée par ``smoke_common.py`` :
port 8104, registration activée avec un initial access token de démo —
aucun client seed : le client est créé dynamiquement), puis joue le
scénario :

1. le discovery annonce ``registration_endpoint`` (``/register``) ;
2. ``POST /register`` sans initial access token -> ``401 invalid_client`` ;
3. ``POST /register`` avec une redirect_uri invalide -> ``400 invalid_redirect_uri`` ;
4. ``POST /register`` avec un initial access token -> ``201`` + ``Location``,
   ``client_id`` + ``client_secret`` + ``registration_access_token`` émis une seule fois ;
5. ``GET /register/{client_id}`` avec le registration access token -> ``200``
   (métadonnées, ni secret ni registration token dans la réponse) ;
6. flow OIDC complet avec le client **dynamique** : ``/authorize`` puis
   ``/token`` avec le secret émis à la registration -> ``200`` access_token ;
7. ``PUT /register/{client_id}`` avec un nouveau ``client_secret`` (rotation)
   -> ``200`` + nouveau secret, émis une seule fois ;
8. ``/token`` avec l'ancien secret -> ``400 invalid_client`` (rotation) ;
9. ``/token`` avec le nouveau secret -> ``200`` access_token ;
10. ``DELETE /register/{client_id}`` -> ``204`` ;
11. ``GET /register/{client_id}`` -> ``404`` (suppression effective).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/registration-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8104
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

# même valeur que la configuration par défaut du serveur (config.toml) :
# le même token fonctionne sur le port 8000 et sur le serveur de test.
INITIAL_ACCESS_TOKEN = "dev-registrar-token"

REGISTRATION_URL = f"{SERVER_URL}/register"

REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"
POST_LOGOUT_URI = f"http://{HOST}:{SERVER_PORT}/post-logout"

_METADATA = {
    "redirect_uris": [REDIRECT_URI],
    "post_logout_redirect_uris": [POST_LOGOUT_URI],
    "scope": "openid profile email",
}

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _authorize(
    http: httpx.Client,
    *,
    client_id: str,
    scope: str = "openid profile email",
) -> str:
    """Émet un code d'autorisation pour ``client_id`` (appel anonyme)."""
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
        },
    )
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def _exchange_code(
    http: httpx.Client,
    *,
    code: str,
    client_id: str,
    client_secret: str,
) -> httpx.Response:
    """Échange le code contre un access_token via ``/token``."""
    return http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )


def _register(
    http: httpx.Client,
    metadata: dict[str, object],
    *,
    initial_access_token: str = INITIAL_ACCESS_TOKEN,
) -> httpx.Response:
    """Appelle ``POST /register`` avec (ou sans) l'initial access token."""
    headers = {"authorization": f"Bearer {initial_access_token}"} if initial_access_token else {}
    return http.post(REGISTRATION_URL, json=metadata, headers=headers)


def _run_scenario() -> None:
    """Joue le scénario de registration dynamique (RFC 7591 + 7592) de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["registration_endpoint"] == f"{SERVER_URL}/register"
        print(f"  [1/11] discovery OK (registration_endpoint={metadata['registration_endpoint']})")

        response = _register(http, _METADATA, initial_access_token="")
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [2/11] POST /register sans initial access token -> 401 invalid_client OK")

        response = _register(http, {**_METADATA, "redirect_uris": ["javascript:alert(1)"]})
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_redirect_uri"
        print("  [3/11] redirect_uri invalide -> 400 invalid_redirect_uri OK")

        response = _register(http, _METADATA)
        assert response.status_code == 201, response.text
        registration = response.json()
        client_id = registration["client_id"]
        client_secret = registration["client_secret"]
        registration_access_token = registration["registration_access_token"]
        registration_client_uri = registration["registration_client_uri"]
        assert client_id
        assert client_secret
        assert registration_access_token
        assert registration["token_endpoint_auth_method"] == "client_secret_basic"
        assert registration["grant_types"] == ["authorization_code"]
        assert registration["response_types"] == ["code"]
        assert registration["scope"] == "email openid profile"
        assert registration["redirect_uris"] == [REDIRECT_URI]
        assert registration["post_logout_redirect_uris"] == [POST_LOGOUT_URI]
        assert response.headers["location"] == registration_client_uri
        assert registration_client_uri == f"{REGISTRATION_URL}/{client_id}"
        print(
            f"  [4/11] POST /register -> 201 (client_id={client_id[:8]}..., "
            f"secret + registration_access_token émis une seule fois)"
        )

        auth = {
            "authorization": f"Bearer {registration_access_token}",
        }
        response = http.get(registration_client_uri, headers=auth)
        assert response.status_code == 200, response.text
        read = response.json()
        assert read["client_id"] == client_id
        assert "client_secret" not in read
        assert "registration_access_token" not in read
        print("  [5/11] GET /register/{{client_id}} -> 200 (ni secret ni token réémis) OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=client_secret)
        assert response.status_code == 200, response.text
        assert response.json()["token_type"] == "Bearer"
        assert response.json()["access_token"]
        print("  [6/11] flow OIDC complet via le client dynamique (secret de registration) OK")

        new_secret = "rotated-secret-8chars"
        response = http.put(
            registration_client_uri,
            json={**_METADATA, "client_secret": new_secret},
            headers=auth,
        )
        assert response.status_code == 200, response.text
        updated = response.json()
        assert updated["client_secret"] == new_secret
        assert updated["scope"] == "email openid profile"
        print("  [7/11] PUT /register/{{client_id}} (rotation du secret) -> 200 OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=client_secret)
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [8/11] ancien secret après rotation -> 400 invalid_client OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=new_secret)
        assert response.status_code == 200, response.text
        assert response.json()["access_token"]
        print("  [9/11] nouveau secret (après rotation) -> 200 access_token OK")

        response = http.delete(registration_client_uri, headers=auth)
        assert response.status_code == 204, response.text
        assert response.content == b""
        print("  [10/11] DELETE /register/{{client_id}} -> 204 corps vide OK")

        response = http.get(registration_client_uri, headers=auth)
        assert response.status_code == 404, response.text
        print("  [11/11] GET /register/{{client_id}} après suppression -> 404 OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(),
            registration_enabled=True,
            registration_initial_access_tokens=(INITIAL_ACCESS_TOKEN,),
        ),
    ):
        print(f"\nScénario de registration dynamique (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
