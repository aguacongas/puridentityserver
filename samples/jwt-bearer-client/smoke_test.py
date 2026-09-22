"""Test manuel de l'authentification JWT client et du grant jwt-bearer (#46).

Smoke test du sample ``jwt-bearer-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8114,
registration activée avec un initial access token — la clé de scellement des
secrets HMAC est **générée automatiquement** au démarrage), puis joue le
scénario :

1. le discovery annonce ``urn:ietf:params:oauth:grant-type:jwt-bearer`` dans
   ``grant_types_supported`` et ``client_secret_jwt`` dans
   ``token_endpoint_auth_methods_supported`` ;
2. ``POST /register`` avec ``token_endpoint_auth_method: client_secret_jwt``
   -> ``201`` + ``client_secret`` émis une seule fois (chiffré au repos) ;
3. grant jwt-bearer (assertion ``iss=client_id``, ``sub=alice``, ``aud=token
   endpoint``) -> ``200`` avec un access token au ``sub`` d'Alice ;
4. ``client_credentials`` authentifié par ``client_assertion`` (méthode
   ``client_secret_jwt``) -> ``200`` au ``sub`` du client ;
5. ``PUT /register/{client_id}`` **sans secret** (drain de la rotation : le
   ciphertext est re-scellé sous la clé récente, aucun secret n'est ré-émis)
   -> ``200``, puis le grant jwt-bearer fonctionne toujours ;
6. assertion expirée -> ``400 invalid_grant`` ;
7. assertion avec une ``aud`` éronée -> ``400 invalid_grant`` ;
8. assertion signée par un client inconnu -> ``400 invalid_client``.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/jwt-bearer-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8114
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

_INITIAL_TOKEN = "dev-registrar-token"
_SUBJECT = "alice"
_SCOPE = "openid profile email"
_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_HTTP_TIMEOUT = 10
_DEADLINE = 60


def _assertion(*, iss: str, sub: str, aud: str, secret: str, expires_in: int = 600) -> str:
    """Signe une assertion JWT HMAC partagée (``exp``/``iat`` valides)."""
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "exp": int(now.timestamp()) + expires_in,
            "iat": int(now.timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def _register(http: httpx.Client, token_endpoint: str) -> dict[str, object]:
    """Enregistre un client ``client_secret_jwt`` et rend ses identifiants."""
    response = http.post(
        f"{SERVER_URL}/register",
        headers={"Authorization": f"Bearer {_INITIAL_TOKEN}"},
        json={
            "redirect_uris": ["http://127.0.0.1:8114/callback"],
            "token_endpoint_auth_method": "client_secret_jwt",
            "scope": _SCOPE,
        },
    )
    assert response.status_code == 201, response.text
    registered = response.json()
    assert registered["token_endpoint_auth_method"] == "client_secret_jwt"
    assert registered["client_secret"]
    registered["token_endpoint"] = token_endpoint
    return registered


def _grant(http: httpx.Client, client_id: str, secret: str, token_endpoint: str) -> httpx.Response:
    """Requeste le grant jwt-bearer avec une assertion valide (sub d'Alice)."""
    return http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": _GRANT,
            "client_id": client_id,
            "assertion": _assertion(iss=client_id, sub=_SUBJECT, aud=token_endpoint, secret=secret),
            "scope": _SCOPE,
        },
    )


def _run_scenario() -> None:
    """Joue le scénario #46 de bout en bout (grant + auth JWT + drain)."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert _GRANT in metadata["grant_types_supported"]
        assert "client_secret_jwt" in metadata["token_endpoint_auth_methods_supported"]
        token_endpoint = metadata["token_endpoint"]
        print("  [1/8] discovery OK (grant jwt-bearer + client_secret_jwt annoncés)")

        registered = _register(http, token_endpoint)
        client_id = registered["client_id"]
        client_secret = registered["client_secret"]
        registry_token = registered["registration_access_token"]
        registry_uri = registered["registration_client_uri"]
        print(
            f"  [2/8] POST /register client_secret_jwt -> 201 "
            f"(client_id={client_id}, secret émis une seule fois, chiffré au repos)"
        )

        response = _grant(http, client_id, client_secret, token_endpoint)
        assert response.status_code == 200, response.text
        access_token = response.json()["access_token"]
        assert pyjwt.decode(access_token, options={"verify_signature": False})["sub"] == _SUBJECT
        print("  [3/8] grant jwt-bearer -> access_token au sub d'Alice OK")

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_assertion_type": _ASSERTION_TYPE,
                "client_assertion": _assertion(
                    iss=client_id, sub=client_id, aud=token_endpoint, secret=client_secret
                ),
            },
        )
        assert response.status_code == 200, response.text
        client_token = response.json()["access_token"]
        assert pyjwt.decode(client_token, options={"verify_signature": False})["sub"] == client_id
        print("  [4/8] client_credentials via client_assertion (client_secret_jwt) OK")

        # drain de la rotation : PUT sans secret (registration access token du
        # client) re-scellé le ciphertext sous la clé récente, aucun secret ré-émis
        response = http.put(
            registry_uri,
            headers={"Authorization": f"Bearer {registry_token}"},
            json={
                "redirect_uris": ["http://127.0.0.1:8114/callback"],
                "token_endpoint_auth_method": "client_secret_jwt",
                "scope": _SCOPE,
            },
        )
        assert response.status_code == 200, response.text
        assert "client_secret" not in response.json()
        print("  [5/8] PUT /register sans secret -> 200 (ciphertext re-scellé, secret conservé)")

        response = _grant(http, client_id, client_secret, token_endpoint)
        assert response.status_code == 200, response.text
        print("  [5/8] grant jwt-bearer toujours OK après le re-scellement")

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": _GRANT,
                "client_id": client_id,
                "assertion": _assertion(
                    iss=client_id,
                    sub=_SUBJECT,
                    aud=token_endpoint,
                    secret=client_secret,
                    expires_in=-60,
                ),
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_grant"
        print("  [6/8] assertion expirée -> 400 invalid_grant OK")

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": _GRANT,
                "client_id": client_id,
                "assertion": _assertion(
                    iss=client_id,
                    sub=_SUBJECT,
                    aud="https://autre-serveur/token",
                    secret=client_secret,
                ),
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_grant"
        print("  [7/8] assertion avec aud éronée -> 400 invalid_grant OK")

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": _GRANT,
                "assertion": _assertion(
                    iss="ghost", sub=_SUBJECT, aud=token_endpoint, secret="ghost-secret"
                ),
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [8/8] assertion d'un client inconnu -> 400 invalid_client OK")
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
            registration_initial_access_tokens=(_INITIAL_TOKEN,),
        ),
    ):
        print(f"\nScénario jwt-bearer + client_secret_jwt (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
