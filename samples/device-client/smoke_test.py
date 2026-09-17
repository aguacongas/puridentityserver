"""Test manuel du Device Authorization Grant (RFC 8628).

Enchaîne de façon synchrone les étapes du flow sur un serveur dédié
port 8103 (``smoke_common.run_server``) :

1. le discovery annonce ``grant_types_supported`` incluant
   ``urn:ietf:params:oauth:grant-type:device_code`` et
   ``device_authorization_endpoint`` ;
2. ``POST /device_authorization`` retourne un ``device_code`` +
   ``user_code`` + ``verification_uri`` ;
3. connexion d'Alice via ``POST /login`` (cookie de session) ;
4. ``POST /device`` (autorisation de l'appareil) ;
5. ``POST /token`` (poll avec grant device_code) → ``access_token`` +
   ``id_token``.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

_PARENTS = list(Path(__file__).resolve().parents)
if str(_PARENTS[1]) not in sys.path:
    sys.path.insert(0, str(_PARENTS[1]))

from smoke_common import run_server, watchdog  # ruff: ignore[module-import-not-at-top-of-file]

SERVER_PORT = 8103
_CLIENT_ID = "sample-device-client"
_CLIENTS = ({"client_id": _CLIENT_ID, "scopes": "openid profile", "client_type": "public"},)
_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}
_DEADLINE = 60


def _login(client: httpx.Client) -> None:
    """Connecte Alice (cookie de session) pour autoriser l'appareil."""
    resp = client.post(
        "/login",
        data={
            "username": "alice@example.com",
            "password": "password",
            "next": "/device",
            "client_id": _CLIENT_ID,
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200, f"[3] login failed: {resp.status_code}"
    assert "Autoriser cet appareil" in resp.text


def _run_scenario() -> None:
    """Joue le scénario device flow de bout en bout."""
    base_url = f"http://127.0.0.1:{SERVER_PORT}"
    with httpx.Client(base_url=base_url, timeout=10) as client:
        # 1. Discovery
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        metadata = resp.json()
        assert (
            "urn:ietf:params:oauth:grant-type:device_code" in metadata["grant_types_supported"]
        ), "grant device_code manquant dans discovery"
        assert "device_authorization_endpoint" in metadata
        print(
            f"  [1/{5}] discovery OK "
            f"(device_authorization_endpoint={metadata['device_authorization_endpoint']})"
        )

        # 2. Device authorization
        resp = client.post(
            "/device_authorization",
            data={"client_id": _CLIENT_ID},
        )
        assert resp.status_code == 200, f"[2] device_authorization failed: {resp.text}"
        data = resp.json()
        device_code = data["device_code"]
        user_code = data["user_code"]
        assert "verification_uri" in data
        assert data["expires_in"] > 0
        print(
            f"  [2/{5}] device_authorization OK "
            f"(user_code={user_code}, expires_in={data['expires_in']}s)"
        )

        # 3. Login (alice)
        _login(client)
        print(f"  [3/{5}] login alice OK")

        # 4. Approve
        resp = client.post(
            "/device",
            data={"user_code": user_code, "action": "authorize"},
        )
        assert resp.status_code == 200, f"[4] device approval failed: {resp.text}"
        assert "Appareil autorisé" in resp.text
        print(f"  [4/{5}] device approved OK")

        # 5. Poll until tokens
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            resp = client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": _CLIENT_ID,
                },
            )
            body = resp.json()
            if body.get("error") is None and resp.status_code == 200:
                print(f"  [5/{5}] tokens OK (access_token={body['access_token'][:40]}...)")
                return
            assert body.get("error") != "expired_token", "device code expired prematurely"
            assert body.get("error") != "access_denied", "device code unexpectedly denied"
            time.sleep(0.3)

    raise AssertionError("[5] tokens never issued within deadline")


def main() -> None:
    """Lance le scénario device flow sur un serveur dédié (port 8103)."""
    print(f"\nScénario Device Authorization Grant (deadline={_DEADLINE}s)...")
    with watchdog(_DEADLINE), run_server(port=SERVER_PORT, clients=_CLIENTS, users=_USERS):
        _run_scenario()
    print("OK\n")


if __name__ == "__main__":
    main()
