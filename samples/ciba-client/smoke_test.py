"""Test manuel du CIBA (Client-Initiated Backchannel Authentication).

Enchaîne de façon synchrone les étapes du flow sur un serveur dédié
port 8116 (``smoke_common.run_server``) :

1. le discovery annonce ``backchannel_authentication_endpoint``,
   ``backchannel_token_delivery_modes_supported`` (poll, ping) et le
   grant ``urn:openid:params:grant-type:ciba`` dans
   ``grant_types_supported`` ;
2. ``POST /bc-authorize`` (Basic auth, ``login_hint``) → ``auth_req_id``
   + ``expires_in`` + ``interval`` ;
3. ``POST /ciba/approve`` (approbation de la demande) ;
4. ``POST /token`` (grant CIBA) → ``access_token`` + ``id_token``.
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

SERVER_PORT = 8116
_CLIENT_ID = "sample-ciba-client"
_CLIENT_SECRET = "ciba-demo-secret"
_CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_CLIENTS = (
    {
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
        "scopes": "openid profile",
        "client_type": "confidential",
        "backchannel_token_delivery_mode": "poll",
    },
)
_USERS_SEED = {"alice": {"email": "alice.martin@example.com", "name": "Alice Martin"}}
_EXTRA = {"ciba_enabled": True, "ciba_approval_enabled": True}
_DEADLINE = 60


def _run_scenario() -> None:
    """Joue le scénario CIBA de bout en bout."""
    base_url = f"http://127.0.0.1:{SERVER_PORT}"
    with httpx.Client(base_url=base_url, timeout=10) as client:
        # 1. Discovery
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        metadata = resp.json()
        bc_endpoint = metadata.get("backchannel_authentication_endpoint")
        assert bc_endpoint, "backchannel_authentication_endpoint manquant dans discovery"
        assert metadata["backchannel_token_delivery_modes_supported"] == ["poll", "ping"]
        assert _CIBA_GRANT in metadata["grant_types_supported"], "grant CIBA manquant"
        print(f"  [1/{4}] discovery OK (backchannel_authentication_endpoint={bc_endpoint})")

        # 2. Backchannel authentication
        resp = client.post(
            "/bc-authorize",
            data={"scope": "openid profile", "login_hint": "alice.martin@example.com"},
            auth=(_CLIENT_ID, _CLIENT_SECRET),
        )
        assert resp.status_code == 200, f"[2] bc-authorize failed: {resp.text}"
        ack = resp.json()
        auth_req_id = ack["auth_req_id"]
        assert ack["expires_in"] > 0
        print(
            f"  [2/{4}] bc-authorize OK "
            f"(expires_in={ack['expires_in']}s, interval={ack['interval']}s)"
        )

        # 3. Approbation de la demande
        resp = client.post("/ciba/approve", params={"token": auth_req_id, "type": "allow"})
        assert resp.status_code == 200, f"[3] approve failed: {resp.text}"
        print(f"  [3/{4}] approve OK")

        # 4. Poll jusqu'aux jetons
        deadline = time.monotonic() + 15
        delay = 0.3
        while time.monotonic() < deadline:
            resp = client.post(
                "/token",
                data={"grant_type": _CIBA_GRANT, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            body = resp.json()
            if body.get("error") is None and resp.status_code == 200:
                assert body.get("id_token"), "id_token absent du réponse CIBA"
                print(f"  [4/{4}] tokens OK (access_token={body['access_token'][:40]}...)")
                return
            error = body.get("error")
            assert error not in ("access_denied", "expired_token", "invalid_grant"), (
                f"CIBA poll en erreur : {error} — {body.get('error_description', '')}"
            )
            if error == "slow_down":
                delay = max(delay, 1.0)
            time.sleep(delay)

    raise AssertionError("[4] tokens never issued within deadline")


def main() -> None:
    """Lance le scénario CIBA sur un serveur dédié (port 8116)."""
    print(f"\nScénario CIBA (deadline={_DEADLINE}s)...")
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            users_seed=_USERS_SEED,
            extra_settings=_EXTRA,
        ),
    ):
        _run_scenario()
    print("OK\n")


if __name__ == "__main__":
    main()
