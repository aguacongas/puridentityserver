"""Test manuel du CIBA (Client-Initiated Backchannel Authentication).

Enchaîne de façon synchrone deux scénarios sur un serveur dédié
port 8116 (``smoke_common.run_server``) :

Scénario non signé (client seed) :

1. le discovery annonce ``backchannel_authentication_endpoint``,
   ``backchannel_token_delivery_modes_supported`` (poll, ping) et le
   grant ``urn:openid:params:grant-type:ciba`` dans
   ``grant_types_supported`` ;
2. ``POST /bc-authorize`` (Basic auth, ``login_hint``) → ``auth_req_id``
   + ``expires_in`` + ``interval`` ;
3. ``POST /ciba/approve`` (approbation de la demande) ;
4. ``POST /token`` (grant CIBA) → ``access_token`` + ``id_token``.

Scénario signé (FAPI-CIBA-ID1, request object JAR) :

1. le discovery publie
   ``backchannel_authentication_request_signing_alg_values_supported`` ;
2. DCR (``POST /register``) avec clé RSA éphémère, ``private_key_jwt``
   et ``backchannel_authentication_request_signing_alg=PS256`` ;
3. demande **sans** ``request`` → 400 ``invalid_request`` (signature
   exigée pour ce client) ;
4. ``POST /bc-authorize`` au corps ``{request, client_assertion,
   client_assertion_type}`` (sans ``client_id``) → ``auth_req_id`` ;
5. approbation ;
6. ``POST /token`` authentifié par ``client_assertion`` → jetons.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

_PARENTS = list(Path(__file__).resolve().parents)
if str(_PARENTS[1]) not in sys.path:
    sys.path.insert(0, str(_PARENTS[1]))

from client import (  # ruff: ignore[module-import-not-at-top-of-file]
    _ASSERTION_TYPE,
    _register_signed_client,
    _signed_form,
    _signing_material,
)
from smoke_common import run_server, watchdog  # ruff: ignore[module-import-not-at-top-of-file]

SERVER_PORT = 8116
_CLIENT_ID = "sample-ciba-client"
_CLIENT_SECRET = "ciba-demo-secret"
_CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_REGISTRAR_TOKEN = "dev-registrar-token"
_LOGIN_HINT = "alice.martin@example.com"
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
_DEADLINE = 90


def _poll_ciba_tokens(
    client: httpx.Client,
    data: dict[str, str],
    auth: tuple[str, str] | None,
    label: str,
) -> None:
    """Interroge ``/token`` jusqu'aux jetons, un refus définitif ou le délai.

    ``data`` porte le corps (grant CIBA + ``auth_req_id``, éventuellement
    ``client_id``/``client_assertion`` en mode signé) ; ``auth`` le Basic
    auth éventuel (``None`` en mode signé, authentifié par assertion).
    """
    deadline = time.monotonic() + 15
    delay = 0.3
    while time.monotonic() < deadline:
        resp = client.post("/token", data=data, auth=auth)
        body = resp.json()
        if body.get("error") is None and resp.status_code == 200:
            assert body.get("id_token"), "id_token absent de la réponse CIBA"
            print(f"{label} tokens OK (access_token={body['access_token'][:40]}...)")
            return
        error = body.get("error")
        assert error not in ("access_denied", "expired_token", "invalid_grant"), (
            f"CIBA poll en erreur : {error} — {body.get('error_description', '')}"
        )
        if error == "slow_down":
            delay = max(delay, 1.0)
        time.sleep(delay)

    raise AssertionError(f"{label} tokens never issued within deadline")


def _run_scenario() -> None:
    """Joue le scénario CIBA non signé de bout en bout (client seed)."""
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
            data={"scope": "openid profile", "login_hint": _LOGIN_HINT},
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
        _poll_ciba_tokens(
            client,
            data={"grant_type": _CIBA_GRANT, "auth_req_id": auth_req_id},
            auth=(_CLIENT_ID, _CLIENT_SECRET),
            label="  [4/4]",
        )


def _run_signed_scenario() -> None:
    """Joue le scénario CIBA signé (JAR + ``private_key_jwt``, FAPI-CIBA-ID1)."""
    issuer = f"http://127.0.0.1:{SERVER_PORT}"
    token_endpoint = f"{issuer}/token"
    with httpx.Client(base_url=issuer, timeout=10) as client:
        # 1. Discovery : metadata de signature du request object
        metadata = client.get("/.well-known/openid-configuration").json()
        algorithms = metadata.get("backchannel_authentication_request_signing_alg_values_supported")
        assert algorithms and "PS256" in algorithms, f"algs absents : {algorithms}"
        print(f"  [1/{6}] discovery signé OK (algs={algorithms})")

        # 2. DCR : clé RSA éphémère, private_key_jwt + PS256 exigé
        private, jwks = _signing_material()
        registration = _register_signed_client(issuer, jwks, "poll", "")
        signed_client_id = str(registration["client_id"])
        print(f"  [2/{6}] DCR OK (client_id={signed_client_id}, auth=private_key_jwt)")

        # 3. Le request object est exigé : même authentifié, sans ``request`` → 400
        form = _signed_form(issuer, token_endpoint, signed_client_id, private, _LOGIN_HINT)
        rejected = client.post(
            "/bc-authorize",
            data={
                "client_id": signed_client_id,
                "scope": "openid profile",
                "login_hint": _LOGIN_HINT,
                "client_assertion": form["client_assertion"],
                "client_assertion_type": _ASSERTION_TYPE,
            },
        )
        assert rejected.status_code == 400, f"[3] attendu 400 : {rejected.text}"
        assert rejected.json().get("error") == "invalid_request", rejected.text
        print(f"  [3/{6}] demande non signée rejetée (invalid_request) OK")

        # 4. Backchannel authentication signé (corps sans client_id)
        resp = client.post("/bc-authorize", data=form)
        assert resp.status_code == 200, f"[4] bc-authorize signé refusé : {resp.text}"
        auth_req_id = str(resp.json()["auth_req_id"])
        print(f"  [4/{6}] bc-authorize signé OK (auth_req_id={auth_req_id[:40]}…)")

        # 5. Approbation de la demande
        resp = client.post("/ciba/approve", params={"token": auth_req_id, "type": "allow"})
        assert resp.status_code == 200, f"[5] approve failed: {resp.text}"
        print(f"  [5/{6}] approve OK")

        # 6. Poll authentifié par client_assertion
        _poll_ciba_tokens(
            client,
            data={
                "grant_type": _CIBA_GRANT,
                "auth_req_id": auth_req_id,
                "client_id": signed_client_id,
                "client_assertion": form["client_assertion"],
                "client_assertion_type": _ASSERTION_TYPE,
            },
            auth=None,
            label="  [6/6]",
        )


def main() -> None:
    """Lance les scénarios CIBA (non signé puis signé, port 8116)."""
    print(f"\nScénarios CIBA (deadline={_DEADLINE}s)...")
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            users_seed=_USERS_SEED,
            registration_enabled=True,
            registration_initial_access_tokens=(_REGISTRAR_TOKEN,),
            extra_settings=_EXTRA,
        ),
    ):
        _run_scenario()
        _run_signed_scenario()
    print("OK\n")


if __name__ == "__main__":
    main()
