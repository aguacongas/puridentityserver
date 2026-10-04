"""Client de démonstration : CIBA (OIDC CIBA 1.0 — backchannel).

Enchaîne le flow CIBA contre le serveur configuré (défaut
``http://127.0.0.1:8000``) :

1. ``POST /bc-authorize`` (Basic auth, ``login_hint``) → ``auth_req_id`` ;
2. approbation de la demande via l'endpoint démo ``/ciba/approve``
   (la commande ``curl`` équivalente est affichée) ;
3. poll sur ``/token`` (grant ``urn:openid:params:grant-type:ciba``)
   jusqu'aux jetons, un refus ou l'expiration.

Mode ping : ``CIBA_MODE=ping`` démarre un listener local qui reçoit la
notification JSON du serveur (``client_notification_token`` + endpoint
``sample-ciba-ping-client``) avant le poll final.

Utilise ``httpx`` pour les appels HTTP et ``pyjwt`` pour décoder
l'``id_token``.

Usage::

    python client.py                        # défaut http://127.0.0.1:8000
    python client.py https://auth.example   # issuer explicite
    CIBA_MODE=ping python client.py         # mode ping (listener local)
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import jwt

_DEFAULT_ISSUER = "http://127.0.0.1:8000"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_NOTIFICATION_PATH = "/notify"


def _discovery(issuer: str) -> dict[str, object]:
    """Charge le document de discovery."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with httpx.Client(timeout=10) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _start_ping_listener(port: int) -> tuple[ThreadingHTTPServer, threading.Event]:
    """Démarre le listener local qui reçoit la notification CIBA (mode ping)."""
    received = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length).decode("utf-8", "replace")
            bearer = self.headers.get("Authorization", "")
            print(f"\n[ping] Notification reçue ({self.path})")
            print(f"       Authorization : {bearer[:40]}...")
            try:
                print(f"       Corps : {json.dumps(json.loads(payload), indent=2)}")
            except ValueError:
                print(f"       Corps : {payload}")
            self.send_response(200)
            self.end_headers()
            received.set()

        def log_message(self, fmt: str, *args: object) -> None:
            """Supprime le log par défaut sur stderr."""

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[ping] Listener démarré sur http://127.0.0.1:{port}{_NOTIFICATION_PATH}")
    return server, received


def _request_authentication(
    client: httpx.Client,
    endpoint: str,
    client_id: str,
    client_secret: str,
    login_hint: str,
    notification_token: str,
) -> dict[str, object]:
    """Lance la backchannel authentication request (§7.1)."""
    data: dict[str, str] = {
        "scope": "openid profile",
        "login_hint": login_hint,
    }
    if notification_token:
        data["client_notification_token"] = notification_token
    resp = client.post(
        endpoint,
        data=data,
        auth=(client_id, client_secret),
    )
    if resp.status_code >= 400:
        print(f"ERREUR {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def _approve(base_url: str, auth_req_id: str, decision: str) -> None:
    """Prend la décision sur la demande via l'endpoint démo /ciba/approve."""
    resp = httpx.post(
        f"{base_url}/ciba/approve",
        params={"token": auth_req_id, "type": decision},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"ERREUR approbation {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)


def _poll_tokens(
    client: httpx.Client,
    token_endpoint: str,
    auth_req_id: str,
    interval: int,
) -> dict[str, object]:
    """Interroge le token endpoint jusqu'à succès, refus ou expiration (§11)."""
    delay = max(interval, 1)
    while True:
        resp = client.post(
            token_endpoint,
            data={
                "grant_type": CIBA_GRANT,
                "auth_req_id": auth_req_id,
            },
        )
        body = resp.json()
        error = body.get("error")
        if error is None:
            return body
        if error in ("access_denied", "expired_token", "invalid_grant"):
            print(f"\nErreur : {error} — {body.get('error_description', '')}")
            sys.exit(1)
        if error == "slow_down":
            delay += 5
        print(f"  ... {error} (prochaine tentative dans {delay}s)")
        time.sleep(delay)


def _decode_claims(token: str) -> dict[str, object]:
    """Décode le payload JWT sans vérifier la signature (démo uniquement)."""
    return jwt.decode(token, options={"verify_signature": False})


def main() -> None:
    """Point d'entrée du client démo : flow CIBA (poll ou ping)."""
    issuer = os.environ.get("CIBA_ISSUER", _DEFAULT_ISSUER).strip().rstrip("/")
    client_id = os.environ.get("CIBA_CLIENT_ID", "sample-ciba-client")
    client_secret = os.environ.get("CIBA_CLIENT_SECRET", "ciba-demo-secret")
    login_hint = os.environ.get("CIBA_LOGIN_HINT", "alice.martin@example.com")
    mode = os.environ.get("CIBA_MODE", "poll").strip().lower()
    notify_port = int(os.environ.get("CIBA_NOTIFY_PORT", "8118"))

    print(f"CIBA (OIDC CIBA 1.0) contre {issuer} — mode {mode}\n")

    metadata = _discovery(issuer)
    bc_endpoint = metadata["backchannel_authentication_endpoint"]
    token_endpoint = metadata["token_endpoint"]
    print(f"[1] Discovery chargé — backchannel_authentication_endpoint = {bc_endpoint}")

    listener: ThreadingHTTPServer | None = None
    received = threading.Event()
    notification_token = ""
    if mode == "ping":
        notification_token = secrets.token_urlsafe(32)
        listener, received = _start_ping_listener(notify_port)

    with httpx.Client(base_url=issuer, timeout=15) as client:
        ack = _request_authentication(
            client, str(bc_endpoint), client_id, client_secret, login_hint, notification_token
        )
        auth_req_id = str(ack["auth_req_id"])
        interval = int(ack.get("interval", 5))
        print(
            f"[2] Demande créée — auth_req_id = {auth_req_id[:40]}… "
            f"(expire dans {ack['expires_in']}s, interval = {interval}s)"
        )
        print("    Approbation manuelle possible depuis un autre terminal :")
        print(f'    curl -X POST "{issuer}/ciba/approve?token={auth_req_id}&type=allow"')

        choice = input("\n    Approuver cette demande ? [O/n] ").strip().lower()
        decision = "deny" if choice in ("n", "no", "non") else "allow"
        _approve(issuer, auth_req_id, decision)
        print(f"[3] Décision envoyée : {decision}")

        if mode == "ping":
            if received.wait(timeout=30):
                print("[4] Notification ping reçue — récupération des jetons")
            else:
                print("[4] Aucune notification (timeout 30s) — tentative de poll anyway")

        print("\n  [5] Poll en cours... ", end="", flush=True)
        tokens = _poll_tokens(client, str(token_endpoint), auth_req_id, interval)

        print("OK !\n")
        print("Tokens reçus :")
        print(f"  access_token : {tokens['access_token'][:50]}...")
        if tokens.get("id_token"):
            print(f"  id_token     : {tokens['id_token'][:50]}...")
        if tokens.get("refresh_token"):
            print(f"  refresh_token: {tokens['refresh_token'][:50]}...")
        print(f"  expires_in   : {tokens.get('expires_in')}")
        print(f"  scope        : {tokens.get('scope', '')}")

        if tokens.get("id_token"):
            claims = _decode_claims(tokens["id_token"])
            print("\nClaims du id_token (décodage sans vérification) :")
            print(json.dumps(claims, indent=2, ensure_ascii=False))

    if listener is not None:
        listener.shutdown()


if __name__ == "__main__":
    main()
