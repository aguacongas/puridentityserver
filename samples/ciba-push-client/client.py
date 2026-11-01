"""Client de demonstration : CIBA en mode push (OIDC CIBA 1.0).

Le client initie une demande /bc-authorize, l'utilisateur approuve via
/ciba/approve, puis le serveur envoie une notification push sous forme
de JWT signe au listener local. Les jetons sont dans ce JWT.

Usage:
    python client.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import jwt

_DEFAULT_ISSUER = "http://127.0.0.1:8000"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_NOTIFY_PATH = "/notify"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _start_listener(port: int, received: dict) -> ThreadingHTTPServer:
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            authorization = self.headers.get("Authorization", "")
            print("\n[push] Notification recue")
            print(f"       Authorization : {authorization[:40]}...")
            try:
                text = body.decode("utf-8")
                claims = jwt.decode(text, options={"verify_signature": False})
                print("       JWT (claims) :")
                print(json.dumps(claims, indent=2))
                received["notification"] = claims
                received["raw"] = text
            except Exception as exc:  # noqa: BLE001
                print(f"       Corps brut : {body!r}")
                print(f"       Erreur de decodage : {exc}")
                received["raw"] = body.decode("utf-8", "replace")
            self.send_response(204)
            self.end_headers()
            received["event"].set()

        def log_message(self, fmt: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    issuer = (sys.argv[1] if len(sys.argv) > 1 else _env("CIBA_ISSUER", _DEFAULT_ISSUER)).rstrip("/")
    client_id = _env("CIBA_CLIENT_ID", "sample-ciba-push-client")
    client_secret = _env("CIBA_CLIENT_SECRET", "ciba-push-demo-secret")
    login_hint = _env("CIBA_LOGIN_HINT", "alice.martin@example.com")
    port = int(_env("CIBA_NOTIFY_PORT", "8119"))

    received: dict = {"event": threading.Event()}
    server = _start_listener(port, received)
    print(f"[push] Listener demarre sur http://127.0.0.1:{port}{_NOTIFY_PATH}")

    with httpx.Client(timeout=10) as client:
        resp = client.post(
            f"{issuer}/bc-authorize",
            data={"scope": "openid profile email", "login_hint": login_hint},
            auth=(client_id, client_secret),
        )
        print(f"\n[bc-authorize] status={resp.status_code}")
        print(resp.text)
        resp.raise_for_status()
        body = resp.json()
        auth_req_id = body["auth_req_id"]
        print(f"auth_req_id={auth_req_id}")

        print("\nApprouvez la demande dans un autre terminal :")
        print(f'curl -X POST "{issuer}/ciba/approve?token={auth_req_id}&type=allow"')
        print("En attente de la notification push (max 120 s)...")
        if not received["event"].wait(timeout=120):
            print("Timeout : aucune notification recue.")
            server.shutdown()
            return 1

    server.shutdown()
    print("\nNotification push recue et decodee avec succes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""
path = pathlib.Path(r"C:\Projects\Perso\PurIdentityServer\samples\ciba-push-client\client.py")
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(content, encoding="utf-8")
print("done")
EOF