#!/usr/bin/env python3
"""Smoke test du flux interactif OpenID4VCI (authorization code)."""

from __future__ import annotations

import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "sample-oid4vci-authcode-client")
REDIRECT_URI = "http://127.0.0.1:8765/callback"
CALLBACK_PORT = 8765


def _send(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    """Envoie une requete et renvoie le statut et le corps JSON."""
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        payload = error.read().decode()
        try:
            return error.code, json.loads(payload or "{}")
        except json.JSONDecodeError:
            return error.code, {"error": payload}


def _post_form(path: str, data: dict[str, str]) -> tuple[int, dict[str, object]]:
    """Poste un formulaire et renvoie le statut et le corps JSON."""
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(BASE_URL + path, data=body, method="POST")  # ruff: ignore[suspicious-url-open-usage]
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    return _send(request)


def _post_json(
    path: str, payload: dict[str, object], token: str = ""
) -> tuple[int, dict[str, object]]:
    """Poste un corps JSON et renvoie le statut et le corps JSON."""
    request = urllib.request.Request(  # ruff: ignore[suspicious-url-open-usage]
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    return _send(request)


def main() -> int:
    """Point d entree du smoke test."""
    captured = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/callback":
                params = urllib.parse.parse_qs(parsed.query)
                captured["code"] = params.get("code", [""])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>OK - retournez au terminal</h1>")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    details = json.dumps(
        [{"type": "openid_credential", "credential_configuration_id": "puridentityserver-sdjwt-vc"}]
    )
    auth_url = (
        BASE_URL
        + "/authorize?"
        + urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid4vci",
                "authorization_details": details,
                "state": "sample-state",
            }
        )
    )
    print("Ouvrez cette URL dans votre navigateur :")
    print(auth_url)
    webbrowser.open(auth_url)

    deadline = time.time() + 300
    while "code" not in captured and time.time() < deadline:
        time.sleep(0.5)
    server.shutdown()

    code = captured.get("code")
    if not code:
        print("aucun code recu")
        return 1
    print("code recu")

    status, tokens = _post_form(
        "/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
        },
    )
    if status != 200:
        print(f"echange refuse ({status}) : {tokens}")
        return 1
    print("access token recu ; authorization_details present :", "authorization_details" in tokens)

    issuer = BASE_URL
    status, nb = _post_form("/nonce", {})
    if status != 200:
        print(f"nonce refuse ({status}) : {nb}")
        return 1
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=False)
    )
    public_jwk["alg"] = "ES256"
    proof = jwt.encode(
        {"aud": issuer, "nonce": nb["c_nonce"], "iat": int(time.time())},
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        algorithm="ES256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": public_jwk},
    )

    status, cred = _post_json(
        "/credential",
        {
            "credential_identifier": "puridentityserver-sdjwt-vc",
            "proofs": {"jwt": [proof]},
        },
        token=str(tokens["access_token"]),
    )
    if status != 200:
        print(f"emission refusee ({status}) : {cred}")
        return 1
    print("credential emis :", str(cred["credentials"][0]["credential"])[:40], "...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
