r"""Test manuel de la response mode form_post (Form Post Response Mode 1.0).

Smoke test du sample ``form-post-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8121,
``require_login = true``, client seed public ``sample-form-post-client``)
ainsi qu'un mini-callback local (port 8122) qui joue le rôle du RP côté
navigateur : il reçoit le ``POST`` ``application/x-www-form-urlencoded``
que la page de l'OP soumet. Scénario :

1. le discovery annonce ``form_post`` dans ``response_modes_supported`` ;
2. ``/authorize`` + ``response_mode=form_post`` + ``prompt=none`` (sans
   session) -> **200** (jamais ``302``) : page HTML auto-soumise dont le
   formulaire porte ``error=login_required`` + ``state`` + ``iss`` vers la
   callback **nue**, avec les en-têtes ``no-cache, no-store`` (Form Post §4) ;
3. le test soumet le formulaire comme le ferait le navigateur -> le
   callback RP reçoit bien le ``POST`` (content-type urlencoded) ;
4. ``POST /login`` (alice) -> session authentifiée ;
5. ``/authorize`` + ``form_post`` -> **200** : page auto-soumise portant
   ``code`` + ``state`` + ``iss`` en champs cachés, ``action`` = callback nue
   sans query ni fragment (aucune ``Location`` : pas de redirection 302) ;
6. soumission du formulaire -> le callback RP reçoit les paramètres, puis
   ``/token`` échange le code (PKCE) -> ``200`` access_token ;
7. une demande **sans** ``response_type`` + ``form_post`` -> ``200`` avec
   ``error=invalid_request`` réfléchi dans le formulaire (RFC 6749 §4.1.2.1,
   CA 4 de l'issue #165).

Le sous-processus et le callback sont terminés dans tous les cas
(``finally``) et un garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/form-post-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8121
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"
CALLBACK_PORT = 8122

CLIENT_ID = "sample-form-post-client"
REDIRECT_URI = f"http://{HOST}:{CALLBACK_PORT}/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": "openid profile email",
        "client_type": "public",
    },
)

_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}

_FORM_ACTION = re.compile(r'<form method="post" action="([^"]*)"')
_FORM_INPUT = re.compile(r'name="([^"]*)" value="([^"]*)"')

# Reçus du callback RP : (content-type, paramètres décodés du corps POST).
_RECEIPTS: list[tuple[str, dict[str, str]]] = []


class _CallbackHandler(BaseHTTPRequestHandler):
    """Callback RP : collecte les soumissions ``x-www-form-urlencoded`` de l'OP."""

    def do_POST(self) -> None:
        """Reçoit un formulaire ``POST`` et répond 200."""
        if not urlparse(self.path).path.startswith("/callback"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8")
        params = {name: values[0] for name, values in parse_qs(raw, keep_blank_values=True).items()}
        _RECEIPTS.append((self.headers.get("Content-Type", ""), params))
        body = b"<html><body>recu</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silencieux : le smoke test affiche son propre compte rendu."""


@contextmanager
def _callback_server() -> Iterator[str]:
    """Démarre le mini-callback RP (port dédié) et l'arrête à la sortie."""
    server = ThreadingHTTPServer((HOST, CALLBACK_PORT), _CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield REDIRECT_URI
    finally:
        server.shutdown()
        server.server_close()


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(*, state: str, verifier: str, **extra: str) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation en ``form_post`` (code + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
        "response_mode": "form_post",
    }
    params.update(extra)
    return params


def _parse_form(body: str) -> tuple[str, dict[str, str]]:
    """Extrait l'``action`` nue et les champs cachés dé-échappés de la page."""
    action_match = _FORM_ACTION.search(body)
    assert action_match, f"aucun formulaire POST dans la page : {body[:200]}"
    action = html.unescape(action_match.group(1))
    inputs = {
        html.unescape(name): html.unescape(value) for name, value in _FORM_INPUT.findall(body)
    }
    return action, inputs


def _submit(http: httpx.Client, action: str, params: dict[str, str]) -> dict[str, str]:
    """Soumet le formulaire au callback comme le ferait le navigateur, retourne le reçu."""
    response = http.post(action, data=params)
    assert response.status_code == 200, response.text
    assert _RECEIPTS, "le callback RP n'a reçu aucune soumission"
    content_type, received = _RECEIPTS.pop()
    assert content_type.startswith("application/x-www-form-urlencoded"), content_type
    return received


def _run_scenario() -> None:
    """Joue le scénario form_post (Form Post Response Mode 1.0) de bout en bout."""
    verifier = "formpost-verifier-0123456789"
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        modes = metadata["response_modes_supported"]
        assert "form_post" in modes, sorted(metadata)
        print(f"  [1/7] discovery OK (response_modes_supported={modes})")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state="st-error", verifier=verifier, prompt="none"),
        )
        assert response.status_code == 200, response.text
        assert "location" not in response.headers, "form_post ne redirige jamais en 302"
        assert response.headers["cache-control"] == "no-cache, no-store"
        assert "document.forms[0].submit()" in response.text
        action, inputs = _parse_form(response.text)
        assert action == REDIRECT_URI, action
        assert inputs["error"] == "login_required", sorted(inputs)
        assert inputs["state"] == "st-error"
        assert inputs["iss"] == SERVER_URL
        assert "code" not in inputs
        print("  [2/7] prompt=none sans session -> page 200 auto-soumise (login_required + iss) OK")

        received = _submit(http, action, inputs)
        assert received["error"] == "login_required"
        assert received["state"] == "st-error"
        assert received["iss"] == SERVER_URL
        print(
            "  [3/7] soumission du formulaire d'erreur -> POST urlencoded reçu par le callback OK"
        )

        login = http.post(
            f"{SERVER_URL}/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
        )
        assert login.status_code == 302, login.text
        print("  [4/7] POST /login (alice) -> session authentifiée OK")

        state = "st-formpost-ok"
        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state=state, verifier=verifier),
        )
        assert response.status_code == 200, response.text
        assert "location" not in response.headers, "form_post ne redirige jamais en 302"
        assert response.headers["content-type"].startswith("text/html")
        action, inputs = _parse_form(response.text)
        assert action == REDIRECT_URI, f"l'action doit être la callback nue : {action}"
        assert not urlparse(action).query and not urlparse(action).fragment, action
        assert inputs["code"], sorted(inputs)
        assert inputs["state"] == state
        assert inputs["iss"] == SERVER_URL
        assert "error" not in inputs
        print("  [5/7] /authorize response_mode=form_post -> 200 (action nue, code+state+iss) OK")

        received = _submit(http, action, inputs)
        assert received["code"] == inputs["code"]
        assert received["state"] == state
        assert received["iss"] == SERVER_URL

        token = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": received["code"],
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200, token.text
        body = token.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"]
        print("  [6/7] soumission reçue puis échange du code (PKCE) au /token -> 200 OK")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid profile email",
                "state": "st-missing",
                "response_mode": "form_post",
            },
        )
        assert response.status_code == 200, response.text
        _action, inputs = _parse_form(response.text)
        assert inputs["error"] == "invalid_request", sorted(inputs)
        assert "response_type" in inputs["error_description"]
        assert inputs["state"] == "st-missing"
        assert inputs["iss"] == SERVER_URL
        print("  [7/7] response_type absent + form_post -> invalid_request réfléchi OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique) et le callback RP, puis tout termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            users=_USERS,
            extra_settings={"require_login": True},
        ),
        _callback_server(),
    ):
        print(
            f"\nScénario form_post (Form Post Response Mode 1.0) - "
            f"response_mode=form_post (deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
