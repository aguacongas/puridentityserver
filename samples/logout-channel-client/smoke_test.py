"""Test bout en bout des canaux de notification front/back-channel (#48).

Smoke test du sample ``logout-channel-client``.

Lance :
1. un mini serveur « RP » (HTTP standard, thread) qui joue les deux canaux
   déclarés par le client de démo (port 8200) :
   - ``GET /front-logout`` (front-channel, OIDC FCL 1.0 §2) enregistre le
     ``sid`` reçu en query (l'OP le charge en iframe) ;
   - ``POST /back-logout`` (back-channel, OIDC BCL 1.0 §3) reçoit le
     ``logout_token`` envoyé par l'OP et le mémorise ;
2. un serveur PurIdentityServer dédié (port 8105, client seed déclarant
   les deux URI + comptes utilisateurs) puis joue le scénario :

   1. le discovery annonce les booleans ``frontchannel_logout_supported`` /
      ``backchannel_logout_supported`` (et variantes ``*_session_supported``) ;
   2. ``/login`` → cookie de session RS256 portant un ``sid`` ;
   3. ``/authorize`` (PKCE) → ``/token`` → ``id_token`` dont le claim
      ``sid`` vaut celui du cookie (OIDC Session Management §2) ;
   4. ``GET /end_session`` (avec l'``id_token_hint`` et le cookie) :
      l'OP notifie le client en back-channel (``logout_token`` POST) ; la
      page rend l'iframe front-channel ``/front-logout?sid=<sid>`` ;
   5. le client vérifie le ``logout_token`` reçu (signature JWKS, ``iss``,
      ``aud``, ``sub``, ``sid``, events backchannel) ;
   6. le user agent « ouvre » l'iframe front-channel et le serveur RP
      reçoit bien ``sid``.

Le sous-processus serveur et le listener RP sont terminés dans tous les
cas et un garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/logout-channel-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8105
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

RP_PORT = 8200
RP_URL = f"http://{HOST}:{RP_PORT}"
FRONT_LOGOUT_URI = f"{RP_URL}/front-logout"
BACK_LOGOUT_URI = f"{RP_URL}/back-logout"

CLIENT_ID = "sample-logout-channel-client"
REDIRECT_URI = "http://127.0.0.1:5178/callback"
POST_LOGOUT_URI = "http://127.0.0.1:5178/done"
_SCOPE = "openid profile email"

_USERS = {
    "alice": {"email": "alice@example.com", "password": "password"},
}

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "post_logout_redirect_uris": [POST_LOGOUT_URI],
        "scopes": _SCOPE,
        "client_type": "confidential",
        "client_secret": "logout-demo-secret",
        "frontchannel_logout_uri": FRONT_LOGOUT_URI,
        "frontchannel_logout_session_required": True,
        "backchannel_logout_uri": BACK_LOGOUT_URI,
    },
)

_VERIFIER = "logout-channel-verifier-0123456789abcdefghijklmnopqrstuvwxyz"
_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(_VERIFIER.encode("ascii")).digest())
    .rstrip(b"=")
    .decode("ascii")
)

_HTTP_TIMEOUT = 10
_DEADLINE = 60


class RPCapture:
    """Mémorise ce que le mini serveur RP a reçu sur ses deux canaux."""

    def __init__(self) -> None:
        """Initialise les captures vides sous verrou."""
        self._lock = threading.Lock()
        self.front_sids: list[str] = []
        self.logout_tokens: list[str] = []

    def record_front(self, sid: str) -> None:
        """Consigne le ``sid`` reçu sur ``GET /front-logout``."""
        with self._lock:
            self.front_sids.append(sid)

    def record_back(self, logout_token: str) -> None:
        """Consigne le ``logout_token`` reçu sur ``POST /back-logout``."""
        with self._lock:
            self.logout_tokens.append(logout_token)

    def snapshot_back(self) -> list[str]:
        """Retourne un instantané des ``logout_token`` reçus."""
        with self._lock:
            return list(self.logout_tokens)


_CAPTURE = RPCapture()


class RPHandler(BaseHTTPRequestHandler):
    """Endpoint de la « RP » : ``GET /front-logout`` et ``POST /back-logout``."""

    def log_message(self, format: str, *args: object) -> None:  # ruff: ignore[builtin-argument-shadowing]
        """Taît les logs HTTP (ou affichés par le test, pas le framework)."""
        return None

    def do_GET(self) -> None:
        """Front-channel : enregistre le ``sid`` reçu en query."""
        parsed = urlparse(self.path)
        if parsed.path != "/front-logout":
            self.send_error(404)
            return
        sid = parse_qs(parsed.query).get("sid", [""])[0]
        _CAPTURE.record_front(sid)
        self.send_response(204)
        self.end_headers()

    def do_POST(self) -> None:
        """Back-channel : enregistre le ``logout_token`` du formulaire."""
        parsed = urlparse(self.path)
        if parsed.path != "/back-logout":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        tokens = form.get("logout_token", [])
        for token in tokens:
            _CAPTURE.record_back(token)
        self.send_response(204)
        self.end_headers()


@contextmanager
def serve_rp() -> Iterator[None]:
    """Lance le listener RP sur ``RP_PORT`` ; le ferme en sortie de bloc."""
    if port_in_use(RP_PORT):
        raise SystemExit(f"Port {RP_PORT} occupé : arrêtez le processus qui écoute dessus.")

    server = ThreadingHTTPServer((HOST, RP_PORT), RPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()


def port_in_use(port: int) -> bool:
    """Indique si un processus écoute déjà sur ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((HOST, port)) == 0


def _run_scenario() -> None:
    """Joue le scénario front/back-channel de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["frontchannel_logout_supported"] is True
        assert metadata["frontchannel_logout_session_supported"] is True
        assert metadata["backchannel_logout_supported"] is True
        assert metadata["backchannel_logout_session_supported"] is True
        print("  [1/6] discovery : booleans front/back-channel logué")
        jwks = http.get(f"{SERVER_URL}/.well-known/jwks.json").json()["keys"]

        login = http.post(
            f"{SERVER_URL}/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
        )
        assert login.status_code == 302, login.text
        print("  [2/6] login -> cookie de session RS256 avec sid OK")

        authorize = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": _SCOPE,
                "code_challenge": _CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        assert authorize.status_code == 302, authorize.text
        code = parse_qs(urlparse(authorize.headers["location"]).query)["code"][0]

        token_resp = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": _CLIENTS[0]["client_secret"],
                "code_verifier": _VERIFIER,
            },
        )
        assert token_resp.status_code == 200, token_resp.text
        id_token = token_resp.json()["id_token"]
        public_key = RSAAlgorithm.from_jwk(jwks[0])
        id_claims = pyjwt.decode(
            id_token, public_key, algorithms=["RS256"], audience=CLIENT_ID, issuer=SERVER_URL
        )
        assert id_claims["sid"], "l'id_token doit porter le sid (OIDC Session Management §2)"
        print(f"  [3/6] authorize/token -> id_token sid={id_claims['sid'][:8]}... OK")

        end_session = http.get(
            f"{SERVER_URL}/end_session",
            params={"id_token_hint": id_token, "post_logout_redirect_uri": POST_LOGOUT_URI},
        )
        assert end_session.status_code == 200, end_session.text
        print("  [4/6] /end_session -> notifications front/back déclenchées")

        logout_tokens = _CAPTURE.snapshot_back()
        assert len(logout_tokens) == 1, f"logout_token attendu, reçu: {logout_tokens}"
        logout_claims = pyjwt.decode(
            logout_tokens[0],
            public_key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=SERVER_URL,
        )
        events = logout_claims["events"]
        assert "http://schemas.openid.net/event/backchannel-logout" in events
        assert logout_claims["sub"] == id_claims["sub"]
        assert logout_claims["sid"] == id_claims["sid"]
        assert logout_claims["jti"]
        print("  [5/6] back-channel : logout_token valide (iss/aud/sub/sid/events) OK")

        iframe_src = _extract_front_logout_src(end_session.text)
        assert FRONT_LOGOUT_URI in iframe_src
        assert f"?sid={id_claims['sid']}" in iframe_src
        front_response = http.get(iframe_src)
        assert front_response.status_code == 204, front_response.text
        assert _CAPTURE.front_sids and _CAPTURE.front_sids[-1] == id_claims["sid"]
        print("  [6/6] front-channel : iframe /front-logout?sid=<sid> chargée OK")
    print()


def _extract_front_logout_src(page: str) -> str:
    """Extrait l'``src`` de l'iframe front-channel de la page /end_session."""
    marker = f'src="{FRONT_LOGOUT_URI}'
    start = page.index(marker) + len('src="')
    end = page.index('"', start)
    return page[start:end].replace("&amp;", "&")


def main() -> None:
    """Lance le listener RP puis le serveur dédié, joue le scénario."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        serve_rp(),
        run_server(port=SERVER_PORT, clients=_CLIENTS, users=_USERS),
    ):
        print(
            f"\nScénario front/back-channel logout "
            f"(RP listener {RP_PORT}, OP {SERVER_PORT}, deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
