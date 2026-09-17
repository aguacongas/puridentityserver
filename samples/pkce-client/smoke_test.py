"""Smoke test du flow Authorization Code + PKCE (sample `pkce-client`).

Lance le serveur puridentityserver et le client de démonstration en sous-processus,
exécute le flux complet et vérifie chaque étape :

1. la page d'accueil du client répond ;
2. `/login` redirige le navigateur vers la page de login du serveur
   (`?next=<authorize>` avec challenge PKCE S256) ;
3. le login réel du serveur (`/login`, cookie de session) est validé et
   redirige vers l'URL `/authorize` construite par le client ;
4. le serveur émet un `code` d'autorisation pour l'utilisateur connecté ;
5. `/callback` échange le code, vérifie l'`id_token` (JWKS), appelle
   `/userinfo` avec le Bearer token et affiche les claims ;
6. le rejeu d'un code consommé est refusé.

Les sous-processus sont terminés dans tous les cas (``finally``). Un
garde-fou borne la durée totale afin de ne jamais bloquer.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/pkce-client/smoke_test.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]

HOST = "127.0.0.1"
SERVER_PORT = 8000
CLIENT_PORT = 5173
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"
CLIENT_URL = f"http://{HOST}:{CLIENT_PORT}"

_HTTP_TIMEOUT = 10
_WAIT_PORT_TIMEOUT = 15
_DEADLINE = 30

_server_proc: subprocess.Popen[bytes] | None = None
_client_proc: subprocess.Popen[bytes] | None = None


def _port_in_use(port: int) -> bool:
    """Indique si un processus écoute déjà sur ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((HOST, port)) == 0


def _wait_port(port: int, timeout: float = _WAIT_PORT_TIMEOUT) -> None:
    """Attend que le port ``port`` accepte des connexions, ou expire."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"Port {port} non prêt après {timeout}s")


def _terminate(processes: list[subprocess.Popen[bytes]]) -> None:
    """Force l'arrêt des sous-processus restants."""
    for proc in processes:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _assert_login_redirect(authorize_url: str) -> tuple[str, str]:
    """Valide l'URL d'autorisation construite par le client et renvoie état + nonce."""
    params = parse_qs(urlparse(authorize_url).query)
    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]
    assert "client_id" in params
    assert params["client_id"] == ["sample-pkce-client"]
    return params["state"][0], params["nonce"][0]


def _run_flow() -> None:
    """Exécute les cinq étapes du flow de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        response = http.get(f"{CLIENT_URL}/")
        assert response.status_code == 200, response.text
        print(f"  [1/6] accueil OK (status={response.status_code})")

        response = http.get(f"{CLIENT_URL}/login")
        assert response.status_code == 302, response.text
        login_page_url = response.headers["location"]
        assert "/login" in urlparse(login_page_url).path, login_page_url
        authorize_url = parse_qs(urlparse(login_page_url).query)["next"][0]
        assert "authorize" in urlparse(authorize_url).path, authorize_url
        state, nonce = _assert_login_redirect(authorize_url)
        print(f"  [2/6] login OK (redirige vers la page de login du serveur, state={state[:8]}...)")

        response = http.post(
            f"{SERVER_URL}/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": authorize_url,
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, response.text
        assert "fastapiusersauth" in response.headers.get("set-cookie", "")
        assert response.headers["location"] == authorize_url
        print("  [3/6] login serveur OK (cookie posé, retour vers /authorize)")

        response = http.get(authorize_url)
        assert response.status_code == 302, response.text
        callback_params = parse_qs(urlparse(response.headers["location"]).query)
        assert callback_params["state"] == [state]
        code = callback_params["code"][0]
        print(f"  [4/6] authorize OK (code={code[:8]}...)")

        callback_url = f"{CLIENT_URL}/callback?code={code}&state={state}"
        response = http.get(callback_url)
        assert response.status_code == 200, response.text
        assert "Connecté" in response.text
        assert "id_token" in response.text
        assert "access_token" in response.text
        assert "UserInfo" in response.text
        assert "alice.martin@example.com" in response.text
        print("  [5/6] callback OK (id_token vérifié + /userinfo interrogé)")

        response = http.get(callback_url)
        assert response.status_code == 400, response.text
        print("  [6/6] rejeu du code refusé OK")
    print("\n=== FLOW OK ===")
    print(f"nonce contrôlé : {nonce[:8]}...")


def main() -> None:
    """Lance serveur et client, joue le flow, puis termine les processus."""
    global _server_proc, _client_proc

    watchdog = threading.Timer(_DEADLINE, _watchdog_exit)
    watchdog.daemon = True
    watchdog.start()

    if _port_in_use(SERVER_PORT) or _port_in_use(CLIENT_PORT):
        raise SystemExit(
            f"Ports {SERVER_PORT}/{CLIENT_PORT} occupés : arrêtez les serveurs dev "
            "avant de lancer le smoke test."
        )

    started_at = time.monotonic()
    env = os.environ.copy()
    try:
        print("Démarrage du serveur puridentityserver...")
        _server_proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "puridentityserver.server:app",
                "--host",
                HOST,
                "--port",
                str(SERVER_PORT),
                "--log-level",
                "warning",
            ],
            cwd=REPO_ROOT,
            env=env,
        )
        _wait_port(SERVER_PORT)

        print("Démarrage du client de démonstration...")
        _client_proc = subprocess.Popen(
            [sys.executable, "samples/pkce-client/app.py"],
            cwd=REPO_ROOT,
            env=env,
        )
        _wait_port(CLIENT_PORT)

        print(f"\nSmoke test (deadline={_DEADLINE}s)...")
        _run_flow()
        print(f"\n=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")
    finally:
        watchdog.cancel()
        _terminate([_server_proc, _client_proc])


def _watchdog_exit() -> None:
    """Force une sortie en cas de blocage du scénario au-delà de `_DEADLINE`."""
    print(f"\nÉCHEC : smoke test bloqué au-delà de {_DEADLINE}s", file=sys.stderr)
    os._exit(2)


if __name__ == "__main__":
    main()
