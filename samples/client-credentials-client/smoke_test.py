"""Test manuel du grand client_credentials (RFC 6749 §4.4).

Smoke test du sample ``client-credentials-client``.

Lance un serveur PurIdentityServer en sous-processus avec la
configuration dédiée ``samples/client-credentials-client/config.toml``
(port 8102, client confidentiel ``sample-cc-client``, scopes
``openid profile``), puis joue le scénario :

1. le discovery annonce ``grant_types_supported`` incluant ``client_credentials`` ;
2. ``/token`` (client_credentials + secret) -> access_token seul (scope
   ``openid profile``, aucun ``id_token``) ;
3. scop restreint ``openid`` -> access_token au scop ``openid`` ;
4. scop non enregistré pour le client (``email``) -> ``400 invalid_scope`` ;
5. secret erroné -> ``400 invalid_client`` ;
6. secret absent -> ``400 invalid_client`` ;
7. client inconnu -> ``400 invalid_client``.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/client-credentials-client/smoke_test.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_FILE = Path(__file__).resolve().with_name("config.toml")

HOST = "127.0.0.1"
SERVER_PORT = 8102
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-cc-client"
CLIENT_SECRET = "cc-demo-secret"
_SCOPE = "openid profile"

_HTTP_TIMEOUT = 10
_WAIT_PORT_TIMEOUT = 15
_DEADLINE = 60

_server_proc: subprocess.Popen[bytes] | None = None


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


def _token(
    http: httpx.Client,
    *,
    secret: str = CLIENT_SECRET,
    client_id: str = CLIENT_ID,
    scope: str | None = None,
) -> httpx.Response:
    """Appelle ``/token`` avec le grand client_credentials."""
    data: dict[str, object] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    }
    if scope is not None:
        data["scope"] = scope
    return http.post(f"{SERVER_URL}/token", data=data)


def _run_scenario() -> None:
    """Joue le scénario client_credentials de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "client_credentials" in metadata["grant_types_supported"]
        print(f"  [1/7] discovery OK (grant_types_supported={metadata['grant_types_supported']})")

        response = _token(http)
        assert response.status_code == 200, response.text
        first = response.json()
        assert first["access_token"]
        assert first["token_type"] == "Bearer"
        assert first["scope"] == "openid profile"
        assert "id_token" not in first
        print(
            "  [2/7] client_credentials -> access_token seul "
            f"(scope={first['scope']}, expires_in={first['expires_in']}) OK"
        )

        response = _token(http, scope="openid")
        assert response.status_code == 200, response.text
        assert response.json()["scope"] == "openid"
        print("  [3/7] scope restreint (openid) OK")

        response = _token(http, scope="email")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_scope"
        print("  [4/7] scope non enregistré -> 400 invalid_scope OK")

        response = _token(http, secret="mauvais-secret")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [5/7] secret erroné -> 400 invalid_client OK")

        response = _token(http, secret="")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [6/7] secret absent -> 400 invalid_client OK")

        response = _token(http, client_id="ghost")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [7/7] client inconnu -> 400 invalid_client OK")
    print()


def main() -> None:
    """Lance le serveur de test, joue le scénario, puis le termine."""
    global _server_proc

    watchdog = threading.Timer(_DEADLINE, _watchdog_exit)
    watchdog.daemon = True
    watchdog.start()

    if _port_in_use(SERVER_PORT):
        raise SystemExit(
            f"Port {SERVER_PORT} occupé : arrêtez le serveur sur le port {SERVER_PORT} "
            "avant de lancer ce test."
        )

    started_at = time.monotonic()
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("PURIDENTITYSERVER_") and key != "PURIDENTITYSERVER_SETTINGS_FILE":
            env.pop(key)
    env["PURIDENTITYSERVER_SETTINGS_FILE"] = str(SETTINGS_FILE)
    try:
        print(f"Démarrage du serveur puridentityserver (config {SETTINGS_FILE.name})...")
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
        print(f"\nScénario client_credentials (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"\n=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")
    finally:
        watchdog.cancel()
        try:
            if _server_proc is not None:
                _server_proc.kill()
                _server_proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _watchdog_exit() -> None:
    """Force une sortie en cas de blocage du scénario au-delà de `_DEADLINE`."""
    print(f"\nÉCHEC : test bloqué au-delà de {_DEADLINE}s", file=sys.stderr)
    os._exit(2)


if __name__ == "__main__":
    main()
