"""Utilitaires partagés des smoke tests des samples.

Chaque smoke test **passe sa propre configuration serveur** : un mini
``config.toml`` (issuer = son port dédié, ses clients seed) est généré dans
un fichier temporaire et transmis au serveur via
``PURIDENTITYSERVER_SETTINGS_FILE``. Chaque test reste ainsi hermétique
(isolé, déterministe) sans fichier de configuration committé par sample :
les clients de démo sont déclarés une seule fois, dans la configuration
**par défaut** du serveur (``config.toml`` à la racine du dépôt).

Usage (dans un smoke test) ::

    with watchdog(_DEADLINE), run_server(port=SERVER_PORT, clients=_CLIENTS):
        _run_scenario()
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"

_WAIT_PORT_TIMEOUT = 15
_JWKS_ALGORITHMS = ["RS256"]


def port_in_use(port: int) -> bool:
    """Indique si un processus écoute déjà sur ``port``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((HOST, port)) == 0


def wait_port(port: int, timeout: float = _WAIT_PORT_TIMEOUT) -> None:
    """Attend que le port ``port`` accepte des connexions, ou expire."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"Port {port} non prêt après {timeout}s")


def render_server_config(*, port: int, clients: tuple[dict[str, object], ...]) -> str:
    """Rend le TOML d'un serveur minimal déclarant ``clients`` sur ``port``."""
    head = (
        "[settings]\n"
        f'issuer = "http://{HOST}:{port}"\n'
        'base_url = ""\n'
        f'host = "{HOST}"\n'
        f"port = {port}\n"
        f"jwks_algorithms = {json.dumps(_JWKS_ALGORITHMS)}\n\n"
    )
    blocks: list[str] = []
    for client in clients:
        lines = ["[[settings.clients_seed]]"]
        for key, value in client.items():
            if isinstance(value, (list, tuple)):
                rendered = ", ".join(json.dumps(item) for item in value)
                lines.append(f"{key} = [{rendered}]")
            else:
                lines.append(f"{key} = {json.dumps(value)}")
        blocks.append("\n".join(lines))
    return head + "\n".join(blocks) + "\n"


@contextmanager
def watchdog(seconds: float = 60) -> Iterator[None]:
    """Force une sortie si le bloc ``with`` dépasse ``seconds`` (garde-fou)."""
    timer = threading.Timer(seconds, _watchdog_exit)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()


def _watchdog_exit() -> None:
    print("\nÉCHEC : test bloqué au-delà du délai imparti", file=sys.stderr)
    os._exit(2)


@contextmanager
def run_server(*, port: int, clients: tuple[dict[str, object], ...]) -> Iterator[str]:
    """Lance un serveur dédié pour la configuration spécifique de ce test.

    Génère la configuration (issuer = ``port``, clients seed ``clients``)
    dans un fichier temporaire, démarre le serveur uvicorn sur ``port`` puis
    fournit l'URL de base jusqu'à la sortie du bloc (sous-processus terminé).
    """
    if port_in_use(port):
        raise SystemExit(f"Port {port} occupé : arrêtez le serveur qui écoute sur {port}.")

    with tempfile.TemporaryDirectory() as tmp:
        settings_file = Path(tmp) / "config.toml"
        settings_file.write_text(render_server_config(port=port, clients=clients), encoding="utf-8")
        proc: subprocess.Popen[bytes] | None = None
        try:
            print("Démarrage du serveur puridentityserver (config générée par le test)...")
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "puridentityserver.server:app",
                    "--host",
                    HOST,
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                cwd=REPO_ROOT,
                env=_purged_env(settings_file),
            )
            wait_port(port)
            yield f"http://{HOST}:{port}"
        finally:
            if proc is not None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def _purged_env(settings_file: Path) -> dict[str, str]:
    """Copie de l'environnement sans les ``PURIDENTITYSERVER_*`` parasites."""
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("PURIDENTITYSERVER_") and key != "PURIDENTITYSERVER_SETTINGS_FILE":
            env.pop(key)
    env["PURIDENTITYSERVER_SETTINGS_FILE"] = str(settings_file)
    return env
