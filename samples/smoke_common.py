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
from collections.abc import Iterator, Mapping
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


def _render_blocks(table: str, items: tuple[dict[str, object], ...]) -> str:
    """Rend la séquence de blocs ``[[settings.<table>]]`` pour chaque ``item``.

    Les valeurs imbriquées (listes, tables inline ``jwks``) passent par
    :func:`_render_settings_value` : ``json.dumps`` seul produirait du JSON
    (``{"kty": "RSA"}``) invalide en TOML (``{"kty" = "RSA"}`` attendu).
    """
    blocks: list[str] = []
    for item in items:
        lines = [f"[[settings.{table}]]"]
        for key, value in item.items():
            lines.append(f"{key} = {_render_settings_value(value)}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _render_settings_value(value: object) -> str:
    """Rend une valeur ``[settings]`` en TOML (scalaire, liste ou objet inline).

    Les ``Mapping`` deviennent des tables inline TOML (``{ "clé" = valeur }``),
    rendues récursivement : c'est le format de ``swagger_ui_init_oauth`` et
    des ``jwks`` client (listes de tables inline).
    """
    if isinstance(value, Mapping):
        rendered = ", ".join(
            f"{json.dumps(str(key))} = {_render_settings_value(entry)}"
            for key, entry in value.items()
        )
        return "{" + rendered + "}"
    if isinstance(value, (list, tuple)):
        rendered = ", ".join(_render_settings_value(entry) for entry in value)
        return f"[{rendered}]"
    return json.dumps(value)


def _render_toml_table(path: str, values: Mapping[str, object]) -> str:
    """Rend la table TOML ``path`` ; les sous-dictes deviennent des sous-tables.

    Les clés scalaires précèdent toujours les sous-tables (règle TOML), quel que
    soit l'ordre des entrées de ``values``.
    """
    scalars = [
        f"{key} = {_render_settings_value(value)}"
        for key, value in values.items()
        if not isinstance(value, Mapping)
    ]
    tables = [
        _render_toml_table(f"{path}.{key}", value)
        for key, value in values.items()
        if isinstance(value, Mapping)
    ]
    return "\n\n".join(["\n".join([f"[{path}]", *scalars]), *tables])


def render_server_config(
    *,
    port: int,
    clients: tuple[dict[str, object], ...],
    users: Mapping[str, Mapping[str, str]] | None = None,
    users_seed: Mapping[str, Mapping[str, object]] | None = None,
    api_resources: tuple[dict[str, object], ...] = (),
    registration_enabled: bool = False,
    registration_initial_access_tokens: tuple[str, ...] = (),
    jwks_algorithms: tuple[str, ...] = _JWKS_ALGORITHMS,
    extra_settings: Mapping[str, object] | None = None,
    issuer: str | None = None,
) -> str:
    """Rend le TOML d'un serveur minimal déclarant ``clients`` (+``users``) sur ``port``.

    ``api_resources`` ajoute des ApiResources seed (``[[settings.api_resources_seed]]``
    : ``name``, ``display_name``, ``scopes`` et ``allowed_access_token_signing_algos``
    en option).
    ``registration_enabled`` ajoute les réglages de Dynamic Client
    Registration (RFC 7591/7592) : endpoint ``/register`` activé et liste des
    initial access tokens autorisés (la création exige un Bearer token).
    ``jwks_algorithms`` choisit les algorithmes de signature fournis (défaut
    ``RS256`` — un smoke test des HS* doit passer ``("RS256", "HS256", ...)``).
    ``extra_settings`` ajoute des clés ``[settings]`` arbitraires (ex.
    ``role``, ``admin_required_claim_values``, mode de registration).
    ``issuer`` fixe ``issuer`` **et** ``base_url`` (défaut : ``issuer`` =
    ``http://127.0.0.1:port`` et ``base_url`` vide) — nécessaire quand le
    client attend un issuer canonique quelconque, ex. ``https://id.example``
    pour ``tests/conformance/``.
    ``users_seed`` déclare les profils de claims
    (``[settings.users_seed.<subject>]``, sous-dictes = sous-tables TOML) que
    ``/userinfo`` rend pour les scopes accordés.
    """
    resolved_issuer = issuer or f"http://{HOST}:{port}"
    resolved_base_url = resolved_issuer if issuer is not None else ""
    head = (
        "[settings]\n"
        f'issuer = "{resolved_issuer}"\n'
        f'base_url = "{resolved_base_url}"\n'
        f'host = "{HOST}"\n'
        f"port = {port}\n"
        f"jwks_algorithms = {json.dumps(list(jwks_algorithms))}\n"
    )
    lines: list[str] = []
    if registration_enabled:
        lines.append("registration_enabled = true")
        if registration_initial_access_tokens:
            rendered = ", ".join(json.dumps(t) for t in registration_initial_access_tokens)
            lines.append(f"registration_initial_access_tokens = [{rendered}]")
    for key, value in (extra_settings or {}).items():
        lines.append(f"{key} = {_render_settings_value(value)}")
    head += "\n".join(lines) + "\n\n"
    blocks = [
        _render_blocks("clients_seed", clients),
        _render_blocks("api_resources_seed", api_resources),
    ]
    for subject, credentials in (users or {}).items():
        lines = [f"[settings.identity_seed_users.{subject}]"]
        for key, value in credentials.items():
            lines.append(f"{key} = {json.dumps(value)}")
        blocks.append("\n".join(lines))
    for subject, claims in (users_seed or {}).items():
        blocks.append(_render_toml_table(f"settings.users_seed.{subject}", claims))
    return head + "\n\n".join(block for block in blocks if block) + "\n"


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
def run_server(
    *,
    port: int,
    clients: tuple[dict[str, object], ...],
    users: Mapping[str, Mapping[str, str]] | None = None,
    users_seed: Mapping[str, Mapping[str, object]] | None = None,
    api_resources: tuple[dict[str, object], ...] = (),
    registration_enabled: bool = False,
    registration_initial_access_tokens: tuple[str, ...] = (),
    jwks_algorithms: tuple[str, ...] = _JWKS_ALGORITHMS,
    extra_settings: Mapping[str, object] | None = None,
    issuer: str | None = None,
) -> Iterator[str]:
    """Lance un serveur dédié pour la configuration spécifique de ce test.

    Génère la configuration (issuer = ``port``, clients seed ``clients``,
    comptes de connexion ``users``, ApiResources seed ``api_resources``,
    éventuellement la Dynamic Client Registration activée avec ses initial
    access tokens, algorithmes de signature ``jwks_algorithms``, plus
    ``extra_settings``) dans un fichier temporaire, démarre le serveur uvicorn
    sur ``port`` puis fournit l'URL de base jusqu'à la sortie du bloc
    (sous-processus terminé). ``issuer`` fixe ``issuer``/``base_url`` (voir
    :func:`render_server_config`) — l'URL fournie reste celle du port.
    ``users_seed`` apporte les profils de claims rendus par ``/userinfo``.
    """
    if port_in_use(port):
        raise SystemExit(f"Port {port} occupé : arrêtez le serveur qui écoute sur {port}.")

    with tempfile.TemporaryDirectory() as tmp:
        settings_file = Path(tmp) / "config.toml"
        settings_file.write_text(
            render_server_config(
                port=port,
                clients=clients,
                users=users,
                users_seed=users_seed,
                api_resources=api_resources,
                registration_enabled=registration_enabled,
                registration_initial_access_tokens=registration_initial_access_tokens,
                jwks_algorithms=jwks_algorithms,
                extra_settings=extra_settings,
                issuer=issuer,
            ),
            encoding="utf-8",
        )
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
