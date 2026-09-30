r"""Smoke : rejoue toute la suite de conformance contre un vrai serveur uvicorn.

Smoke test du chantier « rejouer la certification OIDC en tests Python
locaux » (PR 4/4, issue #72).

Le serveur PurIdentityServer est lancé en sous-processus (port 8121,
``config.toml`` généré reproduisant les seeds du harness : issuer/base_url
``https://id.example``, clients ``web-app`` + ``mobile-app`` +
``unsigned-app`` (``id_token_signed_response_alg=none``), compte ``alice``,
profils de claims ``users_seed`` repris du ``config.toml`` racine,
``require_login = true``), puis ``PURIDENTITYSERVER_CONFORMANCE_URL`` est
exporté : le harness (``tests/conformance/harness.py``) bascule alors sur du
httpx réel au lieu de l'ASGI in-process, et ``pytest -m conformance`` rejoue
les 188 scénarios des plans Basic, Implicit et Hybrid contre le serveur
réel. Le code retour de pytest est propagé ; un garde-fou borne la durée.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/conformance-smoke/smoke_test.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import run_server, watchdog  # ruff: ignore[module-import-not-at-top-of-file]

sys.path.insert(0, str(REPO_ROOT / "tests" / "conformance"))

from conftest import (  # ruff: ignore[module-import-not-at-top-of-file]
    _CLIENT,
    _CLIENT_OTHER,
    _CLIENT_UNSIGNED,
    _IDENTITY_USERS,
)

SERVER_PORT = 8121

# Même canonique que ``tests/conformance/conftest.py`` : ``validate_id_token``
# des tests compare ``iss`` à cette valeur et les redirect_uris des clients
# seed pointent vers des hôtes externes (jamais suivis par le harness).
ISSUER = "https://id.example"

# 188 scénarios contre un vrai serveur : le rejeu in-process prend déjà
# ~14 min, HTTP réel en ajoute — le garde-fou ne doit pas tronquer un rejeu sain.
_DEADLINE = 2400


def _users_seed() -> dict[str, dict[str, object]]:
    """Reprend ``[settings.users_seed.*]`` du ``config.toml`` racine.

    Les tests in-process construisent ``Settings(...)`` sans passer
    ``users_seed`` : les profils de claims de ``/userinfo`` proviennent alors
    du ``config.toml`` du répertoire courant. Le serveur du smoke, lui, lit
    exclusivement son fichier généré — d'où cette reprise explicite.
    """
    settings = tomllib.loads((REPO_ROOT / "config.toml").read_text(encoding="utf-8"))["settings"]
    seed = settings["users_seed"]
    assert isinstance(seed, dict), "users_seed absent du config.toml racine"
    return seed


def main() -> int:
    """Lance le serveur puis le rejeu complet ; renvoie le code retour de pytest."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(_CLIENT, _CLIENT_OTHER, _CLIENT_UNSIGNED),
            users=_IDENTITY_USERS,
            users_seed=_users_seed(),
            issuer=ISSUER,
            extra_settings={"require_login": True},
        ) as server_url,
    ):
        print(f"\nRejeu conformance contre {server_url} (deadline={_DEADLINE}s)...")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("PURIDENTITYSERVER_")
        }
        env["PURIDENTITYSERVER_CONFORMANCE_URL"] = server_url
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-m",
                "conformance",
                "tests/conformance",
                "--no-cov",
                "-p",
                "no:cacheprovider",
            ],
            cwd=REPO_ROOT,
            env=env,
            check=False,
        )
        elapsed = time.monotonic() - started_at
        if completed.returncode == 0:
            print(f"=== REJEU OK contre le serveur réel en {elapsed:.1f}s ===")
        else:
            print(f"=== REJEU EN ÉCHEC ({completed.returncode}) après {elapsed:.1f}s ===")
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
