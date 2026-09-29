"""Fixtures des tests de rejeu de la certification OIDC (marker ``conformance``).

Les tests sont exclus du gate (``-m "not conformance"`` dans ``addopts``) et
ne s'exécutent qu'à la demande : ``uv run --no-sync --no-build --locked python
-m pytest -m conformance --no-cov -p no:cacheprovider`` (sans ``-q`` : le
résumé ``N passed, M deselected`` prouve que le rejeu a eu lieu).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from harness import ConformanceHarness

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_CLIENT = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

# Comptes de ``certification/config.render.toml`` (instances de certification
# et local partagent les mêmes identifiants pilotes).
_IDENTITY_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}


def build_app() -> FastAPI:
    """Monte l'application aux seeds alignés sur la config de certification.

    ``require_login = true`` (OIDC Core 1.0 §3.1.2.1) : la demande non
    authentifiée part vers ``/login``, ce qui est le prérequis des checks
    ``prompt=login`` et ``max_age`` — sans lui le code est émis avec un
    ``sub`` vide et le rejeu perd son sens.
    """
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT,),
            require_login=True,
            identity_seed_users=_IDENTITY_USERS,
        )
    )


@pytest.fixture
def harness() -> Iterator[ConformanceHarness]:
    """Harness RP d'un test : ``/authorize`` → login/consent auto → callback."""
    with ConformanceHarness(build_app()) as instance:
        yield instance
