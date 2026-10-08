"""Fixtures des tests de rejeu de la certification OIDC (marker ``conformance``).

Les tests sont exclus du gate (``-m "not conformance"`` dans ``addopts``) et
ne s'exécutent qu'à la demande : ``uv run --no-sync --no-build --locked python
-m pytest -m conformance --no-cov -p no:cacheprovider`` (sans ``-q`` : le
résumé ``N passed, M deselected`` prouve que le rejeu a eu lieu).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from ciba_harness import CibaHarness
from fapi_harness import FAPI_CLIENT_2_SEED, FAPI_CLIENT_SEED, FapiHarness
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

# Second client confiant : ``oidcc-refresh-token`` rejoue le check
# ``CheckErrorFromTokenEndpointResponseErrorInvalidGrant`` (2ᵉ client qui
# présente le refresh token d'un autre client) — la suite utilise un second
# client enregistré dynamiquement.
_CLIENT_OTHER = {
    "client_id": "mobile-app",
    "client_secret": "mobile-secret",
    "redirect_uris": ["https://mobile.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

# Client inscrit avec ``id_token_signed_response_alg=none`` : la suite
# ``oidcc-idtoken-unsigned`` l'enregistre dynamiquement
# (``AddIdTokenSigningAlgNoneToDynamicRegistrationRequest``).
_CLIENT_UNSIGNED = {
    "client_id": "unsigned-app",
    "client_secret": "unsigned-secret",
    "redirect_uris": ["https://unsigned.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
    "id_token_signed_response_alg": "none",
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

    Les flags ``registration_*``, ``ciba_*`` et ``protected_resource_enabled``
    reprennent ``certification/config.render.toml`` : les modules
    ``fapi-ciba-id1*`` s'enregistrent par DCR sans access token initial,
    appellent ``/bc-authorize`` puis interrogent la ressource protégée.
    ``jwks_algorithms`` ajoute ``PS256`` (l'OP de certification publie tous
    les algorithmes) : la suite enregistre ``id_token_signed_response_alg=
    PS256`` et exige ``FAPIValidateIdTokenSigningAlg`` (FAPI-RW-8.6).
    Les deux clients FAPI (issue #110) portent des clés statiques lues par
    ``fapi_harness`` ; ``par_ttl_seconds`` descend à 30 s pour borner le
    sommeil du module ``PARAttemptToUseExpiredRequestUri``.
    """
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256", "PS256"),
            clients_seed=(
                _CLIENT,
                _CLIENT_OTHER,
                _CLIENT_UNSIGNED,
                FAPI_CLIENT_SEED,
                FAPI_CLIENT_2_SEED,
            ),
            require_login=True,
            identity_seed_users=_IDENTITY_USERS,
            registration_enabled=True,
            registration_initial_access_token_mode="disabled",
            ciba_enabled=True,
            ciba_approval_enabled=True,
            protected_resource_enabled=True,
            par_ttl_seconds=30,
        )
    )


@pytest.fixture
def harness() -> Iterator[ConformanceHarness]:
    """Harness RP d'un test : ``/authorize`` → login/consent auto → callback."""
    with ConformanceHarness(build_app()) as instance:
        yield instance


@pytest.fixture
def ciba_harness() -> Iterator[CibaHarness]:
    """Harness CIBA d'un test : DCR, JAR, ``/bc-authorize``, ``/token``.

    Module ``fapi-ciba-id1*`` (issue #109) : chaque test s'enregistre ses
    clients éphémères via ``register`` et rejoue le flux ``poll`` contre
    l'application locale (ou l'OP distant via ``PURIDENTITYSERVER_
    CONFORMANCE_URL``).
    """
    with CibaHarness(build_app()) as instance:
        yield instance


@pytest.fixture
def fapi_harness() -> Iterator[FapiHarness]:
    """Harness FAPI 1.0 Advanced (issue #110) : clients seedés à clés statiques.

    Chaque test rejoue un module du plan ``fapi1-advanced-final-test-plan``
    contre l'application locale (ou l'OP distant via
    ``PURIDENTITYSERVER_CONFORMANCE_URL``) : JAR ``PS256``, variante
    ``by_value``/``pushed``, ``private_key_jwt``.
    """
    with FapiHarness(build_app()) as instance:
        yield instance


@pytest.fixture
def unsigned_harness() -> Iterator[ConformanceHarness]:
    """Harness d'un client ``id_token_signed_response_alg=none``.

    Module ``oidcc-idtoken-unsigned`` : ``AddIdTokenSigningAlgNoneToDynamicRegistrationRequest``
    attend ce client seed pour rejouer le check signature.
    """
    with ConformanceHarness(
        build_app(),
        client_id=_CLIENT_UNSIGNED["client_id"],
        client_secret=_CLIENT_UNSIGNED["client_secret"],
        redirect_uri=_CLIENT_UNSIGNED["redirect_uris"][0],
    ) as instance:
        yield instance


@dataclass
class RequestDocumentServer:
    """Serveur local qui héberge le document JWT d'un ``request_uri``.

    La suite de certification joue ce rôle côté RP
    (``AbstractOIDCCRequestUriServerTest.handleRequestUriRequest``) en
    ``Content-Type: application/jwt`` — ici, sur un port libre de la machine,
    l'OP local le lisant en ``http://127.0.0.1:<port>/…``.
    """

    url: str = ""
    document: str = ""
    paths: list[str] = field(default_factory=list)


@pytest.fixture
def request_document_server() -> Iterator[RequestDocumentServer]:
    """Démarre le serveur de documents ``request_uri`` pour un test."""
    state = RequestDocumentServer()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Répond avec le document courant et enregistre le chemin appelé."""
            state.paths.append(self.path)
            body = state.document.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/jwt")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            """Silence le serveur de test."""
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
