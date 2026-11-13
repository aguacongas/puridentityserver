"""Tests du fetcher de status list (draft-ietf-oauth-status-list, issue #224)."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from puridentityserver.infrastructure.status_list import StatusListFetcher

_STATUS_LIST = b"header.payload.signature"


class _StatusListHandler(BaseHTTPRequestHandler):
    """Sert ``body`` avec ``content_type`` sur chaque GET (test local)."""

    body = _STATUS_LIST
    content_type = "application/statuslist+jwt"

    def do_GET(self) -> None:
        """Répond 200 avec le corps et le media type configurés en classe."""
        self.send_response(200)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: object) -> None:
        """Supprime le journal stderr du serveur de test."""


class _RedirectHandler(BaseHTTPRequestHandler):
    """Répond 302 vers une autre URL : la redirection ne doit pas être suivie."""

    def do_GET(self) -> None:
        """Répond une redirection permanente vers un chemin inconnu."""
        self.send_response(302)
        self.send_header("Location", "/ailleurs")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        """Supprime le journal stderr du serveur de test."""


@pytest.fixture
def serve_status_list() -> Iterator[Callable[[type[BaseHTTPRequestHandler]], str]]:
    """Démarre un serveur local pour ``handler`` et rend l'URL de la status list."""
    servers: list[ThreadingHTTPServer] = []

    def start(handler: type[BaseHTTPRequestHandler]) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/statuslists/1"

    try:
        yield start
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def test_status_list_is_fetched_from_local_provider(
    serve_status_list: Callable[[type[BaseHTTPRequestHandler]], str],
) -> None:
    """Le fetch retourne le corps servi, destinations locales ouvertes."""
    url = serve_status_list(_StatusListHandler)

    token = StatusListFetcher(allow_local_targets=True).fetch(url)

    assert token == _STATUS_LIST.decode("ascii")


def test_unexpected_content_type_is_refused(
    serve_status_list: Callable[[type[BaseHTTPRequestHandler]], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un media type autre que ``application/statuslist+jwt`` est refusé."""
    monkeypatch.setattr(_StatusListHandler, "content_type", "text/html")
    url = serve_status_list(_StatusListHandler)

    token = StatusListFetcher(allow_local_targets=True).fetch(url)

    assert token is None


def test_oversized_token_is_refused(
    serve_status_list: Callable[[type[BaseHTTPRequestHandler]], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un corps au-delà de la taille maximale est refusé."""
    monkeypatch.setattr(_StatusListHandler, "body", b"x" * 70_000)
    url = serve_status_list(_StatusListHandler)

    token = StatusListFetcher(allow_local_targets=True).fetch(url)

    assert token is None


def test_redirection_is_not_followed(
    serve_status_list: Callable[[type[BaseHTTPRequestHandler]], str],
) -> None:
    """Le fetch n'a aucun suivi de redirection : le 302 est un échec."""
    url = serve_status_list(_RedirectHandler)

    token = StatusListFetcher(allow_local_targets=True).fetch(url)

    assert token is None


def test_local_target_is_refused_when_not_allowed() -> None:
    """Sans ``allow_local_targets``, une destination loopback est refusée."""
    assert StatusListFetcher().fetch("http://127.0.0.1:9/statuslists/1") is None


def test_private_address_is_refused_when_not_allowed() -> None:
    """Sans ``allow_local_targets``, une adresse réseau privée est refusée."""
    assert StatusListFetcher().fetch("http://10.0.0.5/statuslists/1") is None


def test_unresolvable_host_is_refused_when_not_allowed() -> None:
    """Un hôte non résolvable n'est jamais une destination publique."""
    assert StatusListFetcher().fetch("http://nexistant.invalid/statuslists/1") is None


def test_non_http_scheme_is_refused() -> None:
    """Seuls les schémas ``http``/``https`` sont acceptés."""
    fetcher = StatusListFetcher(allow_local_targets=True)

    assert fetcher.fetch("file:///etc/passwd") is None


def test_credentials_in_uri_are_refused() -> None:
    """Une URI portant des identifiants ``user:pass@`` est refusée."""
    fetcher = StatusListFetcher(allow_local_targets=True)

    assert fetcher.fetch("http://user:pass@127.0.0.1:9/statuslists/1") is None


def test_unreachable_provider_returns_none() -> None:
    """Un échec de connexion (refus, timeout) est traduit en ``None``."""
    fetcher = StatusListFetcher(allow_local_targets=True)

    assert fetcher.fetch("http://127.0.0.1:9/statuslists/1") is None
