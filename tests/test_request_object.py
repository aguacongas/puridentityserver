"""Tests des request objects (RFC 9101) et de l'id_token non signé (JWA §6).

Couvre le resolver (priorité des claims, refus, ``request_uri`` poussé),
le fetcher du document (destinations filtrées, type MIME, redirections) et
l'observabilité HTTP de ``/authorize`` : pages d'erreur 400 et émission d'un
code pour une demande portée par un request object.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.request_object import (
    RequestObjectConfig,
    RequestObjectError,
    RequestObjectResolver,
    is_pushed_request_uri,
)
from puridentityserver.infrastructure.request_object import (
    HTTPRequestObjectFetcher,
    loopback_bind,
)
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
_UNSIGNED_CLIENT = {
    **_CLIENT,
    "client_id": "unsigned-app",
    "id_token_signed_response_alg": "none",
}


@dataclass
class _DocumentState:
    """État partagé du serveur local de documents ``request_uri``."""

    paths: list[str] = field(default_factory=list)
    document: str = ""
    status: int = 200
    content_type: str = "application/jwt"
    location: str = ""


class _StubFetcher:
    """Port ``RequestObjectFetcher`` de test : renvoie un document fixe."""

    def __init__(self, document: str | None) -> None:
        """Prépare la réponse du fetch et enregistre les URL appelées."""
        self.document = document
        self.urls: list[str] = []

    async def fetch(self, url: str) -> str | None:
        """Retourne le document prédéfini en mémorisant l'URL demandée."""
        self.urls.append(url)
        return self.document


def _segment(value: object) -> str:
    """Encode un objet JSON en segment base64url non padding (RFC 7515 §2)."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _request_object(claims: dict[str, object], header: object = None) -> str:
    """Construit un JWT compact non signé (``header.payload.``)."""
    head = {"alg": "none"} if header is None else header
    return f"{_segment(head)}.{_segment(claims)}."


def _resolver(document: str | None) -> tuple[RequestObjectResolver, _StubFetcher]:
    """Resolver de test monté sur un fetcher factice."""
    fetcher = _StubFetcher(document)
    return RequestObjectResolver(RequestObjectConfig(), fetcher), fetcher


def _base_params(**extra: str) -> dict[str, str]:
    """Paramètres d'une demande ``response_type=code`` de référence."""
    params = {
        "response_type": "code",
        "client_id": "web-app",
        "redirect_uri": "https://app.example/callback",
        "scope": "openid profile",
        "state": "state-1",
        "nonce": "nonce-1",
    }
    params.update(extra)
    return params


def run(resolver: RequestObjectResolver, **params: str) -> object:
    """Exécute ``resolve`` sur des paramètres donnés."""
    return asyncio.run(resolver.resolve(params))


def _app() -> FastAPI:
    """Application de test alignée sur la configuration des tests d'autorisation."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT, _UNSIGNED_CLIENT),
        )
    )


def _s256_challenge(verifier: str) -> str:
    """Défi PKCE S256 d'un ``code_verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# Resolver : priorité des claims et refus
# --------------------------------------------------------------------------- #


def test_resolve_without_request_object_returns_params_unchanged() -> None:
    resolver, fetcher = _resolver(None)
    params = _base_params()

    resolved = run(resolver, **params)

    assert resolved == params
    assert fetcher.urls == []


def test_request_object_claims_take_precedence_over_query() -> None:
    """Les claims du jeton priment sur la query (OIDC Core 1.0 §6.1).

    C'est le cœur du module ``oidcc-ensure-request-object-with-redirect-uri`` :
    la ``redirect_uri`` du jeton reste valide alors que la query en porte une
    non enregistrée.
    """
    resolver, _fetcher = _resolver(None)
    claims = _base_params(
        redirect_uri="https://app.example/callback",
        state="state-from-jwt",
        nonce="nonce-from-jwt",
    )

    resolved = run(
        resolver,
        **_base_params(redirect_uri="https://app.example/callback_invalid"),
        request=_request_object(claims),
    )

    assert isinstance(resolved, dict)
    assert resolved["redirect_uri"] == "https://app.example/callback"
    assert resolved["state"] == "state-from-jwt"
    assert resolved["nonce"] == "nonce-from-jwt"
    assert "request" not in resolved


def test_request_and_request_uri_are_exclusive() -> None:
    resolver, fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params()),
        request_uri="https://rp.example/requesturi/abc",
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request"
    assert fetcher.urls == []


def test_missing_alg_header_is_accepted_as_unsigned() -> None:
    """Un en-tête sans ``alg`` est un JWT non signé (aucune clé n'y figure)."""
    resolver, _fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params(nonce="nonce-without-alg"), header={}),
    )

    assert isinstance(resolved, dict)
    assert resolved["nonce"] == "nonce-without-alg"


def test_signed_request_object_is_refused() -> None:
    resolver, _fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params(), header={"alg": "RS256"}),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


@pytest.mark.parametrize(
    "document",
    [
        "no-segment-here",
        "only.upto",
        "header.payload.signature",
        "not-base64!.payload.",
        "e30.notjson.",
    ],
    ids=[
        "sans-point",
        "deux-segments-incomplets",
        "signe",
        "en-tete-illisible",
        "claims-illisible",
    ],
)
def test_malformed_request_object_is_refused(document: str) -> None:
    resolver, _fetcher = _resolver(None)

    resolved = run(resolver, **_base_params(), request=document)

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_non_string_claims_are_stringified() -> None:
    """Les claims booléens/nombres/objets passent en paramètres d'URL."""
    resolver, _fetcher = _resolver(None)
    claims: dict[str, object] = {
        **_base_params(),
        "max_age": 86400,
        "prompt": True,
        "claims": {"userinfo": {"name": True}},
    }

    resolved = run(resolver, **_base_params(), request=_request_object(claims))

    assert isinstance(resolved, dict)
    assert resolved["max_age"] == "86400"
    assert resolved["prompt"] == "true"
    assert resolved["claims"] == '{"userinfo":{"name":true}}'


def test_embedded_params_are_never_taken_from_claims() -> None:
    """``request``/``request_uri`` du jeton sont ignorés (RFC 9101 §5)."""
    resolver, fetcher = _resolver(None)
    claims = {**_base_params(), "request_uri": "https://evil.example/x"}

    resolved = run(resolver, **_base_params(), request=_request_object(claims))

    assert isinstance(resolved, dict)
    assert "request_uri" not in resolved
    assert fetcher.urls == []


def test_document_is_fetched_by_reference() -> None:
    resolver, fetcher = _resolver(_request_object(_base_params(nonce="nonce-from-url")))

    resolved = run(resolver, **_base_params(), request_uri="https://rp.example/requesturi/abc")

    assert isinstance(resolved, dict)
    assert resolved["nonce"] == "nonce-from-url"
    assert fetcher.urls == ["https://rp.example/requesturi/abc"]


def test_unreachable_request_uri_returns_invalid_request_uri() -> None:
    resolver, fetcher = _resolver(None)

    resolved = run(resolver, **_base_params(), request_uri="https://rp.example/requesturi/abc")

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_uri"
    assert fetcher.urls == ["https://rp.example/requesturi/abc"]


def test_pushed_request_uri_is_left_to_par() -> None:
    """L'URN opaque de PAR n'est jamais lu sur le réseau (RFC 9126 §6.2)."""
    resolver, fetcher = _resolver(_request_object(_base_params()))
    params = _base_params(request_uri="urn:ietf:params:oauth:request_uri:reference")

    resolved = run(resolver, **params)

    assert resolved == params
    assert fetcher.urls == []


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("urn:ietf:params:oauth:request_uri:abc", True),
        ("https://rp.example/requesturi/abc", False),
        ("", False),
    ],
)
def test_is_pushed_request_uri(reference: str, expected: bool) -> None:
    assert is_pushed_request_uri(reference) is expected


# --------------------------------------------------------------------------- #
# Fetcher : lecture et filtrage du document
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("192.168.1.10", False),
        ("id.example", False),
        ("", False),
    ],
)
def test_loopback_bind_detects_local_listen_addresses(host: str, expected: bool) -> None:
    assert loopback_bind(host) is expected


def test_local_target_is_refused_when_not_allowed() -> None:
    fetcher = HTTPRequestObjectFetcher()

    assert _fetch(fetcher, "http://127.0.0.1:9/document") is None


def test_non_http_scheme_is_refused() -> None:
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, "file:///etc/passwd") is None


def test_credentials_in_uri_are_refused() -> None:
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, "http://user:pass@127.0.0.1:9/document") is None


def _fetch(fetcher: HTTPRequestObjectFetcher, url: str) -> str | None:
    """Exécute ``fetch`` en dehors de toute boucle d'événements."""
    return asyncio.run(fetcher.fetch(url))


@pytest.fixture
def document_server() -> Iterator[tuple[str, _DocumentState]]:
    """Serveur HTTP local servable comme ``request_uri`` des tests."""
    state = _DocumentState(document=_request_object(_base_params()))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Répond selon l'état courant du serveur de test."""
            state.paths.append(self.path)
            if state.location:
                self.send_response(302)
                self.send_header("Location", state.location)
                self.end_headers()
                return
            body = state.document.encode("utf-8")
            self.send_response(state.status)
            self.send_header("Content-Type", state.content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            """Silence le serveur de test."""
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fetch_reads_local_document_and_ignores_fragment(
    document_server: tuple[str, _DocumentState],
) -> None:
    url, state = document_server
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    document = _fetch(fetcher, f"{url}/requesturi/abc#empreinte-du-document")

    assert document == state.document
    assert state.paths == ["/requesturi/abc"]


def test_fetch_refuses_wrong_content_type(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.content_type = "text/plain"
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/document") is None


def test_fetch_does_not_follow_redirect(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.location = f"{url}/document"
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/start") is None
    assert state.paths == ["/start"]


def test_fetch_refuses_oversized_document(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.document = "a" * (64 * 1024 + 1)
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/document") is None


# --------------------------------------------------------------------------- #
# /authorize : observabilité HTTP
# --------------------------------------------------------------------------- #


def test_authorize_accepts_request_object_and_issues_code() -> None:
    """Le module ``oidcc-unsigned-request-object-…`` : flux happy en ``request``."""
    claims = _base_params(
        code_challenge=_s256_challenge("verifier-verifier"),
        code_challenge_method="S256",
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request": _request_object(claims),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["code"]
    assert query["state"] == ["state-1"]


def test_authorize_redirect_uri_of_request_object_takes_precedence() -> None:
    """``oidcc-ensure-request-object-with-redirect-uri`` : la query porte une URI fausse."""
    claims = _base_params(
        redirect_uri="https://app.example/callback",
        code_challenge=_s256_challenge("verifier-verifier"),
        code_challenge_method="S256",
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback_invalid",
                "scope": "openid profile",
                "state": "state-1",
                "request": _request_object(claims),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://app.example/callback?")


def test_authorize_shows_error_page_for_invalid_request_object() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={"request": "pas-un-jwt", "client_id": "web-app"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request_object" in response.text
    assert "location" not in response.headers


def test_authorize_shows_error_page_for_exclusive_parameters() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": _request_object(_base_params()),
                "request_uri": "https://rp.example/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request" in response.text


def test_authorize_shows_error_page_for_unreachable_request_uri() -> None:
    """Aucune redirection : la ``redirect_uri`` de transport n'est pas vérifiable."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={"request_uri": "http://127.0.0.1:9/document", "client_id": "web-app"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request_uri" in response.text


def test_authorize_fetches_request_uri_document(
    document_server: tuple[str, _DocumentState],
) -> None:
    """``oidcc-request-uri-unsigned-…`` : le document est lu sur le réseau."""
    url, state = document_server
    state.document = _request_object(
        _base_params(
            code_challenge=_s256_challenge("verifier-verifier"),
            code_challenge_method="S256",
        )
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request_uri": f"{url}/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert state.paths == ["/requesturi/abc"]


def test_authorize_issues_code_then_unsigned_id_token_for_none_client() -> None:
    """``oidcc-idtoken-unsigned`` : ``id_token_signed_response_alg=none``."""
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "unsigned-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "nonce": "nonce-unsigned",
            },
            follow_redirects=False,
        )
        code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "unsigned-app",
                "client_secret": "super-secret",
            },
        )

    payload = response.json()
    assert response.status_code == 200
    header, claims, signature = payload["id_token"].split(".")
    assert json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["alg"] == "none"
    assert signature == ""
    decoded = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    assert decoded["nonce"] == "nonce-unsigned"
    assert "at_hash" not in decoded
