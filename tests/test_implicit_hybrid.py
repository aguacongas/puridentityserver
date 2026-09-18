"""Tests des flows Implicit et Hybrid (OIDC Core 1.0 §3.2, §3.3).

Couvre les sept ``response_type``, l'encodage de la réponse dans le
*fragment* dès qu'un jeton est retourné, l'obligation du ``nonce`` et les
liens ``at_hash`` / ``c_hash`` entre id_token, access token et code.
"""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import (
    AuthorizeConfig,
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.domain.authorization import Client, ClientType, ResponseMode, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_REDIRECT_URI = "https://spa.example/cb"

_CLIENT = Client(
    client_id="spa",
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.PUBLIC,
)

_CLIENT_JSON = {
    "client_id": "spa",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid",
    "client_type": "public",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests unitaires du use case)."""
    return asyncio.run(awaitable)


def _make_usecase() -> tuple[AuthorizeUseCase, InMemoryAuthorizationCodeRepository]:
    """Construit un AuthorizeUseCase avec des repos mémoire et de vrais jetons."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
    run(clients.save(_CLIENT))
    usecase = AuthorizeUseCase(
        AuthorizeConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        codes,
        PyJWTTokenManager(key_manager),
    )
    return usecase, codes


def _request(
    response_type: str,
    *,
    nonce: str = "",
    state: str = "",
    scope: str = "openid",
    response_mode: str = "",
) -> AuthorizeRequest:
    """Construit une demande d'autorisation valide pour le client ``spa``."""
    return AuthorizeRequest(
        response_type=response_type,
        client_id=_CLIENT.client_id,
        redirect_uri=_REDIRECT_URI,
        scope=scope,
        subject="user-1",
        state=state,
        nonce=nonce,
        response_mode=response_mode,
    )


def _decode(token: str) -> dict[str, object]:
    """Décode un id_token sans vérifier la signature (claims à contrôler)."""
    return jwt.decode(token, options={"verify_signature": False})


def _at_hash(value: str) -> str:
    """Re-calcule l'empreinte attendue (SHA-256, moitié gauche, base64url)."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def _fragment_params(location: str) -> dict[str, list[str]]:
    """Paramètres portés par le fragment d'une URL de redirection."""
    return parse_qs(urlparse(location).fragment)


def _app(**settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT_JSON,),
            **settings,
        )
    )


# ---------------------------------------------------------------------------
# Implicit flow (OIDC Core 1.0 §3.2)
# ---------------------------------------------------------------------------


def test_implicit_id_token_returned_in_fragment() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("id_token", nonce="n-abc")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    assert result.code == ""
    assert result.access_token == ""
    fragment = _fragment_params(result.redirect_uri)
    assert fragment["id_token"] == [result.id_token]
    assert "code" not in fragment
    claims = _decode(result.id_token)
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == "user-1"
    assert claims["aud"] == "spa"
    assert claims["nonce"] == "n-abc"
    assert "at_hash" not in claims
    assert "c_hash" not in claims


def test_implicit_requires_nonce() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("id_token")))

    assert isinstance(result, AuthorizeError)
    assert result.error == "invalid_request"
    assert result.response_mode is ResponseMode.FRAGMENT


def test_implicit_token_only_returns_access_token() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("token", state="st-1")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    assert result.id_token == ""
    fragment = _fragment_params(result.redirect_uri)
    assert fragment["access_token"] == [result.access_token]
    assert fragment["token_type"] == ["Bearer"]
    assert fragment["expires_in"]
    assert fragment["scope"] == ["openid"]
    assert fragment["state"] == ["st-1"]
    assert "id_token" not in fragment
    assert "code" not in fragment


def test_implicit_id_token_token_includes_at_hash() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("id_token token", nonce="n-abc", state="st-1")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    fragment = _fragment_params(result.redirect_uri)
    access_token = fragment["access_token"][0]
    assert fragment["id_token"]
    claims = _decode(fragment["id_token"][0])
    assert claims["nonce"] == "n-abc"
    assert claims["at_hash"] == _at_hash(access_token)
    assert "c_hash" not in claims
    assert "code" not in fragment


# ---------------------------------------------------------------------------
# Hybrid flow (OIDC Core 1.0 §3.3)
# ---------------------------------------------------------------------------


def test_hybrid_code_id_token_includes_c_hash() -> None:
    usecase, codes = _make_usecase()
    result = run(usecase.execute(_request("code id_token", nonce="n-abc")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    fragment = _fragment_params(result.redirect_uri)
    code = fragment["code"][0]
    assert result.code == code
    claims = _decode(fragment["id_token"][0])
    assert claims["c_hash"] == _at_hash(code)
    assert "at_hash" not in claims
    assert run(codes.find_by_code(code)) is not None


def test_hybrid_code_token_returns_code_and_access_token() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("code token")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    fragment = _fragment_params(result.redirect_uri)
    assert fragment["code"]
    assert fragment["access_token"]
    assert "id_token" not in fragment


def test_hybrid_all_three_artefacts_linked() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("code id_token token", nonce="n-abc")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    fragment = _fragment_params(result.redirect_uri)
    claims = _decode(fragment["id_token"][0])
    assert claims["at_hash"] == _at_hash(fragment["access_token"][0])
    assert claims["c_hash"] == _at_hash(fragment["code"][0])


# ---------------------------------------------------------------------------
# Modes de réponse et encodage des erreurs
# ---------------------------------------------------------------------------


def test_default_mode_is_query_for_code_flow() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("code")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.QUERY
    assert urlparse(result.redirect_uri).query
    assert urlparse(result.redirect_uri).fragment == ""


def test_query_response_mode_rejected_with_tokens() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("id_token", nonce="n-abc", response_mode="query")))

    assert isinstance(result, AuthorizeError)
    assert result.error == "invalid_request"
    assert result.response_mode is ResponseMode.FRAGMENT


def test_explicit_fragment_mode_applies_to_code_flow() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("code", response_mode="fragment")))

    assert isinstance(result, AuthorizeRedirect)
    assert result.response_mode is ResponseMode.FRAGMENT
    fragment = _fragment_params(result.redirect_uri)
    assert fragment["code"]
    assert urlparse(result.redirect_uri).query == ""


def test_implicit_error_encoded_in_fragment() -> None:
    usecase, _ = _make_usecase()
    result = run(usecase.execute(_request("id_token", state="st-1", scope="profile")))

    assert isinstance(result, AuthorizeError)
    assert result.error == "invalid_scope"
    assert result.response_mode is ResponseMode.FRAGMENT
    assert result.state == "st-1"
    assert result.redirect_uri == _REDIRECT_URI


# ---------------------------------------------------------------------------
# Intégration HTTP
# ---------------------------------------------------------------------------


def test_authorize_implicit_http_returns_tokens_in_fragment() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "id_token token",
                "client_id": "spa",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid",
                "state": "st-1",
                "nonce": "n-http",
            },
            follow_redirects=False,
        )
        jwks = client.get("/.well-known/jwks.json")

    assert response.status_code == 302
    location = response.headers["location"]
    assert urlparse(location).query == ""
    fragment = _fragment_params(location)
    assert fragment["access_token"]
    assert fragment["id_token"]
    assert fragment["token_type"] == ["Bearer"]
    assert fragment["state"] == ["st-1"]

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks.json()["keys"][0])
    claims = jwt.decode(
        fragment["id_token"][0],
        public_key,
        algorithms=["RS256"],
        audience="spa",
        issuer=_ISSUER,
    )
    assert claims["nonce"] == "n-http"
    assert claims["at_hash"] == _at_hash(fragment["access_token"][0])


def test_authorize_hybrid_code_exchange_succeeds() -> None:
    verifier = "verifier-verifier"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code id_token",
                "client_id": "spa",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid",
                "nonce": "n-hybrid",
                "code_challenge": challenge,
            },
            follow_redirects=False,
        )
        fragment = _fragment_params(auth.headers["location"])
        assert fragment["code"]
        assert fragment["id_token"]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": fragment["code"][0],
                "redirect_uri": _REDIRECT_URI,
                "client_id": "spa",
                "code_verifier": verifier,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["id_token"]
    assert payload["access_token"]


def test_authorize_implicit_error_http_goes_to_fragment() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "id_token",
                "client_id": "spa",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid",
                "state": "st-err",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert urlparse(location).query == ""
    fragment = _fragment_params(location)
    assert fragment["error"] == ["invalid_request"]
    assert fragment["state"] == ["st-err"]


def test_authorize_query_mode_with_tokens_rejected_http() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "id_token",
                "client_id": "spa",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid",
                "nonce": "n",
                "response_mode": "query",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert urlparse(location).query == ""
    assert _fragment_params(location)["error"] == ["invalid_request"]
