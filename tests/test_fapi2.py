"""Tests du profil FAPI 2.0 Security Profile (issue #111, ``fapi2_enabled``).

Couvre les écarts F2-1 (``iss`` RFC 9207 au callback), F2-2 (PKCE ``S256``
au push, ``plain`` refusé), F2-3 (PAR imposé : demande directe refusée),
le flow ``code`` seul (FAPI2-SP-5.3.2.2-2) et le nonce optionnel, plus
l'exclusivité des drapeaux ``fapi_enabled``/``fapi2_enabled`` au chargement
de la configuration.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRequest,
    ValidatedAuthorization,
    validate_authorization_request,
)
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_ID = "fapi2-app"
_CLIENT_SECRET = "fapi2-super-secret"
_REDIRECT_URI = "https://fapi2.example/callback"
_VERIFIER = "verifier-verifier"

_SEED: dict[str, object] = {
    "client_id": _CLIENT_ID,
    "client_secret": _CLIENT_SECRET,
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "confidential",
    "fapi2_enabled": True,
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine en synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _s256(verifier: str) -> str:
    """Empreinte S256 d'un code verifier PKCE (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _app(**settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_SEED,),
            **settings,
        )
    )


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query)


def _push(client: TestClient, **params: str) -> httpx.Response:
    data = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
    }
    data.update(params)
    return client.post("/par", data=data)


def _fapi2_client() -> Client:
    return Client(
        client_id=_CLIENT_ID,
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        client_type=ClientType.CONFIDENTIAL,
        client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
        fapi2_enabled=True,
    )


def _repository() -> InMemoryClientRepository:
    repository = InMemoryClientRepository()
    run(repository.save(_fapi2_client()))
    return repository


def _request(**overrides: str) -> AuthorizeRequest:
    values: dict[str, object] = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "state-1",
        "code_challenge": _s256(_VERIFIER),
        "code_challenge_method": "S256",
    }
    values.update(overrides)
    return AuthorizeRequest(**values)  # type: ignore[arg-type]


def _validate(request: AuthorizeRequest) -> ValidatedAuthorization | AuthorizeError:
    return run(validate_authorization_request(request, _repository()))


def test_seed_fapi2_enabled_is_parsed() -> None:
    """Le drapeau ``fapi2_enabled`` du seed active le profil (composition)."""
    settings = Settings(issuer=_ISSUER, base_url=_ISSUER, clients_seed=(_SEED,))

    parsed = {client.client_id: client for client in settings.seed_clients}

    assert parsed[_CLIENT_ID].fapi2_enabled is True
    assert parsed[_CLIENT_ID].fapi_enabled is False


def test_fapi_flags_are_mutually_exclusive() -> None:
    """``fapi_enabled`` et ``fapi2_enabled`` sont exclusifs au chargement."""
    conflicting = ({**_SEED, "fapi_enabled": True},)
    settings = Settings(issuer=_ISSUER, clients_seed=conflicting)

    with pytest.raises(ValueError, match="exclusifs"):
        _ = settings.seed_clients


def test_fapi2_accepts_code_flow_without_nonce() -> None:
    """FAPI2-SP-5.3.2.2-2 : flow ``code`` admis, nonce non exigé."""
    validated = _validate(_request(nonce=""))

    assert isinstance(validated, ValidatedAuthorization)
    assert validated.wants_code
    assert not validated.wants_id_token


def test_fapi2_rejects_hybrid_response_type() -> None:
    """``EnsureResponseTypeCodeFails`` (5.3.2.2-2) : ``code id_token`` refusé."""
    validated = _validate(_request(response_type="code id_token"))

    assert isinstance(validated, AuthorizeError)
    assert validated.error == "unsupported_response_type"


def test_fapi2_rejects_plain_pkce() -> None:
    """``plain`` refusé dès le validateur (FAPI2-SP-5.3.2.2-5)."""
    validated = _validate(_request(code_challenge="plain-challenge", code_challenge_method="plain"))

    assert isinstance(validated, AuthorizeError)
    assert validated.error == "invalid_request"


def test_direct_authorize_is_rejected() -> None:
    """F2-3 : la demande non poussée vaut ``invalid_request`` (5.3.2.2-4)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid profile",
                "code_challenge": _s256(_VERIFIER),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_request"
    assert "Pushed Authorization Request" in response.json()["detail"]["error_description"]


def test_par_requires_pkce() -> None:
    """F2-2 : ``code_challenge`` exigé au push (FAPI2-SP-5.3.2.2-5)."""
    with TestClient(_app()) as client:
        response = _push(client, scope="openid profile")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "FAPI2-SP-5.3.2.2-5" in response.json()["error_description"]


def test_par_rejects_plain_pkce() -> None:
    """F2-2 : ``plain`` refusé au push (FAPI2-SP-5.3.2.2-5)."""
    with TestClient(_app()) as client:
        response = _push(
            client,
            code_challenge="plain-challenge",
            code_challenge_method="plain",
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "S256" in response.json()["error_description"]


def test_par_accepts_pkce_s256() -> None:
    """Push happy path FAPI2 : PKCE S256 → ``request_uri``."""
    with TestClient(_app()) as client:
        response = _push(
            client,
            code_challenge=_s256(_VERIFIER),
            code_challenge_method="S256",
        )

    assert response.status_code == 201
    assert response.json()["request_uri"]


def test_par_rejects_hybrid_response_type() -> None:
    """Le push rejette ``code id_token`` comme le validateur (5.3.2.2-2)."""
    with TestClient(_app()) as client:
        response = _push(
            client,
            response_type="code id_token",
            nonce="n-1",
            code_challenge=_s256(_VERIFIER),
            code_challenge_method="S256",
        )

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_response_type"


def test_authorize_via_request_uri_carries_iss() -> None:
    """F2-1 : la réponse de succès porte ``iss`` (RFC 9207 §2.3) sans nonce."""
    with TestClient(_app()) as client:
        push = _push(
            client,
            state="st-1",
            code_challenge=_s256(_VERIFIER),
            code_challenge_method="S256",
        )
        assert push.status_code == 201
        auth = client.get(
            "/authorize",
            params={"client_id": _CLIENT_ID, "request_uri": push.json()["request_uri"]},
            follow_redirects=False,
        )

    assert auth.status_code == 302
    query = _redirect_query(auth.headers["location"])
    assert query["code"]
    assert query["state"] == ["st-1"]
    assert query["iss"] == [_ISSUER]


def test_token_endpoint_exchanges_pushed_code() -> None:
    """E2E FAPI2 : push → /authorize → échange du code avec le verifier."""
    with TestClient(_app()) as client:
        push = _push(
            client,
            code_challenge=_s256(_VERIFIER),
            code_challenge_method="S256",
        )
        assert push.status_code == 201
        auth = client.get(
            "/authorize",
            params={"client_id": _CLIENT_ID, "request_uri": push.json()["request_uri"]},
            follow_redirects=False,
        )
        assert auth.status_code == 302
        code = _redirect_query(auth.headers["location"])["code"][0]
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "code_verifier": _VERIFIER,
            },
        )

    assert token.status_code == 200
    payload = token.json()
    assert payload["access_token"]
    assert payload["token_type"] == "Bearer"
    assert payload["id_token"]
