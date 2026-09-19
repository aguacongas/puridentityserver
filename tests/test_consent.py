"""Tests de la feature Consentement OAuth (OIDC Core 1.0 §3.1.2.2).

- unitaires : ``Consent.covers``, ``ConsentUseCase`` (exigence/auto-approbation,
  fusion des scopes), round-trips des repositories mémoire et SQL ;
- intégration HTTP : ``/authorize`` redirige vers ``/consent`` pour un client
  ``require_consent``, la page rend les scopes, ``POST /consent`` autorise
  (code échangeable à ``/token``) ou refuse (``access_denied``), le consentement
  est mémorisé (auto-approbation en 2e demande, nouvel écran pour un scope
  ajouté), l'utilisateur non connecté est renvoyé vers ``/login``, et le flow
  PAR aboutit via la page (exécution directe d'``AuthorizeUseCase``).
"""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from pathlib import Path
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.domain.authorization import Client, Consent, Scope
from puridentityserver.infrastructure.persistence.memory.consents import (
    InMemoryConsentRepository,
)
from puridentityserver.infrastructure.persistence.sql.consents import SQLConsentRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_REDIRECT_URI = "https://app.example/callback"

_CONSENT_CLIENT_JSON: dict[str, object] = {
    "client_id": "app-with-consent",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile email",
    "client_type": "public",
    "require_consent": True,
}

_PLAIN_CLIENT_JSON: dict[str, object] = {
    "client_id": "app-no-consent",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid",
    "client_type": "public",
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _consent_client(require_consent: bool = True) -> Client:
    """Client public par défaut des tests unitaires (consentement activable)."""
    return Client(
        client_id="app-with-consent",
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.EMAIL}),
        require_consent=require_consent,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests unitaires : Consent.covers + ConsentUseCase
# ─────────────────────────────────────────────────────────────────────────────


def test_consent_covers_requested_scopes() -> None:
    consent = Consent(
        subject="alice",
        client_id="app",
        scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.EMAIL}),
    )
    assert consent.covers(frozenset({Scope.OPENID}))
    assert consent.covers(frozenset({Scope.OPENID, Scope.PROFILE}))
    assert not consent.covers(frozenset({Scope.OPENID, Scope.ADDRESS}))
    assert not consent.covers(frozenset({Scope.OPENID, Scope.PHONE}))


def test_consent_without_scopes_covers_nothing() -> None:
    consent = Consent(subject="alice", client_id="app")
    assert not consent.covers(frozenset({Scope.OPENID}))


def test_is_required_skips_non_consent_clients() -> None:
    usecase = ConsentUseCase(InMemoryConsentRepository())
    plain = _consent_client(require_consent=False)
    assert run(usecase.is_required(plain, "alice", frozenset({Scope.OPENID}))) is False
    assert run(usecase.is_required(plain, "alice", frozenset())) is False


def test_is_required_reflects_granted_scopes() -> None:
    usecase = ConsentUseCase(InMemoryConsentRepository())
    client = _consent_client()
    run(usecase.grant("alice", client.client_id, frozenset({Scope.OPENID, Scope.PROFILE})))

    assert run(usecase.is_required(client, "alice", frozenset({Scope.OPENID}))) is False
    assert (
        run(usecase.is_required(client, "alice", frozenset({Scope.OPENID, Scope.PROFILE}))) is False
    )
    assert run(usecase.is_required(client, "alice", frozenset({Scope.OPENID, Scope.EMAIL}))) is True
    assert run(usecase.is_required(client, "bob", frozenset({Scope.OPENID}))) is True


def test_grant_unions_scopes_across_approvals() -> None:
    repository = InMemoryConsentRepository()
    usecase = ConsentUseCase(repository)
    client = _consent_client()
    run(usecase.grant("alice", client.client_id, frozenset({Scope.OPENID, Scope.PROFILE})))
    run(usecase.grant("alice", client.client_id, frozenset({Scope.OPENID, Scope.EMAIL})))

    stored = run(repository.find("alice", client.client_id))
    assert stored is not None
    assert stored.scopes == frozenset({Scope.OPENID, Scope.PROFILE, Scope.EMAIL})
    assert run(usecase.is_required(client, "alice", _scope_set("openid profile email"))) is False


def _scope_set(space_separated: str) -> frozenset[Scope]:
    """Décode des scopes séparés par des espaces (helper de test)."""
    return Scope.from_space_separated(space_separated)


# ─────────────────────────────────────────────────────────────────────────────
# Round-trips des repositories (mémoire + SQL)
# ─────────────────────────────────────────────────────────────────────────────


def test_memory_consent_repo_round_trip() -> None:
    repository = InMemoryConsentRepository()
    consent = Consent(
        subject="alice",
        client_id="app",
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    )
    run(repository.save(consent))
    assert run(repository.find("alice", "app")) == consent
    assert run(repository.find("bob", "app")) is None
    run(repository.delete("alice", "app"))
    assert run(repository.find("alice", "app")) is None
    run(repository.delete("alice", "app"))


def test_sql_consent_repo_round_trip(tmp_path: Path) -> None:
    repository = SQLConsentRepository(f"sqlite+aiosqlite:///{tmp_path / 'consents.db'}")
    run(repository.initialise())
    consent = Consent(
        subject="alice",
        client_id="app",
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    )
    try:
        run(repository.save(consent))
        stored = run(repository.find("alice", "app"))
        assert stored == consent
        assert run(repository.find("bob", "app")) is None
        run(repository.delete("alice", "app"))
        assert run(repository.find("alice", "app")) is None
    finally:
        run(repository.close())


# ─────────────────────────────────────────────────────────────────────────────
# Intégration HTTP : flow /authorize → /consent → décision
# ─────────────────────────────────────────────────────────────────────────────


def _app(clients: tuple[dict[str, object], ...] | None = None, **settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=clients or (_CONSENT_CLIENT_JSON,),
            identity_seed_users=_IDENTITY_SEED,
            **settings,
        )
    )


def _s256_challenge(verifier: str) -> str:
    """Challenge PKCE S256 du verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(
    verifier: str = "verifier-verifier",
    client_id: str = "app-with-consent",
    scope: str = "openid profile",
    state: str = "st-auth",
) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation valide (Authorization Code + PKCE)."""
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _REDIRECT_URI,
        "scope": scope,
        "state": state,
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
    }


def _consent_form_data(
    verifier: str = "verifier-verifier",
    scope: str = "openid profile",
    state: str = "st-auth",
    action: str = "authorize",
) -> dict[str, str]:
    """Champs de la décision ``POST /consent`` (miroir des champs cachés de la page)."""
    params = _authorize_params(verifier, scope=scope, state=state)
    params["nonce"] = ""
    params["response_mode"] = ""
    params["action"] = action
    return params


def _login(client: TestClient) -> None:
    """Connecte le compte de démonstration ``alice`` (cookie de session posé)."""
    response = client.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    """Paramètres de la query string d'une URL de redirection."""
    return parse_qs(urlparse(redirect_url).query)


def test_authorize_redirects_to_consent_page() -> None:
    with TestClient(_app()) as client:
        _login(client)
        response = client.get("/authorize", params=_authorize_params(), follow_redirects=False)

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("/consent?")
    query = _redirect_query(location)
    assert query["client_id"] == ["app-with-consent"]
    assert query["scope"] == ["openid profile"]
    assert query["state"] == ["st-auth"]


def test_consent_page_renders_application_and_scopes() -> None:
    with TestClient(_app()) as client:
        _login(client)
        response = client.get("/consent", params=_authorize_params())

    assert response.status_code == 200
    assert "app-with-consent" in response.text
    assert "Consulter votre profil" in response.text
    assert "<code>openid</code>" in response.text
    assert "https://app.example" in response.text
    assert 'action="/consent"' in response.text


def test_consent_approval_issues_exchangeable_code() -> None:
    verifier = "verifier-verifier"
    with TestClient(_app()) as client:
        _login(client)
        auth = client.get("/authorize", params=_authorize_params(verifier), follow_redirects=False)
        assert auth.headers["location"].startswith("/consent?")

        decision = client.post(
            "/consent", data=_consent_form_data(verifier), follow_redirects=False
        )
        assert decision.status_code == 302
        location = decision.headers["location"]
        assert location.startswith(_REDIRECT_URI + "?")
        query = _redirect_query(location)
        assert query["state"] == ["st-auth"]
        code = query["code"][0]

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": "app-with-consent",
                "code_verifier": verifier,
            },
        )

    assert token.status_code == 200
    assert token.json()["access_token"]


def test_consent_deny_returns_access_denied() -> None:
    with TestClient(_app()) as client:
        _login(client)
        decision = client.post(
            "/consent",
            data=_consent_form_data(action="deny"),
            follow_redirects=False,
        )

    assert decision.status_code == 302
    location = decision.headers["location"]
    assert location.startswith(_REDIRECT_URI + "?")
    query = _redirect_query(location)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["st-auth"]


def test_consent_is_memorized_for_next_authorize() -> None:
    with TestClient(_app()) as client:
        _login(client)
        first = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert first.headers["location"].startswith("/consent?")
        client.post("/consent", data=_consent_form_data(), follow_redirects=False)

        second = client.get("/authorize", params=_authorize_params(), follow_redirects=False)

    assert second.status_code == 302
    location = second.headers["location"]
    assert location.startswith(_REDIRECT_URI + "?")
    assert _redirect_query(location)["code"]


def test_new_scope_requires_consent_again() -> None:
    with TestClient(_app()) as client:
        _login(client)
        client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        client.post("/consent", data=_consent_form_data(), follow_redirects=False)

        wider = _authorize_params(scope="openid profile email")
        response = client.get("/authorize", params=wider, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].startswith("/consent?")
    assert _redirect_query(response.headers["location"])["scope"] == ["openid profile email"]


def test_anonymous_is_sent_to_login_for_consent() -> None:
    with TestClient(_app()) as client:
        auth = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert auth.status_code == 302
        consent_path = auth.headers["location"]
        assert consent_path.startswith("/consent?")

        prompt = client.get(consent_path, follow_redirects=False)
        assert prompt.status_code == 302
        assert prompt.headers["location"].startswith("/login?next=/consent%3F")

        decision = client.post("/consent", data=_consent_form_data(), follow_redirects=False)
        assert decision.status_code == 302
        assert decision.headers["location"].startswith("/login?next=/consent%3F")


def test_consent_without_redirect_uri_rejected() -> None:
    with TestClient(_app()) as client:
        _login(client)
        prompt = client.get(
            "/consent",
            params={"response_type": "code", "client_id": "app-with-consent", "scope": "openid"},
        )
        decision = client.post(
            "/consent",
            data={
                "response_type": "code",
                "client_id": "app-with-consent",
                "redirect_uri": "",
                "scope": "openid",
            },
        )

    assert prompt.status_code == 400
    assert decision.status_code == 400


def test_client_without_consent_skips_the_page() -> None:
    with TestClient(_app(clients=(_PLAIN_CLIENT_JSON,))) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(client_id="app-no-consent", scope="openid"),
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(_REDIRECT_URI + "?")
    assert _redirect_query(location)["code"]


def test_par_flow_reaches_consent_and_approves() -> None:
    verifier = "verifier-verifier"
    with TestClient(_app(par_enabled=True)) as client:
        push = client.post(
            "/par",
            data={
                "response_type": "code",
                "client_id": "app-with-consent",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid profile",
                "state": "st-par",
                "code_challenge": _s256_challenge(verifier),
            },
        )
        assert push.status_code == 201
        request_uri = push.json()["request_uri"]

        _login(client)
        auth = client.get(
            "/authorize",
            params={"client_id": "app-with-consent", "request_uri": request_uri},
            follow_redirects=False,
        )
        assert auth.status_code == 302
        assert auth.headers["location"].startswith("/consent?")

        decision = client.post(
            "/consent",
            data=_consent_form_data(verifier, state="st-par"),
            follow_redirects=False,
        )

    assert decision.status_code == 302
    location = decision.headers["location"]
    assert location.startswith(_REDIRECT_URI + "?")
    query = _redirect_query(location)
    assert query["state"] == ["st-par"]
    assert query["code"]
