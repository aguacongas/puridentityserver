"""Tests de la Pushed Authorization Request (RFC 9126)."""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import AuthorizeRequest
from puridentityserver.application.par import (
    PushedAuthorizationConfig,
    PushedAuthorizationUseCase,
    PushError,
    PushResult,
)
from puridentityserver.domain.authorization import Client, ClientType, PushedAuthorization, Scope
from puridentityserver.infrastructure.persistence.factory import (
    build_pushed_authorization_repository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.pushed_authorizations import (
    InMemoryPushedAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.sql.pushed_authorizations import (
    SQLPushedAuthorizationRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_ID = "par-app"
_CLIENT_SECRET = "super-secret"

_PUBLIC_CLIENT = Client(
    client_id=_CLIENT_ID,
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    client_type=ClientType.PUBLIC,
)

_CONFIDENTIAL_CLIENT = Client(
    client_id="par-web",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
)

_PARAMS = {
    "response_type": "code",
    "client_id": _CLIENT_ID,
    "redirect_uri": "https://app.example/callback",
    "scope": "openid",
    "state": "st-1",
}


def run(awaitable: Awaitable[_T]) -> _T:
    return asyncio.run(awaitable)


def _future_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=5)


def _past_expiry() -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=1)


def _make_usecase(
    client: Client = _PUBLIC_CLIENT,
    repo: InMemoryPushedAuthorizationRepository | None = None,
    ttl: int = 90,
) -> tuple[
    PushedAuthorizationUseCase, InMemoryClientRepository, InMemoryPushedAuthorizationRepository
]:
    clients = InMemoryClientRepository()
    pushed = repo if repo is not None else InMemoryPushedAuthorizationRepository()
    uc = PushedAuthorizationUseCase(PushedAuthorizationConfig(ttl_seconds=ttl), clients, pushed)
    run(clients.save(client))
    return uc, clients, pushed


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _app(seed: tuple[dict[str, object], ...] | None = None, **settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=tuple(
                seed
                or (
                    {
                        "client_id": _CLIENT_ID,
                        "redirect_uris": ["https://app.example/callback"],
                        "scopes": "openid profile",
                        "client_type": "public",
                    },
                )
            ),
            **settings,
        )
    )


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


class TestPushedAuthorizationUseCase:
    """Tests unitaires de PushedAuthorizationUseCase."""

    def test_push_rejects_request_uri_in_body(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "request_uri": "urn:ietf:params:oauth:request_uri:x"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_request"
        assert result.status_code == 400

    def test_push_rejects_unknown_client(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "client_id": "unknown"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_push_rejects_bad_secret_for_confidential(self) -> None:
        uc, _, _ = _make_usecase(_CONFIDENTIAL_CLIENT)
        result = run(uc.push({**_PARAMS, "client_id": "par-web", "client_secret": "wrong"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_push_rejects_secret_for_public_client(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "client_secret": "anything"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_push_confidential_with_valid_secret(self) -> None:
        uc, _, _ = _make_usecase(_CONFIDENTIAL_CLIENT)
        result = run(uc.push({**_PARAMS, "client_id": "par-web", "client_secret": _CLIENT_SECRET}))
        assert isinstance(result, PushResult)
        assert result.expires_in == 90
        assert result.request_uri.startswith("urn:ietf:params:oauth:request_uri:")
        assert len(result.request_uri) > 40

    def test_push_public_client(self) -> None:
        uc, _, pushed = _make_usecase()
        result = run(uc.push(dict(_PARAMS)))
        assert isinstance(result, PushResult)
        stored = run(pushed.find_by_request_uri(result.request_uri))
        assert stored is not None
        assert stored.client_id == _CLIENT_ID
        assert stored.params["state"] == "st-1"
        assert "client_secret" not in stored.params

    def test_push_rejects_missing_openid_scope(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "scope": "profile"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_scope"
        assert result.status_code == 400

    def test_push_rejects_unsupported_response_type(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "response_type": "foo"}))
        assert isinstance(result, PushError)
        assert result.error == "unsupported_response_type"
        assert result.status_code == 400

    def test_push_rejects_unregistered_redirect_uri(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.push({**_PARAMS, "redirect_uri": "https://evil.example/phish"}))
        assert isinstance(result, PushError)
        assert result.error == "invalid_redirect_uri"

    def test_push_unknown_client_does_not_store(self) -> None:
        uc, _, pushed = _make_usecase()
        result = run(uc.push({**_PARAMS, "client_id": "unknown"}))
        assert isinstance(result, PushError)
        assert run(pushed.find_by_request_uri("anything")) is None

    def test_resolve_unknown_request_uri(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.resolve("urn:ietf:params:oauth:request_uri:unknown", _CLIENT_ID))
        assert isinstance(result, PushError)
        assert result.error == "invalid_request"

    def test_resolve_round_trip(self) -> None:
        uc, _, _ = _make_usecase()
        pushed_result = run(uc.push(dict(_PARAMS)))
        assert isinstance(pushed_result, PushResult)
        resolved = run(uc.resolve(pushed_result.request_uri, _CLIENT_ID))
        assert isinstance(resolved, AuthorizeRequest)
        assert resolved.client_id == _CLIENT_ID
        assert resolved.response_type == "code"
        assert resolved.redirect_uri == "https://app.example/callback"
        assert resolved.scope == "openid"
        assert resolved.state == "st-1"

    def test_resolve_is_single_use(self) -> None:
        uc, _, _ = _make_usecase()
        pushed_result = run(uc.push(dict(_PARAMS)))
        assert isinstance(pushed_result, PushResult)
        first = run(uc.resolve(pushed_result.request_uri, _CLIENT_ID))
        assert isinstance(first, AuthorizeRequest)
        second = run(uc.resolve(pushed_result.request_uri, _CLIENT_ID))
        assert isinstance(second, PushError)
        assert second.error == "invalid_request"

    def test_resolve_rejects_other_client(self) -> None:
        uc, _, _ = _make_usecase()
        pushed_result = run(uc.push(dict(_PARAMS)))
        assert isinstance(pushed_result, PushResult)
        result = run(uc.resolve(pushed_result.request_uri, "other-client"))
        assert isinstance(result, PushError)
        assert result.error == "invalid_request"

    def test_resolve_rejects_expired(self) -> None:
        uc, _, pushed = _make_usecase()
        expired = PushedAuthorization(
            request_uri="urn:ietf:params:oauth:request_uri:expired",
            client_id=_CLIENT_ID,
            params=dict(_PARAMS),
            expires_at=_past_expiry(),
        )
        run(pushed.save(expired))
        result = run(uc.resolve(expired.request_uri, _CLIENT_ID))
        assert isinstance(result, PushError)
        assert result.error == "invalid_request"
        assert "expiré" in result.error_description.lower() or "expired" in result.error_description

    def test_resolve_rejects_consumed(self) -> None:
        uc, _, pushed = _make_usecase()
        consumed = PushedAuthorization(
            request_uri="urn:ietf:params:oauth:request_uri:used",
            client_id=_CLIENT_ID,
            params=dict(_PARAMS),
            expires_at=_future_expiry(),
            is_consumed=True,
        )
        run(pushed.save(consumed))
        result = run(uc.resolve(consumed.request_uri, _CLIENT_ID))
        assert isinstance(result, PushError)
        assert result.error == "invalid_request"

    def test_status_code_of_push_errors(self) -> None:
        uc, _, _ = _make_usecase()
        assert isinstance(run(uc.push({**_PARAMS, "scope": "profile"})), PushError)
        assert isinstance(run(uc.push({**_PARAMS, "client_id": "unknown"})), PushError)


class TestPushedAuthorizationRepositories:
    """Round-trip mémoire et SQL du repository PushedAuthorization."""

    def test_memory_round_trip(self) -> None:
        repo = InMemoryPushedAuthorizationRepository()
        pushed = PushedAuthorization(
            request_uri="urn:ietf:params:oauth:request_uri:m1",
            client_id=_CLIENT_ID,
            params=dict(_PARAMS),
            expires_at=_future_expiry(),
        )
        run(repo.save(pushed))
        found = run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:m1"))
        assert found is not None
        assert found.client_id == _CLIENT_ID
        assert found.params["state"] == "st-1"

        run(repo.consume("urn:ietf:params:oauth:request_uri:m1"))
        consumed = run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:m1"))
        assert consumed is not None
        assert consumed.is_consumed is True

        run(repo.delete("urn:ietf:params:oauth:request_uri:m1"))
        assert run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:m1")) is None

    def test_sql_round_trip(self, tmp_path: Path) -> None:
        db = tmp_path / "par.db"
        repo = SQLPushedAuthorizationRepository(f"sqlite+aiosqlite:///{db}")
        run(repo.initialise())
        pushed = PushedAuthorization(
            request_uri="urn:ietf:params:oauth:request_uri:sql1",
            client_id=_CLIENT_ID,
            params=dict(_PARAMS),
            expires_at=_future_expiry(),
        )
        run(repo.save(pushed))
        found = run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:sql1"))
        assert found is not None
        assert found.client_id == _CLIENT_ID
        assert found.params == _PARAMS

        run(repo.consume("urn:ietf:params:oauth:request_uri:sql1"))
        consumed = run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:sql1"))
        assert consumed is not None
        assert consumed.is_consumed is True

        run(repo.delete("urn:ietf:params:oauth:request_uri:sql1"))
        assert run(repo.find_by_request_uri("urn:ietf:params:oauth:request_uri:sql1")) is None
        run(repo.close())

    def test_factory_memory(self) -> None:
        repo = build_pushed_authorization_repository(Settings(storage_type="memory"))
        assert isinstance(repo, InMemoryPushedAuthorizationRepository)

    def test_factory_sql(self, tmp_path: Path) -> None:
        db = tmp_path / "factory.db"
        repo = build_pushed_authorization_repository(
            Settings(storage_type="sql", storage_dsn=f"sqlite+aiosqlite:///{db}")
        )
        assert isinstance(repo, SQLPushedAuthorizationRepository)


class TestParIntegrationHTTP:
    """Tests d'intégration HTTP du flow PAR (TestClient FastAPI)."""

    def test_discovery_exposes_par_endpoint(self) -> None:
        with TestClient(_app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
        assert metadata["pushed_authorization_request_endpoint"] == f"{_ISSUER}/par"

    def test_push_returns_request_uri(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                    "state": "st-1",
                },
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
        assert body["expires_in"] == 90

    def test_push_rejects_unknown_client(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": "unknown",
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"

    def test_push_rejects_invalid_scope(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "profile",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_scope"

    def test_full_flow_code_with_request_uri(self) -> None:
        with TestClient(_app()) as client:
            push = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                    "state": "st-par",
                    "code_challenge": _s256_challenge("verifier-verifier"),
                },
            )
            assert push.status_code == 201
            request_uri = push.json()["request_uri"]

            auth = client.get(
                "/authorize",
                params={"client_id": _CLIENT_ID, "request_uri": request_uri},
                follow_redirects=False,
            )
            assert auth.status_code == 302
            query = _redirect_query(auth.headers["location"])
            assert query["code"]
            assert query["state"] == ["st-par"]

            resp = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": query["code"][0],
                    "redirect_uri": "https://app.example/callback",
                    "client_id": _CLIENT_ID,
                    "code_verifier": "verifier-verifier",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"]

    def test_request_uri_is_single_use(self) -> None:
        with TestClient(_app()) as client:
            push = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
            request_uri = push.json()["request_uri"]

            first = client.get(
                "/authorize",
                params={"client_id": _CLIENT_ID, "request_uri": request_uri},
                follow_redirects=False,
            )
            assert first.status_code == 302

            second = client.get(
                "/authorize",
                params={"client_id": _CLIENT_ID, "request_uri": request_uri},
                follow_redirects=False,
            )
        assert second.status_code == 400
        assert second.json()["detail"]["error"] == "invalid_request"

    def test_authorize_rejects_extra_param_with_request_uri(self) -> None:
        with TestClient(_app()) as client:
            push = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
            request_uri = push.json()["request_uri"]

            resp = client.get(
                "/authorize",
                params={
                    "client_id": _CLIENT_ID,
                    "request_uri": request_uri,
                    "scope": "openid",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_request"

    def test_authorize_rejects_unknown_request_uri(self) -> None:
        with TestClient(_app()) as client:
            resp = client.get(
                "/authorize",
                params={
                    "client_id": _CLIENT_ID,
                    "request_uri": "urn:ietf:params:oauth:request_uri:not-found",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_request"

    def test_authorize_rejects_mismatched_client(self) -> None:
        with TestClient(_app()) as client:
            push = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
            request_uri = push.json()["request_uri"]

            resp = client.get(
                "/authorize",
                params={"client_id": "other-client", "request_uri": request_uri},
                follow_redirects=False,
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_request"

    def test_push_rejects_request_uri_in_body(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                    "request_uri": "urn:ietf:params:oauth:request_uri:whatever",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    def test_authorize_without_params_returns_html_400(self) -> None:
        """Sans response_type : page HTML 400 (RFC 6749 §3.1.1), plus de JSON 422."""
        with TestClient(_app()) as client:
            resp = client.get("/authorize", follow_redirects=False)
        assert resp.status_code == 400
        assert resp.headers["content-type"].startswith("text/html")
        assert "Requête d'autorisation invalide" in resp.text
        assert "response_type" in resp.text

    def test_confidential_client_with_secret_at_par(self) -> None:
        seed = (
            {
                "client_id": "par-web",
                "client_secret": _CLIENT_SECRET,
                "redirect_uris": ["https://app.example/callback"],
                "scopes": "openid",
                "client_type": "confidential",
            },
        )
        with TestClient(_app(seed)) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": "par-web",
                    "client_secret": _CLIENT_SECRET,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
            assert resp.status_code == 201
            request_uri = resp.json()["request_uri"]

            auth = client.get(
                "/authorize",
                params={"client_id": "par-web", "request_uri": request_uri},
                follow_redirects=False,
            )
        assert auth.status_code == 302
        assert _redirect_query(auth.headers["location"])["code"]


class TestParRequiredPerClient:
    """Obligation PAR par client (RFC 9126 §6.1) — comportement /authorize."""

    _SEED = (
        {
            "client_id": _CLIENT_ID,
            "redirect_uris": ["https://app.example/callback"],
            "scopes": "openid profile",
            "client_type": "public",
            "par_required": True,
        },
    )

    def test_direct_authorize_rejected_when_par_required(self) -> None:
        with TestClient(_app(self._SEED)) as client:
            resp = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_request"
        assert "Pushed Authorization Request" in resp.json()["detail"]["error_description"]

    def test_par_flow_allowed_when_par_required(self) -> None:
        with TestClient(_app(self._SEED)) as client:
            push = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                    "state": "st-req",
                },
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
        assert query["state"] == ["st-req"]

    def test_non_required_client_keeps_direct_flow(self) -> None:
        with TestClient(_app()) as client:
            resp = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert _redirect_query(resp.headers["location"])["code"]


class TestParDisabled:
    """Le endpoint /par et la résolution sont coupés quand par_enabled=False."""

    def test_par_endpoint_404_when_disabled(self) -> None:
        with TestClient(_app(par_enabled=False)) as client:
            resp = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid",
                },
            )
        assert resp.status_code == 404

    def test_discovery_omits_par_endpoint_when_disabled(self) -> None:
        with TestClient(_app(par_enabled=False)) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
        assert metadata.get("pushed_authorization_request_endpoint") is None

    def test_authorize_rejects_request_uri_when_disabled(self) -> None:
        with TestClient(_app(par_enabled=False)) as client:
            resp = client.get(
                "/authorize",
                params={
                    "client_id": _CLIENT_ID,
                    "request_uri": "urn:ietf:params:oauth:request_uri:whatever",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_request"
