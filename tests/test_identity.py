"""Tests du module identity (FastAPI Users, spike login).

Les appels directs aux fonctions de route (``pytest.anyio``) garantissent une
couverture fiable : Starlette ``TestClient`` exécute l'app dans un thread
anyio + greenlets SQLAlchemy, un contexte où coverage.py perd le traçage de
certaines lignes (constaté empiriquement sur le corps de ``POST /login`` et la
branche d'insertion de ``seed_demo_user``).

Les tests ``pytest.anyio`` utilisent un ``monkeypatch`` pour injecter leur
propre moteur et session factory (liés à la boucle d'événements du test) sans
perturber les globals du module pour les tests ``TestClient`` qui suivent.
"""

from __future__ import annotations

import base64
import hashlib
import uuid as uuid_mod
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from thepuroidc.identity.config import DEMO_USER_SUBJECT, apply_schema, seed_demo_user
from thepuroidc.infrastructure.settings import Settings
from thepuroidc.server import create_app

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}


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


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


def _post_login_endpoint() -> Callable[..., Any]:
    """Retourne la fonction de route ``POST /login`` du routeur identity."""
    from thepuroidc.identity.config import login_router

    router = login_router()
    for route in router.routes:
        if route.path == "/login" and "POST" in route.methods:
            return route.endpoint
    raise AssertionError("POST /login introuvable dans login_router()")


def _inject_test_db(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Injecte un moteur SQLite isolé dans les globals du module identity.

    Le ``monkeypatch`` restaure automatiquement les valeurs originales à
    la fin du test, laissant les tests ``TestClient`` intacts.
    """
    from thepuroidc.identity import config as mod

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(mod, "_engine", engine)
    monkeypatch.setattr(mod, "_session_factory", factory)
    return engine, factory


# ─────────────────────────────────────────────────────────────────────────────
# Tests unitaires directs (pytest.anyio) — couverture déterministe
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_apply_schema_raises_when_engine_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apply_schema() lève RuntimeError si _engine reste None après init."""
    from thepuroidc.identity import config as mod
    from thepuroidc.identity.config import init_users_db

    monkeypatch.setattr(mod, "_session_factory", None)
    monkeypatch.setattr(mod, "_engine", None)
    init_users_db()
    monkeypatch.setattr(mod, "_engine", None)
    with pytest.raises(RuntimeError, match="moteur non initialisé"):
        await apply_schema()


def test_get_session_factory_raises_before_init(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Appel à _get_session_factory() avant init_users_db() → RuntimeError."""
    from thepuroidc.identity import config as mod

    monkeypatch.setattr(mod, "_session_factory", None)
    with pytest.raises(RuntimeError, match="init_users_db"):
        mod._get_session_factory()


@pytest.mark.anyio
async def test_seed_demo_user_insert_then_returns_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Premier appel insère Alice ; les suivants sortent par la branche early."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_demo_user()
    await seed_demo_user()


def test_parse_id_converts_uuid_string() -> None:
    """parse_id() convertit le ``sub`` du JWT en ``uuid.UUID``."""
    from thepuroidc.identity.config import UserManager

    manager = UserManager.__new__(UserManager)
    value = "12345678-1234-5678-1234-567812345678"
    assert manager.parse_id(value) == uuid_mod.UUID(value)


@pytest.mark.anyio
async def test_post_login_success_sets_cookie_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login valide le redirect + cookie de session (appel direct)."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_demo_user()

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="password",  # ruff: ignore[hardcoded-password-func-arg]
        next_url="/target",
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/target"
    assert "fastapiusersauth" in response.headers["set-cookie"]


@pytest.mark.anyio
async def test_post_login_rejects_wrong_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login avec un mauvais mot de passe redirige vers le formulaire."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_demo_user()

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="wrong-password",  # ruff: ignore[hardcoded-password-func-arg]
        next_url="/",
    )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")
    assert "set-cookie" not in response.headers


@pytest.mark.anyio
async def test_post_login_handles_awaitable_strategy_and_empty_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login tolère une stratégie coroutine et une réponse sans cookie."""
    from thepuroidc.identity import config as mod

    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_demo_user()

    async def _awaitable_strategy() -> mod.JWTStrategy:  # ruff: ignore[unused-async]
        return mod._jwt_strategy()

    async def _fake_backend_login(strategy: object, user: object) -> object:  # ruff: ignore[unused-async]
        return type(
            "Fake",
            (),
            {"headers": {"location": "/"}},
        )()

    monkeypatch.setattr(mod.cookie_backend, "get_strategy", _awaitable_strategy)
    monkeypatch.setattr(mod.cookie_backend, "login", _fake_backend_login)

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="password",  # ruff: ignore[hardcoded-password-func-arg]
        next_url="/target",
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/target"
    assert "set-cookie" not in response.headers


@pytest.mark.anyio
async def test_get_login_page_escapes_next_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /login rend le formulaire HTML avec ``next`` échappé (XSS safe)."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    from thepuroidc.identity.config import login_router

    router = login_router()
    for route in router.routes:
        if route.path == "/login" and "GET" in route.methods:
            page = await route.endpoint(next_url='"><script>')
            break
    else:
        raise AssertionError("GET /login introuvable")

    assert isinstance(page, str)  # le endpoint renvoie le HTML brut (enveloppé par HTMLResponse)
    assert "Connexion à ThePurOidc" in page
    assert 'name="username"' in page
    assert 'value="&quot;&gt;&lt;script&gt;"' in page
    assert (
        "script" in page
    )  # seul le littéral « script » échappé apparaît (pas de balise effective)


# ─────────────────────────────────────────────────────────────────────────────
# Tests comportementaux via HTTP (TestClient) — preuve end-to-end
# ─────────────────────────────────────────────────────────────────────────────
# Ces tests tournent EN DERNIER : les tests directs ci-dessus restaurent
# les globals via monkeypatch, donc le TestClient retrouve bien le moteur
# original lié à sa boucle d'événements.


def test_login_page_get_renders_form() -> None:
    """GET /login rend la page HTML avec le formulaire."""
    with TestClient(_app()) as client:
        response = client.get("/login")

    assert response.status_code == 200
    assert "Connexion à ThePurOidc" in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text
    assert 'name="next"' in response.text


def test_post_login_bad_credentials_redirects() -> None:
    """POST /login avec un mauvais mot de passe redirige vers le formulaire."""
    with TestClient(_app()) as client:
        response = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "wrong", "next": "/"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")


def test_login_authorize_token_full_flow() -> None:
    """Flow E2E : login (cookie) → /authorize → /token → /userinfo.

    Vérifie que le ``sub`` du id_token est l'UUID d'Alice (pas vide =
    requête anonyme), et que `/userinfo` renvoie le profil Alice ponté
    identité ⊕ user store.
    """
    verifier = "verifier-verifier"
    demo_profile = {
        "name": "Alice Martin",
        "preferred_username": "alice-martin",
        "email": "alice.martin@example.com",
        "email_verified": True,
    }
    with TestClient(_app(users_seed={DEMO_USER_SUBJECT: demo_profile})) as client:
        login_resp = client.post(
            "/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": "/",
            },
            follow_redirects=False,
        )
        assert login_resp.status_code == 302
        assert "fastapiusersauth" in (login_resp.headers.get("set-cookie", ""))

        auth_resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile email",
                "nonce": "n-spiked",
                "code_challenge": _s256_challenge(verifier),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert auth_resp.status_code == 302
        code = _redirect_query(auth_resp.headers["location"])["code"][0]

        token_resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": "super-secret",
                "code_verifier": verifier,
            },
        )
        payload = token_resp.json()
        assert token_resp.status_code == 200
        assert payload["id_token"]
        assert payload["access_token"]

        jwks = client.get("/.well-known/jwks.json")
        assert jwks.status_code == 200
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks.json()["keys"][0])
        id_claims = jwt.decode(
            payload["id_token"],
            public_key,
            algorithms=["RS256"],
            audience="web-app",
            issuer=_ISSUER,
        )
        assert "openid" in id_claims["scope"]
        assert "profile" in id_claims["scope"]
        assert "email" in id_claims["scope"]

        sub = id_claims["sub"]
        assert sub != ""  # sub = UUID d'Alice, pas vide (requête anonyme)
        assert uuid_mod.UUID(sub)

        userinfo_resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {payload['access_token']}"},
        )
        assert userinfo_resp.status_code == 200
        userinfo = userinfo_resp.json()
        assert userinfo["sub"] == sub
        assert userinfo["name"] == "Alice Martin"
        assert userinfo["email"] == "alice.martin@example.com"
