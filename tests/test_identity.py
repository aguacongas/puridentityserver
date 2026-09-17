"""Tests du module identity (FastAPI Users, spike login).

Les appels directs aux fonctions de route (``pytest.anyio``) garantissent une
couverture fiable : Starlette ``TestClient`` exécute l'app dans un thread
anyio + greenlets SQLAlchemy, un contexte où coverage.py perd le traçage de
certaines lignes (constaté empiriquement sur le corps de ``POST /login`` et la
branche d'insertion de ``seed_users``).

Les tests ``pytest.anyio`` utilisent un ``monkeypatch`` pour injecter leur
propre moteur et session factory (liés à la boucle d'événements du test) sans
perturber les globals du module pour les tests ``TestClient`` qui suivent.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import uuid as uuid_mod
from collections.abc import Callable
from pathlib import Path
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

from puridentityserver.identity.config import UserManager, apply_schema, seed_users
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
    "bob": {"email": "bob@example.com", "password": "password"},
}


def _app(**settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT_JSON,),
            identity_seed_users=_IDENTITY_SEED,
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
    from puridentityserver.identity.config import login_router

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
    from puridentityserver.identity import config as mod

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(mod, "_engine", engine)
    monkeypatch.setattr(mod, "_session_factory", factory)
    return engine, factory


def _ensure_identity_configured() -> None:
    """Configure l'identité (signataires session/reset/verify) pour les tests directs."""
    from puridentityserver.domain.jwks import KeyUse
    from puridentityserver.identity import config as mod
    from puridentityserver.infrastructure.jwks import DefaultKeyManager
    from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository

    mod.configure_identity(
        session_key_manager=DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.SESSION),
        reset_token_key_manager=DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.RESET),
        verification_token_key_manager=DefaultKeyManager(
            InMemoryKeyPairRepository(), use=KeyUse.VERIFY
        ),
        cookie_lifetime_seconds=mod._cookie_lifetime_seconds,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests unitaires directs (pytest.anyio) — couverture déterministe
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_apply_schema_raises_when_engine_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apply_schema() lève RuntimeError si _engine reste None après init."""
    from puridentityserver.identity import config as mod
    from puridentityserver.identity.config import init_users_db

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
    from puridentityserver.identity import config as mod

    monkeypatch.setattr(mod, "_session_factory", None)
    with pytest.raises(RuntimeError, match="init_users_db"):
        mod._get_session_factory()


@pytest.mark.anyio
async def test_seed_users_insert_then_return_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Premier appel crée les comptes ; les suivants les rechargent (idempotent)."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    users = await seed_users(_IDENTITY_SEED)
    assert set(users) == {"alice", "bob"}
    again = await seed_users(_IDENTITY_SEED)
    assert {subject: user.id for subject, user in again.items()} == {
        subject: user.id for subject, user in users.items()
    }


def test_parse_id_converts_uuid_string() -> None:
    """parse_id() convertit le ``sub`` du JWT en ``uuid.UUID``."""
    from puridentityserver.identity.config import UserManager

    manager = UserManager.__new__(UserManager)
    value = "12345678-1234-5678-1234-567812345678"
    assert manager.parse_id(value) == uuid_mod.UUID(value)


def test_configure_identity_wires_settings_values() -> None:
    """configure_identity applique les signataires (session, reset, verify)."""
    from puridentityserver.domain.jwks import KeyUse
    from puridentityserver.identity import config as mod
    from puridentityserver.infrastructure.jwks import DefaultKeyManager
    from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository

    session_manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.SESSION)
    reset_manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.RESET)
    verify_manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.VERIFY)
    mod.configure_identity(
        session_key_manager=session_manager,
        reset_token_key_manager=reset_manager,
        verification_token_key_manager=verify_manager,
        cookie_lifetime_seconds=7200,
        session_rotation_days=15,
        session_grace_period_days=3,
    )
    try:
        strategy = mod._session_strategy()
        assert strategy._signer is not None  # type: ignore[union-attr]
        assert strategy._signer._key_manager is session_manager  # type: ignore[attr-defined]
        assert strategy._signer._rotation_days == 15  # type: ignore[attr-defined]
        assert strategy._signer._grace_period_days == 3  # type: ignore[attr-defined]
        assert mod._cookie_lifetime_seconds == 7200
        assert mod._reset_signer is not None
        assert mod._verify_signer is not None
        assert mod._reset_signer._key_manager is reset_manager  # type: ignore[attr-defined]
        assert mod._verify_signer._key_manager is verify_manager  # type: ignore[attr-defined]
        # plus aucun secret statique : les jetons sont signés par les KeyManagers
        assert not hasattr(mod.UserManager, "reset_password_token_secret")
        assert not hasattr(mod.UserManager, "verification_token_secret")
    finally:
        mod.configure_identity(
            session_key_manager=session_manager,
            reset_token_key_manager=reset_manager,
            verification_token_key_manager=verify_manager,
            cookie_lifetime_seconds=mod._cookie_lifetime_seconds,
            session_rotation_days=15,
            session_grace_period_days=3,
        )


@pytest.mark.anyio
async def test_post_login_success_sets_cookie_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login valide le redirect + cookie de session (appel direct)."""
    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_users(_IDENTITY_SEED)

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="password",
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
    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_users(_IDENTITY_SEED)

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="wrong-password",
        next_url="/",
    )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")
    assert "set-cookie" not in response.headers


@pytest.mark.anyio
async def test_post_login_tolerates_empty_cookie_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login tolère une réponse backend sans cookie."""
    from puridentityserver.identity import config as mod

    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_users(_IDENTITY_SEED)

    async def _fake_login(_self: object, strategy: object, user: object) -> object:
        await asyncio.sleep(0)
        return type("Fake", (object,), {"headers": {}})()

    monkeypatch.setattr(mod.AuthenticationBackend, "login", _fake_login)

    endpoint = _post_login_endpoint()
    response = await endpoint(
        username="alice@example.com",
        password="password",
        next_url="/target",
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/target"
    assert "set-cookie" not in response.headers


@pytest.mark.anyio
async def test_post_login_applies_client_session_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /login applique la durée du client du flow (cookie Max-Age + exp JWT)."""
    import re as re_mod

    from puridentityserver.identity.config import login_router

    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    await seed_users(_IDENTITY_SEED)

    async def _resolve(client_id: str) -> int | None:
        await asyncio.sleep(0)
        return 600 if client_id == "web-app" else None

    router = login_router(_resolve)
    endpoint = next(
        route.endpoint
        for route in router.routes
        if route.path == "/login" and "POST" in route.methods
    )
    response = await endpoint(
        username="alice@example.com",
        password="password",
        next_url="/authorize?client_id=web-app",
        client_id="web-app",
    )

    assert response.status_code == 302
    cookie = response.headers["set-cookie"]
    assert "Max-Age=600" in cookie
    token = re_mod.search(r"fastapiusersauth=([^;]+)", cookie).group(1)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 600


@pytest.mark.anyio
async def test_get_login_page_injects_hidden_client_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /login pré-remplit le champ caché ``client_id`` depuis l'URL de retour."""
    from puridentityserver.identity.config import login_router

    _inject_test_db(monkeypatch)
    await apply_schema()
    router = login_router()
    get_endpoint = next(
        route.endpoint
        for route in router.routes
        if route.path == "/login" and "GET" in route.methods
    )

    page = await get_endpoint(next_url="/authorize?client_id=web-app&state=s1")
    assert 'name="client_id" value="web-app"' in page

    plain = await get_endpoint(next_url="/")
    assert 'name="client_id"' not in plain


class _CapturingUserManager(UserManager):
    """UserManager qui capture les jetons de gestion émis via les hooks internes."""

    def __init__(self, user_db: object) -> None:
        super().__init__(user_db)  # type: ignore[arg-type]
        self.verify_token = ""
        self.reset_token = ""

    async def on_after_request_verify(
        self, user: object, token: str, request: object = None
    ) -> None:
        self.verify_token = token

    async def on_after_forgot_password(
        self, user: object, token: str, request: object = None
    ) -> None:
        self.reset_token = token


@pytest.mark.anyio
async def test_request_verify_and_verify_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """request_verify → verify : jeton RS256 rotatif, compte vérifié, rejeu refusé."""
    from fastapi_users import exceptions
    from fastapi_users.db import SQLAlchemyUserDatabase

    from puridentityserver.identity import config as mod
    from puridentityserver.identity.user import User

    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    users = await seed_users(_IDENTITY_SEED)
    alice = users["alice"]

    async with mod._get_session_factory()() as session:
        user_db: SQLAlchemyUserDatabase[User, uuid_mod.UUID] = SQLAlchemyUserDatabase(session, User)
        manager = _CapturingUserManager(user_db)

        await manager.request_verify(alice)
        token = manager.verify_token
        assert token
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"]
        assert (
            jwt.decode(token, options={"verify_signature": False})["aud"] == "fastapi-users:verify"
        )

        verified = await manager.verify(token)
        assert verified.is_verified
        with pytest.raises(exceptions.InvalidVerifyToken):
            await manager.verify("jeton-invalide")
        with pytest.raises(exceptions.UserAlreadyVerified):
            await manager.verify(token)


@pytest.mark.anyio
async def test_forgot_and_reset_password_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """forgot_password → reset_password : jeton RS256 rotatif, mot de passe changé."""
    from fastapi_users import exceptions
    from fastapi_users.db import SQLAlchemyUserDatabase

    from puridentityserver.identity import config as mod
    from puridentityserver.identity.user import User

    _ensure_identity_configured()
    _inject_test_db(monkeypatch)
    await apply_schema()
    users = await seed_users(_IDENTITY_SEED)
    alice = users["alice"]

    async with mod._get_session_factory()() as session:
        user_db: SQLAlchemyUserDatabase[User, uuid_mod.UUID] = SQLAlchemyUserDatabase(session, User)
        manager = _CapturingUserManager(user_db)

        await manager.forgot_password(alice)
        token = manager.reset_token
        assert token
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"]
        assert (
            jwt.decode(token, options={"verify_signature": False})["aud"] == "fastapi-users:reset"
        )

        old_hash = alice.hashed_password
        updated = await manager.reset_password(token, "nouveau-mdp-42!")
        assert updated.id == alice.id
        assert updated.hashed_password != old_hash
        # le hachage ayant changé, le même jeton (fingerprint) n'est plus valide
        with pytest.raises(exceptions.InvalidResetPasswordToken):
            await manager.reset_password(token, "encore-un-mdp-42!")
        with pytest.raises(exceptions.InvalidResetPasswordToken):
            await manager.reset_password("jeton-invalide", "encore-un-mdp-42!")


@pytest.mark.anyio
async def test_get_login_page_escapes_next_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /login rend le formulaire HTML avec ``next`` échappé (XSS safe)."""
    _inject_test_db(monkeypatch)
    await apply_schema()
    from puridentityserver.identity.config import login_router

    router = login_router()
    for route in router.routes:
        if route.path == "/login" and "GET" in route.methods:
            page = await route.endpoint(next_url='"><script>')
            break
    else:
        raise AssertionError("GET /login introuvable")

    assert isinstance(page, str)  # le endpoint renvoie le HTML brut (enveloppé par HTMLResponse)
    assert "Connexion à PurIdentityServer" in page
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
    assert "Connexion à PurIdentityServer" in response.text
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


@pytest.mark.parametrize(
    ("email", "expected_name", "expected_roles"),
    (
        ("alice@example.com", "Alice Martin", ["admin", "member"]),
        ("bob@example.com", "Bob Durand", ["member"]),
    ),
)
def test_login_authorize_token_full_flow(
    email: str, expected_name: str, expected_roles: list[str]
) -> None:
    """Flow E2E : login (cookie) → /authorize → /token → /userinfo.

    Vérifie que le ``sub`` du id_token est l'UUID FastAPI Users de
    l'utilisateur (pas vide = requête anonyme), et que `/userinfo` renvoie
    son profil ponté identité ⊕ user store, rôles inclus.
    """
    verifier = "verifier-verifier"
    users_seed = {
        "alice": {
            "name": "Alice Martin",
            "preferred_username": "alice-martin",
            "email": "alice.martin@example.com",
            "email_verified": True,
            "roles": ["admin", "member"],
        },
        "bob": {
            "name": "Bob Durand",
            "preferred_username": "bob-durand",
            "email": "bob.durand@example.com",
            "email_verified": True,
            "roles": ["member"],
        },
    }
    with TestClient(_app(users_seed=users_seed)) as client:
        login_resp = client.post(
            "/login",
            data={
                "username": email,
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
        assert sub != ""  # sub = UUID de l'utilisateur, pas vide (requête anonyme)
        assert uuid_mod.UUID(sub)

        userinfo_resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {payload['access_token']}"},
        )
        assert userinfo_resp.status_code == 200
        userinfo = userinfo_resp.json()
        assert userinfo["sub"] == sub
        assert userinfo["name"] == expected_name
        assert userinfo["roles"] == expected_roles


def test_login_per_client_lifetime_from_seed() -> None:
    """POST /login applique ``session_lifetime_seconds`` du client seed.

    Vérifie le câblage complet : le résolveur de durée (server.py) lit la
    durée déclarée dans ``clients_seed`` du client du flow, le cookie en a
    le ``Max-Age`` et le JWT un ``exp`` calé dessus.
    """
    client_json = {**_CLIENT_JSON, "session_lifetime_seconds": 1800}
    app = create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(client_json,),
            identity_seed_users=_IDENTITY_SEED,
        )
    )
    with TestClient(app) as client:
        login_resp = client.post(
            "/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": f"/authorize?client_id={_CLIENT_JSON['client_id']}",
            },
            follow_redirects=False,
        )
        assert login_resp.status_code == 302
        cookie = login_resp.headers["set-cookie"]
        assert "Max-Age=1800" in cookie
        token = re.search(r"fastapiusersauth=([^;]+)", cookie).group(1)
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["exp"] - claims["iat"] == 1800


def test_login_cookie_signed_with_dedicated_session_key(tmp_path: Path) -> None:
    """Le cookie est RS256, signé par une clé de session distincte des clés JWKS.

    La base SQL partagée contient les deux familles (``sig`` pour les tokens,
    ``session`` pour le cookie) : seule la seconde signe le cookie, et seule
    la première est publiée dans ``/.well-known/jwks.json``. Le schéma a été
    créé sans la colonne ``use`` (schéma antérieur) pour valider la migration.
    """
    import asyncio
    import re
    import sqlite3

    from puridentityserver.domain.jwks import KeyUse
    from puridentityserver.infrastructure.persistence.sql.keys import SQLKeyPairRepository

    db_path = tmp_path / "keys.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE key_pairs ("
        "kid VARCHAR(128) PRIMARY KEY, algorithm VARCHAR(16), "
        "private_key_pem TEXT, public_key_pem TEXT, "
        "created_at DATETIME, is_active BOOLEAN, key_size INTEGER)"
    )
    conn.close()

    dsn = f"sqlite:///{db_path}"
    with TestClient(_app(storage_type="sql", storage_dsn=dsn)) as client:
        resp = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        token = re.search(r"fastapiusersauth=([^;]+)", resp.headers["set-cookie"]).group(  # type: ignore[union-attr]
            1
        )

        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"]
        session_kid = header["kid"]

        token_jwks = client.get("/.well-known/jwks.json").json()["keys"]
        assert token_jwks  # des clés de signature existent
        assert all(jwk.get("kid") != session_kid for jwk in token_jwks)
        token_public_key = jwt.algorithms.RSAAlgorithm.from_jwk(token_jwks[0])
        with pytest.raises(jwt.PyJWTError):
            jwt.decode(
                token,
                token_public_key,
                algorithms=["RS256"],
                options={"verify_exp": False, "verify_aud": False},
            )

    async def _read_session_key() -> object:
        repo = SQLKeyPairRepository(dsn)
        await repo.initialise()  # valide la migration (colonne `use` ajoutée)
        keys = await repo.find_all()
        session_key = next(key for key in keys if key.use is KeyUse.SESSION)
        # les autres familles (sig / reset / verify) sont disjointes, jamais session
        assert all(key.use is not KeyUse.SESSION for key in keys if key.kid != session_key.kid)
        return session_key

    session_key = asyncio.run(_read_session_key())
    claims = jwt.decode(
        token,
        session_key.public_key_pem,  # type: ignore[union-attr]
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_aud": False},
    )
    assert claims["sub"]
