"""Configuration FastAPI Users — backend cookie (JWT) + routes /auth.

Fournit l'identité utilisateur du serveur OIDC :

- ``auth_router``            : routes ``/auth/cookie/login``, ``/logout``, ``/refresh``
- ``register_router``        : route ``/auth/register``
- ``login_router``           : page ``/login`` (formulaire HTML, spike navigateur)
- ``CurrentUser``            : dependency d'utilisateur authentifié (requis)
- ``CurrentUserOptional``    : dependency d'utilisateur authentifié (facultatif)
- ``apply_schema``           : crée la table ``user`` (SQLite en mémoire, spike)
- ``seed_users``             : crée les comptes décrits par ``Settings.identity_seed_users``
- ``configure_identity``     : injecte les secrets (config.toml / THEPUROIDC_* / .env)

Note spike : la base utilisateurs est en mémoire (``StaticPool``) ; en
production elle sera remplacée par un vrai magasin (DSN dédié ou la base
partagée ``KEY_STORE_DSN``).
"""

from __future__ import annotations

import html
import inspect
import uuid
from collections.abc import AsyncGenerator, Mapping
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import BaseUserManager, FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.schemas import BaseUser, BaseUserCreate
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from thepuroidc.identity.user import Base, User

# ── configuration d'exécution (injectée par ``configure_identity``) ─────────
# Valeurs de repli de démonstration : la composition root (``server.py``)
# injecte celles de ``Settings`` (config.toml, ``THEPUROIDC_*``, ``.env``).
_cookie_secret = "spike-dev-only-256bits-secret-change-in-prod!"  # ruff: ignore[hardcoded-password-string]
_cookie_lifetime_seconds = 3600
_reset_password_secret = "spike-reset-secret"  # ruff: ignore[hardcoded-password-string]
_verification_secret = "spike-verify-secret"  # ruff: ignore[hardcoded-password-string]

# ── base de données users (async, séparée des stores OIDC) ──────────────────
_session_factory: async_sessionmaker[AsyncSession] | None = None
_engine: AsyncEngine | None = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("init_users_db() n'a pas encore été appelé")
    return _session_factory


async def _manager_dependency() -> AsyncGenerator[UserManager, None]:
    """Dependency FastAPI fournissant un user manager par requête."""
    factory = _get_session_factory()
    async with factory() as session:
        user_db: SQLAlchemyUserDatabase[User, uuid.UUID] = SQLAlchemyUserDatabase(session, User)
        yield UserManager(user_db)


class UserManager(BaseUserManager[User, uuid.UUID]):
    """Manager d'authentification.

    Les secrets de token de gestion (reset / verify) sont surchargés par
    ``configure_identity`` à partir de la configuration du serveur.
    """

    # Repli de démonstration — remplacés par configure_identity depuis Settings.
    reset_password_token_secret = "spike-reset-secret"  # ruff: ignore[hardcoded-password-string]
    verification_token_secret = "spike-verify-secret"  # ruff: ignore[hardcoded-password-string]

    def parse_id(self, value: str) -> uuid.UUID:
        """Convertit le ``sub`` (string) du JWT en ``uuid.UUID`` (clé primaire)."""
        return uuid.UUID(value)


def configure_identity(
    *,
    cookie_secret: str,
    cookie_lifetime_seconds: int,
    reset_password_secret: str,
    verification_secret: str,
) -> None:
    """Injecte les secrets de session et de gestion de compte depuis la configuration.

    Appelée par la composition root avec les valeurs de ``Settings`` : la
    hiérarchie config.toml → `THEPUROIDC_*` → ``.env`` permet de remplacer
    les valeurs de démonstration sans toucher au code.
    """
    global _cookie_secret, _cookie_lifetime_seconds, _reset_password_secret, _verification_secret
    _cookie_secret = cookie_secret
    _cookie_lifetime_seconds = cookie_lifetime_seconds
    _reset_password_secret = reset_password_secret
    _verification_secret = verification_secret
    UserManager.reset_password_token_secret = reset_password_secret
    UserManager.verification_token_secret = verification_secret


class UserRead(BaseUser[uuid.UUID]):
    """Schéma de lecture d'un utilisateur (pour le routeur de registre)."""


class UserCreate(BaseUserCreate):
    """Schéma de création d'un utilisateur (inscription)."""


def _jwt_strategy() -> JWTStrategy[User, uuid.UUID]:
    return JWTStrategy(
        secret=_cookie_secret,
        lifetime_seconds=_cookie_lifetime_seconds,
        algorithm="HS256",
    )


cookie_backend = AuthenticationBackend(
    name="cookie",
    transport=CookieTransport(cookie_secure=False, cookie_max_age=3600),
    get_strategy=_jwt_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](_manager_dependency, [cookie_backend])

CurrentUser = Annotated[User, Depends(fastapi_users.current_user(active=True))]
CurrentUserOptional = Annotated[
    User | None,
    Depends(fastapi_users.authenticator.current_user(optional=True, active=True)),
]

auth_router = fastapi_users.get_auth_router(cookie_backend)
register_router = fastapi_users.get_register_router(UserRead, UserCreate)


def init_users_db() -> None:
    """Initialise le moteur (SQLite en mémoire partagée) et le session factory."""
    global _session_factory, _engine
    if _session_factory is None:
        from sqlalchemy.ext.asyncio import create_async_engine

        _engine = create_async_engine(
            "sqlite+aiosqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def apply_schema() -> None:
    """Crée la table ``user`` (SQLite en mémoire, spike)."""
    init_users_db()
    if _engine is None:
        raise RuntimeError("application_schema() : moteur non initialisé")
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_users(seed: Mapping[str, Mapping[str, str]]) -> dict[str, User]:
    """Crée ou recharge les comptes décrits par ``seed`` et les retourne par subject.

    Chaque entrée associe un ``subject`` à ses identifiants de connexion
    (``email``, ``password``). Source : ``Settings.identity_seed_users``
    (config.toml / `THEPUROIDC_IDENTITY_SEED_USERS` / ``.env``). Les comptes
    existants sont rechargés plutôt que recréés (idempotent entre démarrages).
    """
    if not seed:
        return {}
    factory = _get_session_factory()
    result: dict[str, User] = {}
    async with factory() as session:
        user_db: SQLAlchemyUserDatabase[User, uuid.UUID] = SQLAlchemyUserDatabase(session, User)
        for subject, credentials in seed.items():
            email = str(credentials["email"])
            password = str(credentials["password"])
            existing = await user_db.get_by_email(email)
            if existing is not None:
                result[subject] = existing
                continue
            user = await UserManager(user_db).create(BaseUserCreate(email=email, password=password))
            result[subject] = user
    return result


_LOGIN_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>ThePurOidc — connexion</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    label {{ display: block; margin: 0.6rem 0 0.2rem; }}
    input {{ width: 100%; padding: 0.4rem; box-sizing: border-box; }}
    button {{ margin-top: 1rem; padding: 0.5rem 1.2rem; }}
    .error {{ color: #b00020; }}
  </style>
</head>
<body>
  <h1>Connexion à ThePurOidc</h1>
  {error}<form method="post" action="/login">
    <input type="hidden" name="next" value="{next}">
    <label>Email <input type="email" name="username" required autofocus></label>
    <label>Mot de passe <input type="password" name="password" required></label>
    <button type="submit">Se connecter</button>
  </form>
  <p><small>Démo : <code>alice@example.com / password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com / password</code> (user)</small></p>
</body>
</html>
"""


def login_router() -> APIRouter:
    """Construit le routeur ``/login`` (formulaire HTML de démonstration)."""
    router = APIRouter(tags=["identity"])

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(next_url: str = Query(default="/", alias="next")) -> str:
        """Affiche le formulaire de connexion (utilisateur démo pré-rempli)."""
        return _LOGIN_PAGE.format(error="", next=html.escape(next_url, quote=True))

    @router.post("/login")
    async def login(
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        next_url: Annotated[str, Form(alias="next")] = "/",
    ) -> RedirectResponse:
        """Authentifie, pose le cookie de session puis redirige vers ``next``."""
        credentials = OAuth2PasswordRequestForm(username=username, password=password)
        factory = _get_session_factory()
        async with factory() as session:
            user_db: SQLAlchemyUserDatabase[User, uuid.UUID] = SQLAlchemyUserDatabase(session, User)
            user = await UserManager(user_db).authenticate(credentials)
            if user is None or not user.is_active:
                return RedirectResponse(f"/login?next={quote(next_url, safe='')}", status_code=302)
            strategy = cookie_backend.get_strategy()
            if inspect.isawaitable(strategy):
                strategy = await strategy
            login_response = await cookie_backend.login(strategy, user)  # type: ignore[arg-type]
            redirect = RedirectResponse(next_url or "/", status_code=302)
            cookie = login_response.headers.get("set-cookie")
            if cookie:
                redirect.headers["set-cookie"] = cookie
            return redirect

    return router
