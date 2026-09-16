"""Configuration FastAPI Users — backend cookie (JWT rotatif) + routes /auth.

Fournit l'identité utilisateur du serveur OIDC :

- ``auth_router``            : routes ``/auth/cookie/login``, ``/logout``, ``/refresh``
- ``register_router``        : route ``/auth/register``
- ``login_router``           : page ``/login`` (formulaire HTML, spike navigateur)
- ``CurrentUser``            : dependency d'utilisateur authentifié (requis)
- ``CurrentUserOptional``    : dependency d'utilisateur authentifié (facultatif)
- ``apply_schema``           : crée la table ``user`` (SQLite en mémoire, spike)
- ``seed_users``             : crée les comptes décrits par ``Settings.identity_seed_users``
- ``configure_identity``     : injecte les KeyManagers (config.toml / THEPUROIDC_* / .env)

Aucun secret statique ne signe les jetons : cookies de session
(``KeyUse.SESSION``), jetons de réinitialisation de mot de passe
(``KeyUse.RESET``) et de vérification de compte (``KeyUse.VERIFY``) sont
signés RS256 par un ``RotatingTokenSigner`` dédié à chaque famille, sur la
base d'un KeyManager rotatif distinct des clés de signature des tokens OIDC.

Note spike : la base utilisateurs est en mémoire (``StaticPool``) ; en
production elle sera remplacée par un vrai magasin (DSN dédié ou la base
partagée ``KEY_STORE_DSN``).
"""

from __future__ import annotations

import html
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from typing import Annotated
from urllib.parse import parse_qs, quote, urlparse

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import BaseUserManager, FastAPIUsers, exceptions
from fastapi_users.authentication import AuthenticationBackend, CookieTransport
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.manager import (
    RESET_PASSWORD_TOKEN_AUDIENCE,
    VERIFY_USER_TOKEN_AUDIENCE,
)
from fastapi_users.schemas import BaseUser, BaseUserCreate
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from thepuroidc.identity.rotating_signer import RotatingTokenSigner
from thepuroidc.identity.session_strategy import SessionJWTStrategy
from thepuroidc.identity.user import Base, User
from thepuroidc.interfaces.domain.jwks import KeyManager

# ── configuration d'exécution (injectée par ``configure_identity``) ─────────
# Valeurs de repli de démonstration : la composition root (``server.py``)
# injecte celles de ``Settings`` (config.toml, ``THEPUROIDC_*``, ``.env``).
# Chaque famille de jetons privés (session / reset / verify) possède son
# propre signataire rotatif, jamais publié dans le JWKS.
_session_signer: RotatingTokenSigner | None = None
_reset_signer: RotatingTokenSigner | None = None
_verify_signer: RotatingTokenSigner | None = None
_cookie_lifetime_seconds = 3600
_NOT_CONFIGURED = "configure_identity() n'a pas encore été appelé"

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
    """Manager d'authentification — tokens de gestion signés en RS256 rotatif.

    Les jetons ``request_verify``/``verify`` et ``forgot_password``/
    ``reset_password`` sont signés par des ``RotatingTokenSigner`` dédiés
    (``KeyUse.VERIFY`` / ``KeyUse.RESET``) injectés par ``configure_identity`` :
    plus aucun secret statique en configuration.
    """

    reset_password_token_lifetime_seconds = 3600
    verification_token_lifetime_seconds = 3600

    def parse_id(self, value: str) -> uuid.UUID:
        """Convertit le ``sub`` (string) du JWT en ``uuid.UUID`` (clé primaire)."""
        return uuid.UUID(value)

    async def request_verify(self, user: User, request: Request | None = None) -> None:
        """Émet un jeton de vérification signé avec la clé ``verify`` active.

        Déclenche ``on_after_request_verify`` en cas de succès.
        """
        if _verify_signer is None:
            raise RuntimeError(_NOT_CONFIGURED)
        if not user.is_active:
            raise exceptions.UserInactive()
        if user.is_verified:
            raise exceptions.UserAlreadyVerified()

        token_data = {
            "sub": str(user.id),
            "email": user.email,
            "aud": VERIFY_USER_TOKEN_AUDIENCE,
        }
        token = await _verify_signer.write(token_data, self.verification_token_lifetime_seconds)
        await self.on_after_request_verify(user, token, request)

    async def verify(self, token: str, request: Request | None = None) -> User:
        """Valide un jeton de vérification (signature, ``aud``, email) et active le compte."""
        if _verify_signer is None:
            raise RuntimeError(_NOT_CONFIGURED)
        data = await _verify_signer.read(token)
        if data is None:
            raise exceptions.InvalidVerifyToken()

        try:
            user_id = str(data["sub"])
            email = str(data["email"])
        except KeyError:
            raise exceptions.InvalidVerifyToken() from None

        try:
            user = await self.get_by_email(email)
        except exceptions.UserNotExists:
            raise exceptions.InvalidVerifyToken() from None

        try:
            parsed_id = self.parse_id(user_id)
        except exceptions.InvalidID:
            raise exceptions.InvalidVerifyToken() from None

        if parsed_id != user.id:
            raise exceptions.InvalidVerifyToken()

        if user.is_verified:
            raise exceptions.UserAlreadyVerified()

        verified_user = await self._update(user, {"is_verified": True})

        await self.on_after_verify(verified_user, request)

        return verified_user

    async def forgot_password(self, user: User, request: Request | None = None) -> None:
        """Émet un jeton de réinitialisation signé avec la clé ``reset`` active.

        Déclenche ``on_after_forgot_password`` en cas de succès.
        """
        if _reset_signer is None:
            raise RuntimeError(_NOT_CONFIGURED)
        if not user.is_active:
            raise exceptions.UserInactive()

        token_data = {
            "sub": str(user.id),
            "password_fgpt": self.password_helper.hash(user.hashed_password),
            "aud": RESET_PASSWORD_TOKEN_AUDIENCE,
        }
        token = await _reset_signer.write(token_data, self.reset_password_token_lifetime_seconds)
        await self.on_after_forgot_password(user, token, request)

    async def reset_password(
        self, token: str, password: str, request: Request | None = None
    ) -> User:
        """Valide un jeton de réinitialisation et met à jour le mot de passe."""
        if _reset_signer is None:
            raise RuntimeError(_NOT_CONFIGURED)
        data = await _reset_signer.read(token)
        if data is None:
            raise exceptions.InvalidResetPasswordToken()

        try:
            user_id = str(data["sub"])
            password_fingerprint = str(data["password_fgpt"])
        except KeyError:
            raise exceptions.InvalidResetPasswordToken() from None

        try:
            parsed_id = self.parse_id(user_id)
        except exceptions.InvalidID:
            raise exceptions.InvalidResetPasswordToken() from None

        user = await self.get(parsed_id)

        valid_password_fingerprint, _ = self.password_helper.verify_and_update(
            user.hashed_password, password_fingerprint
        )
        if not valid_password_fingerprint:
            raise exceptions.InvalidResetPasswordToken()

        if not user.is_active:
            raise exceptions.UserInactive()

        updated_user = await self._update(user, {"password": password})

        await self.on_after_reset_password(user, request)

        return updated_user


def configure_identity(
    *,
    session_key_manager: KeyManager,
    reset_token_key_manager: KeyManager,
    verification_token_key_manager: KeyManager,
    cookie_lifetime_seconds: int,
    session_rotation_days: int = 90,
    session_grace_period_days: int = 7,
) -> None:
    """Injecte les KeyManagers rotatifs (session, reset, verify) depuis la configuration.

    Appelée par la composition root avec les valeurs de ``Settings`` : la
    hiérarchie config.toml → `THEPUROIDC_*` → ``.env`` permet de remplacer
    les valeurs de démonstration sans toucher au code. Chaque famille de
    jetons privés est signée RS256 par un ``RotatingTokenSigner`` dédié,
    jamais un secret statique : seules les durées et la politique de
    rotation sont injectées ici.
    """
    global _session_signer, _reset_signer, _verify_signer
    global _cookie_lifetime_seconds
    _session_signer = RotatingTokenSigner(
        session_key_manager,
        token_audience=["fastapi-users:auth"],
        rotation_days=session_rotation_days,
        grace_period_days=session_grace_period_days,
    )
    _reset_signer = RotatingTokenSigner(
        reset_token_key_manager,
        token_audience=[RESET_PASSWORD_TOKEN_AUDIENCE],
        rotation_days=session_rotation_days,
        grace_period_days=session_grace_period_days,
    )
    _verify_signer = RotatingTokenSigner(
        verification_token_key_manager,
        token_audience=[VERIFY_USER_TOKEN_AUDIENCE],
        rotation_days=session_rotation_days,
        grace_period_days=session_grace_period_days,
    )
    _cookie_lifetime_seconds = cookie_lifetime_seconds


def _session_strategy(lifetime_seconds: int | None = None) -> SessionJWTStrategy[User, uuid.UUID]:
    """Construit la stratégie de session, avec la durée demandée (défaut serveur sinon)."""
    if _session_signer is None:
        raise RuntimeError(_NOT_CONFIGURED)
    return SessionJWTStrategy(
        signer=_session_signer,
        lifetime_seconds=(
            lifetime_seconds if lifetime_seconds is not None else _cookie_lifetime_seconds
        ),
    )


cookie_backend = AuthenticationBackend(
    name="cookie",
    transport=CookieTransport(cookie_secure=False, cookie_max_age=3600),
    get_strategy=_session_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](_manager_dependency, [cookie_backend])


class UserRead(BaseUser[uuid.UUID]):
    """Schéma de lecture d'un utilisateur (pour le routeur de registre)."""


class UserCreate(BaseUserCreate):
    """Schéma de création d'un utilisateur (inscription)."""


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
    {client_hidden}<label>Email <input type="email" name="username" required autofocus></label>
    <label>Mot de passe <input type="password" name="password" required></label>
    <button type="submit">Se connecter</button>
  </form>
  <p><small>Démo : <code>alice@example.com / password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com / password</code> (user)</small></p>
</body>
</html>
"""


def _client_id_from_next(next_url: str) -> str:
    """Extrait ``client_id`` de la query de l'URL de retour (RFC 6749 §4.1.1)."""
    query = urlparse(next_url).query
    return parse_qs(query).get("client_id", [""])[0]


async def _resolve_cookie_lifetime(
    client_id: str,
    next_url: str,
    resolver: Callable[[str], Awaitable[int | None]] | None,
    default_lifetime: int,
) -> int:
    """Durée du cookie pour le client du flow, sinon la durée serveur par défaut."""
    resolved_client = client_id or _client_id_from_next(next_url)
    lifetime = default_lifetime
    if resolved_client and resolver is not None:
        client_lifetime = await resolver(resolved_client)
        if client_lifetime is not None and client_lifetime > 0:
            lifetime = client_lifetime
    return lifetime


def login_router(
    resolve_session_lifetime: Callable[[str], Awaitable[int | None]] | None = None,
) -> APIRouter:
    """Construit le routeur ``/login`` (formulaire HTML de démonstration).

    ``resolve_session_lifetime`` permet d'appliquer une durée de session
    cookie par client (ex. ``session_lifetime_seconds`` du client) : le
    ``client_id`` du flow est transmis dans le champ caché (lorsqu'il est
    présent dans l'URL de retour) et reconduit par le formulaire.
    """
    router = APIRouter(tags=["identity"])

    @router.get("/login", response_class=HTMLResponse)
    async def login_page(
        next_url: Annotated[str, Query(alias="next")] = "/",
    ) -> str:
        """Affiche le formulaire de connexion (client_id du flow en champ caché)."""
        client_id = _client_id_from_next(next_url)
        hidden = (
            f'<input type="hidden" name="client_id" value="{html.escape(client_id)}">'
            if client_id
            else ""
        )
        return _LOGIN_PAGE.format(
            error="", next=html.escape(next_url, quote=True), client_hidden=hidden
        )

    @router.post("/login")
    async def login(
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        next_url: Annotated[str, Form(alias="next")] = "/",
        client_id: Annotated[str, Form()] = "",
    ) -> RedirectResponse:
        """Authentifie, pose le cookie de session puis redirige vers ``next``.

        La durée du cookie est celle du client du flow si elle est
        configurée (sinon la durée serveur par défaut).
        """
        credentials = OAuth2PasswordRequestForm(username=username, password=password)
        factory = _get_session_factory()
        async with factory() as session:
            user_db: SQLAlchemyUserDatabase[User, uuid.UUID] = SQLAlchemyUserDatabase(session, User)
            user = await UserManager(user_db).authenticate(credentials)
            if user is None or not user.is_active:
                return RedirectResponse(f"/login?next={quote(next_url, safe='')}", status_code=302)

            lifetime = await _resolve_cookie_lifetime(
                client_id, next_url, resolve_session_lifetime, _cookie_lifetime_seconds
            )

            strategy = _session_strategy(lifetime_seconds=lifetime)
            backend = AuthenticationBackend(
                name=cookie_backend.name,
                transport=CookieTransport(cookie_secure=False, cookie_max_age=lifetime),
                get_strategy=lambda: strategy,
            )
            login_response = await backend.login(strategy, user)
            redirect = RedirectResponse(next_url or "/", status_code=302)
            cookie = login_response.headers.get("set-cookie")
            if cookie:
                redirect.headers["set-cookie"] = cookie
            return redirect

    return router
