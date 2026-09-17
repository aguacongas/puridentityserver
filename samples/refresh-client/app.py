"""Client de démonstration : refresh token (RFC 6749 §6) avec rotation.

Implémente une *relying party* qui se connecte à un serveur
PurIdentityServer puis renouvelle ses jetons hors ligne :

1. redirection du navigateur vers la page de login du serveur
   (`/login?next=<authorize>`), avec challenge PKCE S256 et scop
   `offline_access` (demande un refresh token),
2. l'utilisateur s'authentifie sur le serveur (cookie de session),
3. le serveur redirige vers ``/authorize`` avec le cookie ; le ``code``
   d'autorisation est émis avec le ``sub`` de l'utilisateur connecté,
4. réception du ``code`` d'autorisation sur ``/callback``,
5. échange du code au ``/token`` avec le ``code_verifier`` : le serveur
   retourne access_token, id_token **et refresh_token**,
6. appui sur « Rafraîchir » : ``POST /token`` avec `grant_type=refresh_token`
   et le refresh token ; le serveur **consomme l'ancien jeton** et en
   émet un nouveau (rotation), puis retourne des jetons frais,
7. nouvel appui sur « Rafraîchir » avec un jeton déjà consommé : le
   serveur répond ``400 invalid_grant`` (un jeton n'est jamais réutilisable).

Lancement (à la racine du dépôt, serveur PurIdentityServer déjà démarré
sur le port ``8000`` par défaut) :

    uv run python samples/refresh-client/app.py
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote, urlencode

import httpx
import jwt as pyjwt
import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

_HTTP_TIMEOUT = 10

_HTML_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — client démo (Refresh Token + rotation)</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 42rem; }}
    code {{ background: #f4f4f4; padding: 0.15rem 0.35rem; border-radius: 4px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    a.button, button {{ display: inline-block; background: #116d8e; color: #fff;
                 padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none;
                 border: 0; font-size: 1rem; cursor: pointer; }}
    pre {{ white-space: pre-wrap; word-break: break-all; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""

_SCOPE = "openid profile email offline_access"


class Settings(BaseSettings):
    """Réglages du client de démonstration (env `OIDC_*`, config.toml du sample).

    Hiérarchie : arguments d'init > environnement `OIDC_*` > `config.toml`
    du sample > défauts du code. Le fichier de config est surchargeable
    via `OIDC_SETTINGS_FILE`.
    """

    model_config = SettingsConfigDict(env_prefix="OIDC_", extra="ignore")

    issuer: str = "http://127.0.0.1:8000"
    client_id: str = "sample-refresh-client"
    redirect_uri: str = "http://127.0.0.1:5174/callback"
    host: str = "127.0.0.1"
    port: int = 5174

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Charge la table `[settings]` du `config.toml` situé à côté du script."""
        default_path = Path(__file__).resolve().parent / "config.toml"
        toml_path = Path(os.environ.get("OIDC_SETTINGS_FILE", str(default_path)))
        toml_settings = TomlConfigSettingsSource(
            settings_cls, toml_file=toml_path, toml_table_header=("settings",)
        )
        return (init_settings, env_settings, toml_settings, dotenv_settings, file_secret_settings)


@dataclass(frozen=True, slots=True)
class PendingAuth:
    """Mémorise le ``code_verifier`` et le ``nonce`` d'un login en cours."""

    verifier: str
    nonce: str


@dataclass(slots=True)
class IssuedTokens:
    """Jetons en cours de session, avec le compteur de rafraîchissements."""

    access_token: str
    id_token: str
    refresh_token: str
    refreshes: int = 0


_session: IssuedTokens | None = None


def _base64url_bytes(size: int) -> str:
    """Produit une chaîne base64url sans padding à partir de ``size`` octets aléatoires."""
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).rstrip(b"=").decode("ascii")


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 (RFC 7636 §4.2) d'un ``code_verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


async def _discovery(client: httpx.AsyncClient, settings: Settings) -> dict[str, Any]:
    """Récupère le document de discovery du serveur (endpoints et algorithmes)."""
    url = f"{settings.issuer.rstrip('/')}/.well-known/openid-configuration"
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


def _page(body: str) -> str:
    """Enveloppe un contenu HTML dans le gabarit de la démo."""
    return _HTML_PAGE.format(body=body)


def _ttl_seconds(jwt_token: str) -> int:
    """Temps restant en secondes d'un JWT (0 si décodage impossible)."""
    claims = pyjwt.decode(jwt_token, options={"verify_signature": False})
    return max(0, int(claims["exp"]) - int(time.time()))


def _verify_id_token(
    id_token: str,
    endpoints: dict[str, Any],
    settings: Settings,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Vérifie la signature (JWKS) et les claims d'un ``id_token``.

    Le ``nonce`` n'est exigé que pour l'``id_token`` du flow interactif ;
    celui d'un refresh (OIDC Core §12.2) n'en porte pas.
    """
    algorithms = endpoints.get("id_token_signing_alg_values_supported") or ["RS256"]
    signing_key = pyjwt.PyJWKClient(endpoints["jwks_uri"]).get_signing_key_from_jwt(id_token).key
    required = ["iss", "exp", "iat", "nonce"] if nonce is not None else ["iss", "exp", "iat"]
    claims = pyjwt.decode(
        id_token,
        key=signing_key,
        algorithms=algorithms,
        audience=settings.client_id,
        options={"require": required},
    )
    if claims.get("iss") != endpoints["issuer"]:
        raise HTTPException(status_code=502, detail="Issuer inattendu dans l'id_token")
    if nonce is not None and claims.get("nonce") != nonce:
        raise HTTPException(status_code=502, detail="Nonce inattendu dans l'id_token")
    return claims


def _index_html(settings: Settings) -> str:
    """Page d'accueil : invite à se connecter via le flow Authorization Code."""
    body = f"""
<h1>PurIdentityServer — client démo</h1>
<p>Se connecter avec le flow <strong>Authorization Code + PKCE</strong>
(<code>offline_access</code>) contre le serveur
<code>{html.escape(settings.issuer)}</code>.</p>
<p>Client : <code>{html.escape(settings.client_id)}</code></p>
<p><a class="button" href="/login">Se connecter avec PurIdentityServer</a></p>
<p><small>Comptes démo : <code>alice@example.com</code> / <code>password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com</code> / <code>password</code> (user)</small></p>
"""
    return _page(body)


def _tokens_html(
    endpoints: dict[str, Any],
    settings: Settings,
    tokens: IssuedTokens,
    message: str = "",
) -> str:
    """Affiche les jetons courants et le bouton de rafraîchissement."""
    notice = (
        f'<p style="color:#1a7f37"><strong>{html.escape(message)}</strong></p>' if message else ""
    )
    claims = _verify_id_token(tokens.id_token, endpoints, settings)
    return _page(
        f"""
<h1 style="display: inline-block">Connecté</h1> {notice}
<p>Rafraîchissements : <strong>{tokens.refreshes}</strong>
<a href="/logout">[réinitialiser la session]</a></p>
<p>Session : <code>sub</code> = <code>{html.escape(str(claims.get("sub")))}</code></p>
<h2>access_token (expire dans {_ttl_seconds(tokens.access_token)} s)</h2>
<pre>{html.escape(tokens.access_token)}</pre>
<h2>refresh_token (exposé uniquement pour la démo)</h2>
<pre>{html.escape(tokens.refresh_token)}</pre>
<form method="post" action="/refresh">
  <button type="submit">Rafraîchir les jetons (grant_type=refresh_token)</button>
</form>
<p><small>Chaque rafraîchissement consomme l'ancien refresh_token et en émet un nouveau ;
rejouer un jeton déjà consommé produit une erreur <code>400 invalid_grant</code>.</small></p>
"""
    )


def _authorization_url(
    endpoints: dict[str, Any], settings: Settings, state: str, nonce: str, challenge: str
) -> str:
    """Construit l'URL de ``/authorize`` avec les paramètres du flow."""
    params = urlencode(
        {
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "scope": _SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{endpoints['authorization_endpoint']}?{params}"


async def _exchange_code(
    client: httpx.AsyncClient,
    endpoints: dict[str, Any],
    settings: Settings,
    code: str,
    verifier: str,
) -> dict[str, Any]:
    """Échange le code d'autorisation contre les jetons (dont refresh_token)."""
    response = await client.post(
        endpoints["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.redirect_uri,
            "client_id": settings.client_id,
            "code_verifier": verifier,
        },
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Échec de l'échange du code : {response.text}",
        )
    return response.json()


async def _refresh(
    client: httpx.AsyncClient,
    endpoints: dict[str, Any],
    settings: Settings,
    refresh_token: str,
) -> dict[str, Any]:
    """Renouvelle les jetons au endpoint ``/token`` (grant_type=refresh_token)."""
    response = await client.post(
        endpoints["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.client_id,
        },
    )
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Échec du refresh : {response.text}",
        )
    return response.json()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI du client de démonstration."""
    app_settings = settings or Settings()
    pending: dict[str, PendingAuth] = {}

    app = FastAPI(
        title="PurIdentityServer — client démo (Refresh Token + rotation)",
        description=(
            "Relying party de démonstration du refresh token (RFC 6749 §6) "
            "avec rotation et rejet de réutilisation."
        ),
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        """Page d'accueil : invite à se connecter (ou montre les jetons courants)."""
        if _session is None:
            return _index_html(app_settings)
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
        return _tokens_html(endpoints, app_settings, _session)

    @app.get("/login")
    async def login() -> RedirectResponse:
        """Initialise un login PKCE puis redirige le navigateur vers la page de login du serveur."""
        verifier = _base64url_bytes(32)
        challenge = _s256_challenge(verifier)
        state = _base64url_bytes(32)
        nonce = _base64url_bytes(16)
        pending[state] = PendingAuth(verifier=verifier, nonce=nonce)

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
        authorize_url = _authorization_url(endpoints, app_settings, state, nonce, challenge)
        server_login_url = (
            f"{app_settings.issuer.rstrip('/')}/login?next={quote(authorize_url, safe='')}"
        )
        return RedirectResponse(url=server_login_url, status_code=302)

    @app.get("/callback")
    async def callback(
        code: Annotated[str, Query()], state: Annotated[str, Query()]
    ) -> HTMLResponse:
        """Échange le code, vérifie l'``id_token`` et stocke les jetons de session."""
        auth = pending.pop(state, None)
        if auth is None:
            raise HTTPException(status_code=400, detail="État inconnu ou expiré")

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
            token_payload = await _exchange_code(
                client, endpoints, app_settings, code, auth.verifier
            )

        _verify_id_token(token_payload["id_token"], endpoints, app_settings, nonce=auth.nonce)
        if not token_payload.get("refresh_token"):
            raise HTTPException(status_code=502, detail="Le serveur n'a pas émis de refresh_token")
        global _session
        _session = IssuedTokens(
            access_token=token_payload["access_token"],
            id_token=token_payload["id_token"],
            refresh_token=token_payload["refresh_token"],
        )
        return HTMLResponse(_tokens_html(endpoints, app_settings, _session))

    @app.post("/refresh")
    async def refresh() -> HTMLResponse:
        """Renouvelle les jetons via le refresh token ; échoue s'il est déjà consommé."""
        if _session is None:
            raise HTTPException(status_code=400, detail="Aucune session : connectez-vous d'abord")
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
            payload = await _refresh(client, endpoints, app_settings, _session.refresh_token)
        _session.access_token = payload["access_token"]
        _session.id_token = payload["id_token"]
        _session.refresh_token = payload["refresh_token"]
        _session.refreshes += 1
        return HTMLResponse(
            _tokens_html(endpoints, app_settings, _session, "Jetons rafraîchis (rotation OK)")
        )

    @app.get("/logout")
    async def logout() -> RedirectResponse:
        """Réinitialise la session du client (supprime les jetons de démonstration)."""
        global _session
        _session = None
        return RedirectResponse(url="/", status_code=302)

    return app


def main() -> None:
    """Lance le client de démonstration avec Uvicorn (host/port de ``OIDC_*``)."""
    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
