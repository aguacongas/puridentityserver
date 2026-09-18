"""Client de démonstration : Authorization Code + PKCE (RFC 6749, RFC 7636).

Implémente une *relying party* qui se connecte à un serveur PurIdentityServer :

1. redirection du navigateur vers la page de login du serveur
   (`/login?next=<authorize>`), avec un challenge PKCE S256,
2. l'utilisateur s'authentifie sur le serveur (cookie de session),
3. le serveur redirige vers ``/authorize`` avec le cookie ; le ``code``
   d'autorisation est émis avec le ``sub`` de l'utilisateur connecté,
4. réception du ``code`` d'autorisation sur ``/callback``,
5. échange du code au ``/token`` avec le ``code_verifier``,
6. vérification de l'``id_token`` (signature JWKS, ``aud``, ``nonce``) et
   affichage des claims,
7. appel de ``/userinfo`` avec l'access token Bearer et affichage des claims
   de l'utilisateur renvoyés par le serveur.

Le sample illustre aussi le **RP-Initiated Logout** (OIDC Core 1.0 §5) :

8. ``/logout`` redirige vers l'``end_session_endpoint`` du serveur avec
   l'``id_token_hint`` (l'``id_token`` reçu) et l'URI de sortie
   ``post_logout_redirect_uri`` enregistrée pour ce client,
9. le serveur termine la session (cookie effacé) puis renvoie le navigateur
   vers ``/post-logout`` (``state`` rejoué) où le client purge sa session locale.

Lancement (depuis la racine du dépôt) :

    uv run python samples/pkce-client/app.py

Le client (http://127.0.0.1:5173) est pré-enregistré par défaut sur le
serveur PurIdentityServer ; rien d'autre à configurer pour un démarrage local.
"""

from __future__ import annotations

import base64
import hashlib
import html
import os
import secrets
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
  <title>PurIdentityServer — client démo (Authorization Code + PKCE + UserInfo)</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 42rem; }}
    code {{ background: #f4f4f4; padding: 0.15rem 0.35rem; border-radius: 4px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    a.button {{ display: inline-block; background: #116d8e; color: #fff;
                padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""

_SCOPE = "openid profile email"


class Settings(BaseSettings):
    """Réglages du client de démonstration (env `OIDC_*`, config.toml du sample).

    Hiérarchie : arguments d'init > environnement `OIDC_*` > `config.toml`
    du sample > défauts du code. Le fichier de config est surchargeable
    via `OIDC_SETTINGS_FILE`.
    """

    model_config = SettingsConfigDict(env_prefix="OIDC_", extra="ignore")

    issuer: str = "http://127.0.0.1:8000"
    client_id: str = "sample-pkce-client"
    redirect_uri: str = "http://127.0.0.1:5173/callback"
    post_logout_redirect_uri: str = "http://127.0.0.1:5173/post-logout"
    host: str = "127.0.0.1"
    port: int = 5173

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


def _index_html(settings: Settings) -> str:
    """Page d'accueil : invite à se connecter via le flow Authorization Code."""
    body = f"""
<h1>PurIdentityServer — client démo</h1>
<p>Se connecter avec le flow <strong>Authorization Code + PKCE</strong>
contre le serveur <code>{html.escape(settings.issuer)}</code>.</p>
<p>Client : <code>{html.escape(settings.client_id)}</code></p>
<p><a class="button" href="/login">Se connecter avec PurIdentityServer</a></p>
<p><small>Comptes démo : <code>alice@example.com</code> / <code>password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com</code> / <code>password</code> (user)</small></p>
"""
    return _page(body)


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
    """Échange le code d'autorisation contre un token au endpoint ``/token``."""
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


async def _fetch_userinfo(
    client: httpx.AsyncClient,
    endpoints: dict[str, Any],
    access_token: str,
) -> dict[str, Any]:
    """Récupère les claims utilisateur via ``GET /userinfo`` (OIDC Core §5.3)."""
    endpoint = endpoints.get("userinfo_endpoint")
    if not endpoint:
        raise HTTPException(status_code=502, detail="Discovery sans userinfo_endpoint")
    response = await client.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Échec de l'appel à /userinfo : {response.text}",
        )
    return response.json()


def _verify_id_token(
    id_token: str,
    jwks_uri: str,
    endpoints: dict[str, Any],
    settings: Settings,
    nonce: str,
) -> dict[str, Any]:
    """Vérifie la signature (JWKS, résolution par `kid`) et les claims de l'`id_token`.

    Contrôles : RFC 7519 et OIDC Core §3.1.3.7 (`iss`, `aud`, `nonce`, `exp`).
    """
    algorithms = endpoints.get("id_token_signing_alg_values_supported") or ["RS256"]
    signing_key = pyjwt.PyJWKClient(jwks_uri).get_signing_key_from_jwt(id_token).key
    claims = pyjwt.decode(
        id_token,
        key=signing_key,
        algorithms=algorithms,
        audience=settings.client_id,
        options={"require": ["iss", "exp", "iat", "nonce"]},
    )
    if claims.get("iss") != endpoints["issuer"]:
        raise HTTPException(status_code=502, detail="Issuer inattendu dans l'id_token")
    if claims.get("nonce") != nonce:
        raise HTTPException(status_code=502, detail="Nonce inattendu dans l'id_token")
    return claims


def _claims_table(title: str, description: str, claims: dict[str, Any]) -> str:
    """Affiche une table de claims avec son en-tête."""
    rows = "".join(
        f"<tr><td><code>{html.escape(str(key))}</code></td>"
        f"<td><code>{html.escape(str(value))}</code></td></tr>"
        for key, value in sorted(claims.items())
    )
    description_html = f"<p>{description}</p>" if description else ""
    return f"""
<h2>{title}</h2>
{description_html}
<table>
  <tr><th>Claim</th><th>Valeur</th></tr>
  {rows}
</table>
"""


def _token_html(
    id_claims: dict[str, Any],
    access_token: str,
    expires_in: object,
    userinfo: dict[str, Any],
) -> str:
    """Affiche les claims validés de l'``id_token`` et ceux de ``/userinfo``."""
    body = f"""
<h1>Connecté</h1>
<p><code>id_token</code> vérifié (signature JWKS, <code>aud</code>, <code>nonce</code>).</p>
{_claims_table("id_token (claims vérifiés localement)", "", id_claims)}
{
        _claims_table(
            "UserInfo — endpoint /userinfo (claims filtrés par scopes)",
            "Renvoyés par le serveur avec l'access token Bearer (RFC 6750).",
            userinfo,
        )
    }
<p><code>access_token</code> (expire dans {html.escape(str(expires_in))} s)&nbsp;:</p>
<pre>{html.escape(access_token)}</pre>
<p><a class="button" href="/logout">Se déconnecter (RP-Initiated Logout)</a></p>
<p><a href="/">Retour à l'accueil</a></p>
"""
    return _page(body)


def _post_logout_html(settings: Settings, state: str, ok: bool) -> str:
    """Page affichée sur ``/post-logout`` (URI de retour enregistrée de la démo)."""
    if ok:
        notice = (
            "<p>Le serveur a rejoué le <code>state</code> de la demande "
            "(relie la réponse à la demande de logout).</p>"
        )
    else:
        notice = (
            "<p><strong>Attention :</strong> le <code>state</code> rejoué ne "
            "correspond pas à celui émis par ce client.</p>"
        )
    body = f"""
<h1>Déconnecté</h1>
<p>La session au serveur <code>{html.escape(settings.issuer)}</code> a été
terminée via le RP-Initiated Logout ({html.escape(state) or "sans state"}).</p>
{notice}
<p><a class="button" href="/">Se reconnecter</a></p>
"""
    return _page(body)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI du client de démonstration."""
    app_settings = settings or Settings()
    pending: dict[str, PendingAuth] = {}
    session: dict[str, str] = {}

    app = FastAPI(
        title="PurIdentityServer — client démo (Authorization Code + PKCE + UserInfo)",
        description=(
            "Relying party de démonstration du flow authorization code + PKCE "
            "et de l'endpoint UserInfo."
        ),
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        """Page d'accueil du client de démonstration."""
        return _index_html(app_settings)

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
        """Échange le code, vérifie l'``id_token`` et interroge ``/userinfo``."""
        auth = pending.pop(state, None)
        if auth is None:
            raise HTTPException(status_code=400, detail="État inconnu ou expiré")

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
            token_payload = await _exchange_code(
                client, endpoints, app_settings, code, auth.verifier
            )
            userinfo = await _fetch_userinfo(client, endpoints, token_payload["access_token"])

        claims = _verify_id_token(
            token_payload["id_token"], endpoints["jwks_uri"], endpoints, app_settings, auth.nonce
        )
        session["id_token"] = token_payload["id_token"]
        return HTMLResponse(
            _token_html(
                claims,
                token_payload["access_token"],
                token_payload.get("expires_in"),
                userinfo,
            )
        )

    @app.get("/logout")
    async def logout() -> RedirectResponse:
        """Déclenche le RP-Initiated Logout auprès de l'``end_session_endpoint`` du serveur.

        Transmet l'``id_token_hint`` (l'``id_token`` reçu), l'URI de sortie
        enregistrée et un ``state`` local ; le serveur termine la session
        (cookie purgé) puis renvoie le navigateur vers l'URI de sortie.
        """
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
        end_session = endpoints.get("end_session_endpoint")
        if not end_session:
            session.clear()
            return RedirectResponse(url="/", status_code=302)

        state = _base64url_bytes(16)
        session["logout_state"] = state
        id_token = session.get("id_token")
        params: list[str] = []
        if id_token:
            params.append(f"id_token_hint={quote(id_token, safe='')}")
        params.append(
            f"post_logout_redirect_uri={quote(app_settings.post_logout_redirect_uri, safe='')}"
        )
        params.append(f"state={state}")
        return RedirectResponse(url=f"{end_session}?{'&'.join(params)}", status_code=302)

    @app.get("/post-logout", response_class=HTMLResponse)
    async def post_logout(state: str = "") -> str:
        """URI de retour du logout : purge la session locale et confirme la sortie.

        Vérifie le ``state`` rejoué par le serveur avant de considérer le
        logout comme correspondant à la demande émise par ce client.
        """
        expected = session.get("logout_state")
        session.clear()
        return _post_logout_html(app_settings, state, state == expected)

    return app


def main() -> None:
    """Lance le client de démonstration avec Uvicorn (host/port de ``OIDC_*``)."""
    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
