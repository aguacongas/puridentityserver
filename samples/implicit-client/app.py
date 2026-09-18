"""Client de démonstration : Implicit flow (OIDC Core 1.0 §3.2).

Implémente une *relying party* dont les jetons sont remis **directement
par l'endpoint d'autorisation**, dans le *fragment* de l'URL de
redirection (jamais dans la query string, RFC 6749 §4.2.2) :

1. redirection du navigateur vers la page de login du serveur
   (`/login?next=<authorize>`), avec ``response_type=id_token token``,
   un ``state`` et un ``nonce`` (obligatoire dès qu'un ``id_token``
   est émis),
2. l'utilisateur s'authentifie sur le serveur (cookie de session),
3. le serveur redirige vers ``/authorize`` avec le cookie, puis vers la
   ``redirect_uri`` en plaçant ``id_token`` et ``access_token`` dans le
   **fragment** de l'URL,
4. la page de callback lit le fragment côté navigateur (JavaScript) et
   le transmet au client (``POST /collect``) — les tokens ne transpirent
   jamais par la query string,
5. le client vérifie l'``id_token`` (signature JWKS, ``aud``, ``iss``,
   ``nonce``) **et** le lien ``at_hash`` avec l'access token (OIDC Core
   1.0 §3.2.2.11),
6. appel de ``/userinfo`` avec l'access token Bearer et affichage des
   claims de l'utilisateur.

Le sample illustre aussi le **RP-Initiated Logout** (OIDC Core 1.0 §5) :

7. ``/logout`` redirige vers l'``end_session_endpoint`` du serveur avec
   l'``id_token_hint`` (l'``id_token`` reçu) et l'URI de sortie
   ``post_logout_redirect_uri`` enregistrée pour ce client,
8. le serveur termine la session (cookie effacé) puis renvoie le navigateur
   vers ``/post-logout`` (``state`` rejoué) où le client purge sa session locale.

Contrairement au flow Authorization Code, aucun échange au ``/token``
n'a lieu : les jetons arrivent en une seule requête, dans le fragment.

Lancement (à la racine du dépôt, serveur PurIdentityServer déjà démarré
sur le port ``8000`` par défaut) :

    uv run python samples/implicit-client/app.py
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
from fastapi import FastAPI, Form, HTTPException
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
  <title>PurIdentityServer — client démo (Implicit flow)</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 42rem; }}
    code {{ background: #f4f4f4; padding: 0.15rem 0.35rem; border-radius: 4px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }}
    a.button {{ display: inline-block; background: #116d8e; color: #fff;
                padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; }}
    pre {{ white-space: pre-wrap; word-break: break-all; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""

_CALLBACK_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — remise des jetons</title>
</head>
<body>
  <p>Réception de la réponse d'autorisation (fragment)…</p>
  <script type="text/javascript">
    var params = new URLSearchParams(window.location.hash.substring(1));
    fetch("/collect", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    }).then(function (response) { return response.text(); }).then(function (html) {
      document.open();
      document.write(html);
      document.close();
    });
  </script>
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
    client_id: str = "sample-implicit-client"
    redirect_uri: str = "http://127.0.0.1:5175/callback"
    post_logout_redirect_uri: str = "http://127.0.0.1:5175/post-logout"
    host: str = "127.0.0.1"
    port: int = 5175

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
    """Mémorise le ``nonce`` associé à un login en cours."""

    nonce: str


def _base64url_bytes(size: int) -> str:
    """Produit une chaîne base64url sans padding à partir de ``size`` octets aléatoires."""
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).rstrip(b"=").decode("ascii")


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
    """Page d'accueil : invite à se connecter via le flow Implicit."""
    body = f"""
<h1>PurIdentityServer — client démo</h1>
<p>Se connecter avec le flow <strong>Implicit</strong>
(<code>response_type=id_token token</code>) contre le serveur
<code>{html.escape(settings.issuer)}</code>.</p>
<p>Client : <code>{html.escape(settings.client_id)}</code></p>
<p>Les jetons sont remis par l'endpoint d'autorisation dans le
<strong>fragment</strong> de l'URL de redirection, puis transmis au client
par une petite page JavaScript (jamais par la query string).</p>
<p><a class="button" href="/login">Se connecter avec PurIdentityServer</a></p>
<p><small>Comptes démo : <code>alice@example.com</code> / <code>password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com</code> / <code>password</code> (user)</small></p>
"""
    return _page(body)


def _authorization_url(
    endpoints: dict[str, Any], settings: Settings, state: str, nonce: str
) -> str:
    """Construit l'URL de ``/authorize`` pour le flow Implicit (id_token token)."""
    params = urlencode(
        {
            "response_type": "id_token token",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "scope": _SCOPE,
            "state": state,
            "nonce": nonce,
        }
    )
    return f"{endpoints['authorization_endpoint']}?{params}"


def _jwt_alg(token: str) -> str:
    """Algorithme JWS (``alg``) annoncé dans l'en-tête déchiffré du jeton."""
    return str(pyjwt.get_unverified_header(token).get("alg", "RS256"))


def _hash_artefact(value: str, algorithm: str) -> str:
    """Re-calcule ``at_hash`` / ``c_hash`` attendu (OIDC Core 1.0 §3.3.2.11).

    Moitié gauche du digest SHA-2 (256/384/512 selon l'algorithme JWS),
    encodée base64url sans padding — identique à la production du serveur.
    """
    digest = hashlib.new(f"sha{algorithm[-3:]}", value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def _verify_id_token(
    id_token: str,
    access_token: str,
    endpoints: dict[str, Any],
    settings: Settings,
    nonce: str,
) -> dict[str, Any]:
    """Vérifie la signature (JWKS) et les claims de l'``id_token`` du flow Implicit.

    Contrôles : OIDC Core §3.2.2.10 (`iss`, `aud`, `nonce`, `exp`) **et** le
    lien ``at_hash`` avec l'access token émis dans le même fragment (§3.2.2.11).
    """
    algorithms = endpoints.get("id_token_signing_alg_values_supported") or ["RS256"]
    signing_key = pyjwt.PyJWKClient(endpoints["jwks_uri"]).get_signing_key_from_jwt(id_token).key
    claims = pyjwt.decode(
        id_token,
        key=signing_key,
        algorithms=algorithms,
        audience=settings.client_id,
        options={"require": ["iss", "exp", "iat", "nonce", "at_hash"]},
    )
    if claims.get("iss") != endpoints["issuer"]:
        raise HTTPException(status_code=502, detail="Issuer inattendu dans l'id_token")
    if claims.get("nonce") != nonce:
        raise HTTPException(status_code=502, detail="Nonce inattendu dans l'id_token")
    expected = _hash_artefact(access_token, _jwt_alg(id_token))
    if claims.get("at_hash") != expected:
        raise HTTPException(status_code=502, detail="at_hash incohérent avec l'access_token")
    return claims


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


def _tokens_html(
    id_claims: dict[str, Any],
    access_token: str,
    expires_in: object,
    userinfo: dict[str, Any],
) -> str:
    """Affiche les claims validés de l'``id_token`` et ceux de ``/userinfo``."""
    body = f"""
<h1>Connecté</h1>
<p><code>id_token</code> vérifié (signature JWKS, <code>aud</code>,
<code>nonce</code>, lien <code>at_hash</code> avec l'access token).</p>
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
        title="PurIdentityServer — client démo (Implicit flow)",
        description=(
            "Relying party de démonstration du flow Implicit (OIDC Core 1.0 §3.2) "
            "avec remise des jetons dans le fragment et vérification at_hash."
        ),
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        """Page d'accueil du client de démonstration."""
        return _index_html(app_settings)

    @app.get("/login")
    async def login() -> RedirectResponse:
        """Initialise un login implicit puis redirige vers la page de login du serveur."""
        state = _base64url_bytes(32)
        nonce = _base64url_bytes(16)
        pending[state] = PendingAuth(nonce=nonce)

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
        authorize_url = _authorization_url(endpoints, app_settings, state, nonce)
        server_login_url = (
            f"{app_settings.issuer.rstrip('/')}/login?next={quote(authorize_url, safe='')}"
        )
        return RedirectResponse(url=server_login_url, status_code=302)

    @app.get("/callback", response_class=HTMLResponse)
    async def callback() -> str:
        """Page de réception : le navigateur lit le fragment puis le transmet à /collect."""
        return _CALLBACK_PAGE

    @app.post("/collect")
    async def collect(
        id_token: Annotated[str, Form()],
        access_token: Annotated[str, Form()],
        state: Annotated[str, Form()],
        expires_in: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        """Reçoit les jetons du fragment, les vérifie et interroge ``/userinfo``."""
        auth = pending.pop(state, None)
        if auth is None:
            raise HTTPException(status_code=400, detail="État inconnu ou expiré")

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
            userinfo = await _fetch_userinfo(client, endpoints, access_token)

        claims = _verify_id_token(id_token, access_token, endpoints, app_settings, auth.nonce)
        session["id_token"] = id_token
        return HTMLResponse(_tokens_html(claims, access_token, expires_in, userinfo))

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
