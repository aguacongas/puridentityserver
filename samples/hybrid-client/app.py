"""Client de démonstration : Hybrid flow (OIDC Core 1.0 §3.3).

Implémente une *relying party* combinant l'Authorization Code flow
(RFC 6749 §4.1, PKCE RFC 7636) et l'Implicit flow : l'endpoint
d'autorisation remet un ``code`` **et** des jetons ``id_token`` +
``access_token`` dans le **fragment** de l'URL de redirection
(response_type ``code id_token token``) :

1. redirection du navigateur vers la page de login du serveur
   (`/login?next=<authorize>`), avec ``response_type=code id_token token``,
   un ``state``/``nonce`` et un ``code_challenge`` PKCE S256,
2. l'utilisateur s'authentifie sur le serveur (cookie de session),
3. le serveur redirige vers ``/authorize`` puis vers la ``redirect_uri`` en
   plaçant ``code``, ``id_token``, ``access_token`` et ``state`` dans le
   **fragment** de l'URL — le ``id_token`` porte ``at_hash`` (lien avec
   l'access token) et ``c_hash`` (lien avec le code, OIDC Core §3.3.2.11),
4. la page de callback lit le fragment côté navigateur (JavaScript) et le
   transmet au client (``POST /collect``),
5. le client vérifie l'``id_token`` (signature JWKS, ``aud``, ``nonce``,
   ``at_hash``, ``c_hash``) **puis échange le code** au ``/token`` en
   présentant le ``code_verifier`` PKCE : il obtient un second ``id_token``
   et un ``access_token`` final,
6. appel de ``/userinfo`` avec l'access token final et affichage des claims.

Le flow Hybrid permet au client de consommer aussitôt les claims du
``id_token`` (rapidité) tout en conservant le code pour obtenir des jetons
finaux en toute sécurité (tokens finaux jamais exposés au navigateur au
niveau de l'endpoint d'autorisation).

Lancement (à la racine du dépôt, serveur PurIdentityServer déjà démarré
sur le port ``8000`` par défaut) :

    uv run python samples/hybrid-client/app.py
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
  <title>PurIdentityServer — client démo (Hybrid flow)</title>
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
    client_id: str = "sample-hybrid-client"
    redirect_uri: str = "http://127.0.0.1:5176/callback"
    host: str = "127.0.0.1"
    port: int = 5176

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
    """Mémorise le ``nonce`` et le ``code_verifier`` PKCE d'un login en cours."""

    nonce: str
    verifier: str


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
    """Page d'accueil : invite à se connecter via le flow Hybrid."""
    body = f"""
<h1>PurIdentityServer — client démo</h1>
<p>Se connecter avec le flow <strong>Hybrid</strong>
(<code>response_type=code id_token token</code>) contre le serveur
<code>{html.escape(settings.issuer)}</code>.</p>
<p>Client : <code>{html.escape(settings.client_id)}</code></p>
<p>L'endpoint d'autorisation remet un <code>code</code> et des jetons
(<code>id_token</code> + <code>access_token</code>) dans le <strong>fragment</strong>
de l'URL de redirection ; le code est ensuite échangé au <code>/token</code>
avec PKCE pour obtenir les jetons finaux.</p>
<p><a class="button" href="/login">Se connecter avec PurIdentityServer</a></p>
<p><small>Comptes démo : <code>alice@example.com</code> / <code>password</code> (admin)
    &nbsp;·&nbsp; <code>bob@example.com</code> / <code>password</code> (user)</small></p>
"""
    return _page(body)


def _authorization_url(
    endpoints: dict[str, Any], settings: Settings, state: str, nonce: str, challenge: str
) -> str:
    """Construit l'URL de ``/authorize`` pour le flow Hybrid (code id_token token)."""
    params = urlencode(
        {
            "response_type": "code id_token token",
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
    endpoints: dict[str, Any],
    settings: Settings,
    nonce: str,
    *,
    access_token: str | None = None,
    code: str | None = None,
    require_hashes: bool = False,
) -> dict[str, Any]:
    """Vérifie la signature (JWKS) et les claims d'un ``id_token`` hybrid.

    Contrôles : OIDC Core §3.3.2.9 (`iss`, `aud`, `nonce`, `exp`), et les
    liens ``at_hash`` / ``c_hash`` du modèle hybrid (§3.3.2.11) quand les
    valeurs correspondantes sont fournies.

    ``require_hashes`` impose la présence de ``at_hash``/``c_hash`` : c'est
    le cas pour l'``id_token`` remis par ``/authorize`` dans le flow hybrid.
    L'``id_token`` du ``/token`` ne porte pas d'``at_hash`` (OIDC Core
    §3.3.3) : ses liens ne sont vérifiés que s'ils sont présents.
    """
    algorithms = endpoints.get("id_token_signing_alg_values_supported") or ["RS256"]
    signing_key = pyjwt.PyJWKClient(endpoints["jwks_uri"]).get_signing_key_from_jwt(id_token).key
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
    algorithm = _jwt_alg(id_token)
    if access_token is not None:
        at_hash = claims.get("at_hash")
        if at_hash != _hash_artefact(access_token, algorithm) and (
            require_hashes or at_hash is not None
        ):
            raise HTTPException(status_code=502, detail="at_hash incohérent avec l'access_token")
    if code is not None:
        c_hash = claims.get("c_hash")
        if c_hash != _hash_artefact(code, algorithm) and (require_hashes or c_hash is not None):
            raise HTTPException(status_code=502, detail="c_hash incohérent avec le code")
    return claims


async def _exchange_code(
    client: httpx.AsyncClient,
    endpoints: dict[str, Any],
    settings: Settings,
    code: str,
    verifier: str,
) -> dict[str, Any]:
    """Échange le code d'autorisation au ``/token`` avec le ``code_verifier`` PKCE."""
    endpoint = endpoints.get("token_endpoint")
    if not endpoint:
        raise HTTPException(status_code=502, detail="Discovery sans token_endpoint")
    response = await client.post(
        endpoint,
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
            detail=f"Échec de l'échange du code au /token : {response.text}",
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


def _hybrid_html(
    authorize_claims: dict[str, Any],
    token_claims: dict[str, Any],
    token_access_token: str,
    expires_in: object,
    verifier_ok: bool,
    userinfo: dict[str, Any],
) -> str:
    """Affiche les deux jeux de jetons du flow Hybrid et les claims de /userinfo."""
    code_exchange = (
        "<p>Code d'autorisation échangé au <code>/token</code> avec le "
        "<code>code_verifier</code> PKCE (vérifié) :</p>"
        if verifier_ok
        else "<p>Échec de l'échange du code au <code>/token</code>.</p>"
    )
    body = f"""
<h1>Connecté</h1>
<p>Jetons remis par l'endpoint d'autorisation dans le <strong>fragment</strong>
(code + id_token + access_token), <code>id_token</code> vérifié : signature JWKS,
<code>aud</code>, <code>nonce</code>, liens <code>at_hash</code> (access token)
et <code>c_hash</code> (code).</p>
{_claims_table("id_token d'authorize (vérifié localement)", "", authorize_claims)}
<h2>Échange du code au /token</h2>
{code_exchange}
{_claims_table("id_token final du /token (vérifié localement)", "", token_claims)}
<h2>UserInfo — endpoint /userinfo (claims filtrés par scopes)</h2>
<p>Renvoyés par le serveur avec l'access token final (RFC 6750).</p>
<p><code>{html.escape(token_access_token[:36])}…</code> (expire dans
{html.escape(str(expires_in))} s)&nbsp;:</p>
{_claims_table("userinfo", "", userinfo)}
<p><a href="/">Retour à l'accueil</a></p>
"""
    return _page(body)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI du client de démonstration."""
    app_settings = settings or Settings()
    pending: dict[str, PendingAuth] = {}

    app = FastAPI(
        title="PurIdentityServer — client démo (Hybrid flow)",
        description=(
            "Relying party de démonstration du flow Hybrid (OIDC Core 1.0 §3.3) : "
            "code + id_token/access_token en fragment puis échange PKCE au /token."
        ),
    )

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        """Page d'accueil du client de démonstration."""
        return _index_html(app_settings)

    @app.get("/login")
    async def login() -> RedirectResponse:
        """Initialise un login hybrid puis redirige vers la page de login du serveur."""
        state = _base64url_bytes(32)
        nonce = _base64url_bytes(16)
        verifier = _base64url_bytes(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        pending[state] = PendingAuth(nonce=nonce, verifier=verifier)

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
        authorize_url = _authorization_url(endpoints, app_settings, state, nonce, challenge)
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
        code: Annotated[str, Form()],
        id_token: Annotated[str, Form()],
        access_token: Annotated[str, Form()],
        state: Annotated[str, Form()],
        expires_in: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        """Reçoit le fragment, vérifie l'``id_token`` puis échange le code au /token."""
        auth = pending.pop(state, None)
        if auth is None:
            raise HTTPException(status_code=400, detail="État inconnu ou expiré")

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            endpoints = await _discovery(client, app_settings)
            authorize_claims = _verify_id_token(
                id_token,
                endpoints,
                app_settings,
                auth.nonce,
                access_token=access_token,
                code=code,
                require_hashes=True,
            )
            token_response = await _exchange_code(
                client, endpoints, app_settings, code, auth.verifier
            )
            userinfo = await _fetch_userinfo(client, endpoints, token_response["access_token"])

        token_claims = _verify_id_token(
            token_response["id_token"],
            endpoints,
            app_settings,
            auth.nonce,
            access_token=token_response["access_token"],
        )
        return HTMLResponse(
            _hybrid_html(
                authorize_claims,
                token_claims,
                token_response["access_token"],
                token_response.get("expires_in", ""),
                verifier_ok=True,
                userinfo=userinfo,
            )
        )

    return app


def main() -> None:
    """Lance le client de démonstration avec Uvicorn (host/port de ``OIDC_*``)."""
    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
