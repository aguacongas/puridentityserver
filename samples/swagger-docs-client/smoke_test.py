"""Smoke test du sample ``swagger-docs-client`` (Authorize dans Swagger UI).

Lance **un** serveur PurIdentityServer (port 8109) dont la configuration
active l'authentification OIDC de Swagger UI, puis rejoue à la main le flow
que le bouton **Authorize** déclenche dans le navigateur :

1. ``GET /openapi.json`` publie le schéma OAuth2 ``oidc`` (authorization code
   + PKCE) et le référence sur les CRUD ;
2. ``GET /docs`` rend Swagger UI configuré (``initOAuth`` + redirect) ;
3. ``GET /docs/oauth2-redirect`` sert la page de retour OAuth2 de Swagger ;
4. ``GET /authorize`` (PKCE S256, ``scope=openid admin``) redirige vers cette
   page avec un ``code`` ;
5. ``POST /token`` échange le code contre l'access token ;
6. ``GET /api-resources`` refuse le appel sans jeton (401) puis l'accepte avec
   ce jeton portant le claim ``scope=admin`` (200).

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/swagger-docs-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8109
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-swagger-client"
REDIRECT_URI = f"{SERVER_URL}/docs/oauth2-redirect"
SCOPE = "openid admin"

_CODE_VERIFIER = "swagger-smoke-code-verifier-0123456789abcdefghijklmnopqrstuv"
_STATE = "swagger-smoke-state"

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": SCOPE,
        "client_type": "public",
    },
)

_API_RESOURCES = ({"name": "management", "display_name": "API de gestion", "scopes": ["admin"]},)

_EXTRA_SETTINGS = {
    "swagger_ui_oauth2_enabled": True,
    "swagger_ui_init_oauth": {
        "clientId": CLIENT_ID,
        "scopes": ["openid", "admin"],
        "usePkceWithAuthorizationCodeGrant": True,
    },
}

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _code_challenge(verifier: str) -> str:
    """Calcule le ``code_challenge`` S256 (RFC 7636 §4.2) du ``verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _run_scenario() -> None:
    """Joue le flow OIDC de Swagger UI de bout en bout."""
    with httpx.Client(timeout=_HTTP_TIMEOUT) as http:
        schema = http.get(f"{SERVER_URL}/openapi.json").json()
        scheme = schema["components"]["securitySchemes"]["oidc"]
        assert scheme["type"] == "oauth2", scheme
        flow = scheme["flows"]["authorizationCode"]
        assert flow["authorizationUrl"] == f"{SERVER_URL}/authorize", flow
        assert flow["tokenUrl"] == f"{SERVER_URL}/token", flow
        assert schema["paths"]["/api-resources"]["get"]["security"] == [
            {"oidc": ["openid", "admin"]}
        ]
        print("  [1/6] /openapi.json : schéma oauth2 « oidc » déclaré sur les CRUD")

        html = http.get(f"{SERVER_URL}/docs").text
        assert "ui.initOAuth(" in html, "initOAuth absent de /docs"
        assert f'"clientId": "{CLIENT_ID}"' in html, "clientId absent de /docs"
        assert "oauth2RedirectUrl: window.location.origin" in html
        print(f"  [2/6] /docs : initOAuth(clientId={CLIENT_ID}) + oauth2RedirectUrl")

        page = http.get(REDIRECT_URI)
        assert page.status_code == 200, page.text
        print("  [3/6] /docs/oauth2-redirect : page de retour OAuth2 servie (200)")

        authorize = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "state": _STATE,
                "code_challenge": _code_challenge(_CODE_VERIFIER),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302, authorize.text
        location = authorize.headers["location"]
        query = parse_qs(urlparse(location).query)
        code = query.get("code", [""])[0]
        assert location.startswith(REDIRECT_URI), location
        assert code and query["state"] == [_STATE], query
        print("  [4/6] /authorize : 302 vers /docs/oauth2-redirect avec code + state")

        token = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": _CODE_VERIFIER,
            },
        )
        assert token.status_code == 200, token.text
        access_token = token.json()["access_token"]
        print("  [5/6] /token : authorization_code + PKCE échangé contre l'access token")

        response = http.get(f"{SERVER_URL}/api-resources")
        assert response.status_code == 401, response.text
        granted = http.get(
            f"{SERVER_URL}/api-resources",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert granted.status_code == 200, granted.text
        names = [resource["name"] for resource in granted.json()]
        print(f"  [6/6] /api-resources : 401 sans jeton puis 200 avec le jeton ({names})")
    print()


def main() -> None:
    """Lance le serveur puis le scénario d'authentification Swagger UI."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            api_resources=_API_RESOURCES,
            extra_settings=_EXTRA_SETTINGS,
        ) as _url,
    ):
        print(f"\nScénario Swagger UI OIDC (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
