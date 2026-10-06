"""Test manuel des Resource Indicators (RFC 8707) et du resource server intégré.

Smoke test du sample ``resource-indicators-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8119, deux
ApiResources ``sample-api`` / ``sample-other`` portant un ``indicator``, le
client confidentiel ``sample-ri-client`` et
``protected_resource_enabled = true``), puis joue le scénario :

1. le discovery annonce les endpoints d'autorisation et de jetons ;
2. ``GET /authorize`` avec ``resource`` = URI enregistrée -> ``302`` code,
   échange au ``/token`` -> access token dont l'``aud`` vaut l'URI ciblée
   (chaîne unique, RFC 8707 §3) ;
3. ``GET /authorize`` sans ``resource`` -> échange -> ``aud`` = ``client_id``
   (comportement historique, aucun scope d'API accordé) ;
4. ``resource`` inconnue (aucun ``ApiResource.indicator``) -> ``302``
   ``error=invalid_target`` (RFC 8707 §2.2) ;
5. ``resource`` malformée (pas une URI absolue) -> ``302``
   ``error=invalid_target`` ;
6. ``GET /authorize`` avec deux ``resource`` répétées -> échange -> ``aud``
   en liste ``[uri1, uri2]`` ;
7. ``/token`` (refresh) avec ``resource`` hors du périmètre lié au grant ->
   ``400 invalid_target`` ; puis sans ``resource`` -> ``aud`` conservé ;
8. ``GET /protected-resource`` avec Bearer + ``x-fapi-interaction-id`` ->
   ``200`` JSON, en-tête échoyé, ``Date`` présent (FAPI-R-6.2.1) ;
9. sans jeton / jeton invalide / transport en query string -> ``401`` avec
   challenge ``WWW-Authenticate`` (RFC 6750 §2-§3) ;
10. ``x-fapi-interaction-id`` absente côté client -> ``uuid4`` généré en
    réponse (la suite l'exige même sans émission côté client).

Les sous-processus sont terminés dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/resource-indicators-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import httpx
import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8119
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"
RESOURCE_A = f"{SERVER_URL}/protected-resource"
RESOURCE_B = f"{SERVER_URL}/other"
UNKNOWN_RESOURCE = "https://unknown.example/api"

CLIENT_ID = "sample-ri-client"
CLIENT_SECRET = "ri-demo-secret"
REDIRECT_URI = "http://127.0.0.1:8119/callback"
SCOPE = "openid profile offline_access"

_API_RESOURCES = (
    {
        "name": "sample-api",
        "display_name": "API de démonstration",
        "scopes": ["api.read"],
        "indicator": RESOURCE_A,
    },
    {
        "name": "sample-other",
        "display_name": "API annexe",
        "scopes": ["api.write"],
        "indicator": RESOURCE_B,
    },
)

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [REDIRECT_URI],
        "scopes": SCOPE,
        "client_type": "confidential",
    },
)

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _base_params() -> dict[str, str]:
    """Paramètres communs d'une demande d'autorisation valide."""
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": "st-1",
    }


def _authorize(http: httpx.Client, **extra: str) -> httpx.Response:
    """Appelle ``GET /authorize`` sans suivre la redirection."""
    params = _base_params()
    params.update(extra)
    return http.get(f"{SERVER_URL}/authorize", params=params)


def _code_of(response: httpx.Response) -> str:
    """Extrait le code d'autorisation de la redirection réussie."""
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert "error" not in query, query
    return query["code"][0]


def _error_of(response: httpx.Response) -> str:
    """Extrait le code d'erreur OAuth de la redirection en échec."""
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    return query["error"][0]


def _exchange(http: httpx.Client, code: str, *, resource: str | None = None) -> httpx.Response:
    """Échange un code d'autorisation contre les jetons."""
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    if resource is not None:
        data["resource"] = resource
    return http.post(f"{SERVER_URL}/token", data=data)


def _refresh(
    http: httpx.Client, refresh_token: str, *, resource: str | None = None
) -> httpx.Response:
    """Renouvelle les jetons avec le refresh token fourni."""
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    if resource is not None:
        data["resource"] = resource
    return http.post(f"{SERVER_URL}/token", data=data)


def _friendly(token: str) -> dict[str, object]:
    """Décode les claims du JWT sans en vérifier la signature (démo)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def _run_scenario() -> None:
    """Joue le scénario Resource Indicators + resource server de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "authorization_endpoint" in metadata, metadata
        assert "token_endpoint" in metadata, metadata
        print("  [1/10] discovery OK (authorization_endpoint / token_endpoint)")

        auth = _authorize(http, resource=RESOURCE_A)
        response = _exchange(http, _code_of(auth))
        assert response.status_code == 200, response.text
        body = response.json()
        token = str(body["access_token"])
        refresh_token = str(body["refresh_token"])
        claims = _friendly(token)
        assert claims["aud"] == RESOURCE_A, claims
        print(f"  [2/10] resource enregistrée -> code échangé, aud={claims['aud']!r} OK")

        auth = _authorize(http)
        response = _exchange(http, _code_of(auth))
        assert response.status_code == 200, response.text
        claims = _friendly(str(response.json()["access_token"]))
        assert claims["aud"] == CLIENT_ID, claims
        print(f"  [3/10] sans resource -> aud={claims['aud']!r} (client_id, historique) OK")

        response = _authorize(http, resource=UNKNOWN_RESOURCE)
        assert _error_of(response) == "invalid_target", response.headers.get("location")
        print("  [4/10] resource inconnue -> 302 error=invalid_target OK")

        response = _authorize(http, resource="pas-une-uri")
        assert _error_of(response) == "invalid_target", response.headers.get("location")
        print("  [5/10] resource malformée -> 302 error=invalid_target OK")

        auth = http.get(
            f"{SERVER_URL}/authorize",
            params={**_base_params(), "resource": [RESOURCE_A, RESOURCE_B]},
        )
        response = _exchange(http, _code_of(auth))
        assert response.status_code == 200, response.text
        claims = _friendly(str(response.json()["access_token"]))
        assert claims["aud"] == [RESOURCE_A, RESOURCE_B], claims
        print(f"  [6/10] deux resources répétées -> aud en liste {claims['aud']!r} OK")

        rejected = _refresh(http, refresh_token, resource=RESOURCE_B)
        assert rejected.status_code == 400, rejected.text
        assert rejected.json()["error"] == "invalid_target", rejected.text
        renewed = _refresh(http, refresh_token)
        assert renewed.status_code == 200, renewed.text
        claims = _friendly(str(renewed.json()["access_token"]))
        assert claims["aud"] == RESOURCE_A, claims
        print(
            "  [7/10] refresh: resource hors périmètre -> 400 invalid_target ; "
            f"sans resource -> aud conservé {claims['aud']!r} OK"
        )

        response = http.get(
            f"{SERVER_URL}/protected-resource",
            headers={
                "Authorization": f"Bearer {token}",
                "x-fapi-interaction-id": "ri-smoke-1",
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-fapi-interaction-id"] == "ri-smoke-1"
        assert "date" in response.headers, response.headers
        body = response.json()
        assert "openid" in str(body["scope"]), body
        print(
            "  [8/10] GET /protected-resource -> 200 (JSON, "
            "x-fapi-interaction-id échoyée, Date présent) OK"
        )

        response = http.get(f"{SERVER_URL}/protected-resource")
        assert response.status_code == 401, response.text
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert response.json()["error"] == "invalid_request"
        response = http.get(
            f"{SERVER_URL}/protected-resource",
            headers={"Authorization": "Bearer jeton-pourri"},
        )
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_token"
        response = http.get(f"{SERVER_URL}/protected-resource", params={"access_token": token})
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_request"
        print(
            "  [9/10] sans jeton / jeton invalide / transport query -> 401 "
            "+ challenge WWW-Authenticate OK"
        )

        response = http.get(
            f"{SERVER_URL}/protected-resource",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, response.text
        UUID(response.headers["x-fapi-interaction-id"])
        print("  [10/10] x-fapi-interaction-id absente -> uuid4 généré en réponse OK")
    print()


def main() -> None:
    """Lance le serveur de test, puis le scénario Resource Indicators."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            api_resources=_API_RESOURCES,
            extra_settings={"protected_resource_enabled": True},
        ),
    ):
        print(
            f"\nScénario Resource Indicators + resource server intégré (deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
