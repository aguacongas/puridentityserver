"""Test manuel des ApiResources, du registre des scopes et de l'API protégée échantillon.

Smoke test du sample ``api-resources-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8106, deux
ApiResources ``sample-api`` / ``sample-admin`` et un client confidentiel
``sample-api-client``), démarre l'API protégée échantillon (``api_server.py``)
sur le port 8120, puis joue le scénario :

1. le discovery annonce ``scopes_supported`` incluant les scopes d'API
   (``api.read``, ``api.write``, ``api.admin``) ;
2. ``GET /api-resources`` liste les resources protégées et leurs scopes ;
3. ``/token`` (client_credentials, ``api.read``) -> access token dont
   l'``aud`` (décodée sans vérification) vaut ``sample-api`` et le ``sub``
   le ``client_id`` émetteur ;
4. ``/token`` (client_credentials, ``api.read api.admin``) -> ``aud`` en
   liste triée ``["sample-admin", "sample-api"]`` ;
5. ``/token`` (client_credentials, scope inconnu ``nope``) -> ``400
   invalid_scope`` (tout scope non enregistré est refusé) ;
6. ``/introspect`` sur le token API -> ``active: true``, ``aud``/``client_id``
   = audience API (une audience unique reste attribuée au client dans la
   réponse RFC 7662) ;
7. ``/token`` (client_credentials, ``openid profile``, aucun scope d'API) ->
   ``aud`` = ``client_id`` (comportement historique sans audience API) ;
8. CRUD : ``PUT /api-resources/sample-api`` remplace ses scopes, ``DELETE
   /api-resources/sample-admin`` la retire, ``GET`` après suppression ->
   ``404`` ;
9. ``GET /api/data`` de l'API protégée avec un jeton invalide -> ``401
   invalid_token`` ;
10. ``GET /api/data`` avec le jeton ``api.read`` -> ``200`` et les claims du
    jeton (la signature JWKS, ``iss``, ``exp``, ``aud`` et le scope ont été
    vérifiés par le resource server) ;
11. ``GET /api/data`` avec un jeton adressé à l'API mais **sans le scope
    requis** (``api.write``) -> ``403 insufficient_scope`` ; un jeton non
    adressé à l'API (``aud`` = ``client_id``) est quant à lui refusé en
    ``401 invalid_token``.

Les sous-processus sont terminés dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/api-resources-client/smoke_test.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, REPO_ROOT, run_server, wait_port, watchdog

SERVER_PORT = 8106
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"
API_PORT = 8120
API_URL = f"http://{HOST}:{API_PORT}"

CLIENT_ID = "sample-api-client"
CLIENT_SECRET = "api-demo-secret"

_API_RESOURCES = (
    {
        "name": "sample-api",
        "display_name": "API de démonstration",
        "scopes": ["api.read", "api.write"],
    },
    {
        "name": "sample-admin",
        "display_name": "API d'administration",
        "scopes": ["api.admin"],
    },
)

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "scopes": "openid profile api.read api.write api.admin",
        "client_type": "confidential",
        "client_secret": CLIENT_SECRET,
    },
)

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _token(
    http: httpx.Client, *, scope: str | None = None, secret: str = CLIENT_SECRET
) -> httpx.Response:
    """Appelle ``/token`` avec le grand client_credentials."""
    data: dict[str, object] = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": secret,
    }
    if scope is not None:
        data["scope"] = scope
    return http.post(f"{SERVER_URL}/token", data=data)


def _friendly_claims(token: str) -> dict[str, object]:
    """Décode les claims du JWT sans en vérifier la signature (démo)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def _introspect(http: httpx.Client, *, token: str) -> httpx.Response:
    """Appelle ``/introspect`` avec les identifiants du client confidentiel."""
    return http.post(
        f"{SERVER_URL}/introspect",
        data={"token": token, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
    )


def _call_api(*, token: str) -> httpx.Response:
    """Appelle l'API protégée échantillon avec un Bearer token."""
    return httpx.get(
        f"{API_URL}/api/data",
        headers={"Authorization": f"Bearer {token}"},
        timeout=_HTTP_TIMEOUT,
    )


@contextmanager
def _api_server(*, issuer: str) -> Iterator[str]:
    """Lance l'API protégée échantillon (port 8120) en sous-processus."""
    sample_dir = Path(__file__).resolve().parent
    env = os.environ.copy()
    env["API_RES_ISSUER"] = issuer
    env["API_RES_PORT"] = str(API_PORT)
    proc: subprocess.Popen[bytes] | None = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "api_server:app",
            "--app-dir",
            str(sample_dir),
            "--host",
            HOST,
            "--port",
            str(API_PORT),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
    )
    try:
        wait_port(API_PORT)
        yield API_URL
    finally:
        if proc is not None:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _scopes_supported(metadata: dict[str, object]) -> list[str]:
    """Scopes annoncés par le discovery."""
    scopes = metadata["scopes_supported"]
    if not isinstance(scopes, list):
        raise AssertionError("scopes_supported doit être une liste")
    return [str(scope) for scope in scopes]


def _run_scenario() -> None:
    """Joue le scénario ApiResources et API protégée de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        scopes = _scopes_supported(metadata)
        for expected in ("api.read", "api.write", "api.admin"):
            assert expected in scopes, f"{expected} manquant dans scopes_supported"
        print("  [1/11] discovery OK (scopes_supported contient api.read/api.write/api.admin)")

        response = http.get(f"{SERVER_URL}/api-resources")
        assert response.status_code == 200, response.text
        resources = response.json()
        names = [resource["name"] for resource in resources]
        assert names == ["sample-api", "sample-admin"], names
        print(
            "  [2/11] GET /api-resources OK "
            f"(audiences {names}, scopes {[resource['scopes'] for resource in resources]})"
        )

        response = _token(http, scope="api.read")
        assert response.status_code == 200, response.text
        claims = _friendly_claims(response.json()["access_token"])
        assert claims["aud"] == "sample-api", claims
        assert claims["sub"] == CLIENT_ID, claims
        print(
            f"  [3/11] client_credentials api.read -> aud={claims['aud']!r} OK "
            f"(sub={claims['sub']!r})"
        )

        response = _token(http, scope="api.read api.admin")
        assert response.status_code == 200, response.text
        claims = _friendly_claims(response.json()["access_token"])
        assert claims["aud"] == ["sample-admin", "sample-api"], claims
        print(f"  [4/11] client_credentials api.read api.admin -> aud={claims['aud']!r} OK")

        response = _token(http, scope="nope")
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_scope"
        print("  [5/11] scope inconnu (nope) -> 400 invalid_scope OK")

        api_token = _token(http, scope="api.read").json()["access_token"]
        response = _introspect(http, token=api_token)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["active"] is True
        assert body["aud"] == "sample-api"
        assert body["client_id"] == "sample-api"
        assert body["scope"] == "api.read"
        print(
            "  [6/11] introspection token API OK "
            f"(aud={body['aud']!r}, client_id={body['client_id']!r})"
        )

        response = _token(http, scope="openid profile")
        assert response.status_code == 200, response.text
        claims = _friendly_claims(response.json()["access_token"])
        assert claims["aud"] == CLIENT_ID, claims
        print(f"  [7/11] client_credentials openid profile -> aud={claims['aud']!r} OK (client_id)")

        response = http.put(
            f"{SERVER_URL}/api-resources/sample-api",
            json={"name": "sample-api", "scopes": ["api.read", "api.write", "api.list"]},
        )
        assert response.status_code == 200, response.text
        replaced = response.json()
        assert replaced["scopes"] == ["api.list", "api.read", "api.write"], replaced
        response = http.get(f"{SERVER_URL}/api-resources/sample-api")
        assert response.json()["scopes"] == ["api.list", "api.read", "api.write"]
        response = http.delete(f"{SERVER_URL}/api-resources/sample-admin")
        assert response.status_code == 204, response.text
        response = http.get(f"{SERVER_URL}/api-resources/sample-admin")
        assert response.status_code == 404, response.text
        response = http.get(f"{SERVER_URL}/api-resources")
        assert [resource["name"] for resource in response.json()] == ["sample-api"]
        print("  [8/11] CRUD /api-resources OK (PUT remplace les scopes, DELETE retire, 404 après)")

        response = _call_api(token="jeton-pourri")
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_token"
        print("  [9/11] API protégée, jeton invalide -> 401 invalid_token OK")

        response = _call_api(token=api_token)
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["resource"] == "sample-api"
        assert data["sub"] == CLIENT_ID
        assert data["aud"] == "sample-api"
        assert data["scope"] == "api.read"
        print(
            "  [10/11] API protégée, jeton api.read -> 200 OK "
            f"(sub={data['sub']!r}, aud={data['aud']!r}, scope={data['scope']!r}, "
            "JWKS/iss/exp vérifiés par l'API)"
        )

        scope_less_token = _token(http, scope="api.write").json()["access_token"]
        response = _call_api(token=scope_less_token)
        assert response.status_code == 403, response.text
        assert response.json()["error"] == "insufficient_scope"
        print("  [11/11] API protégée, jeton sans scope requis -> 403 insufficient_scope OK")
    print()


def main() -> None:
    """Lance le serveur de test et l'API échantillon, puis le scénario."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(port=SERVER_PORT, clients=_CLIENTS, api_resources=_API_RESOURCES) as issuer,
        _api_server(issuer=issuer),
    ):
        print(f"\nScénario ApiResources + API protégée (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
