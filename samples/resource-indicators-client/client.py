"""Client de démonstration : Resource Indicators (RFC 8707).

Le client joue le flow Authorization Code contre un serveur PurIdentityServer
en cours d'exécution (configuration `config.toml` par défaut, port 8000) :

1. `GET /authorize` avec le paramètre `resource` (URI déclarée en `indicator`
   de l'ApiResource `sample-api`) -> `302` code d'autorisation ;
2. échange du code au `/token` -> access token dont le claim `aud` porte
   l'URI de la resource ciblée (RFC 8707 §3) ;
3. rejet `invalid_target` d'une resource inconnue (RFC 8707 §2.2) ;
4. appel de la ressource protégée intégrée `GET /protected-resource` avec le
   jeton (`200` + en-tête `x-fapi-interaction-id`), puis sans jeton
   (`401` + challenge `WWW-Authenticate`, RFC 6750 §3).

Usage (depuis la racine du dépôt, serveur déjà démarré - voir README.md) :

    uv run python samples/resource-indicators-client/client.py
"""

from __future__ import annotations

import json
import os
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import jwt as pyjwt

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("RI_ISSUER", "http://127.0.0.1:8000")
_CLIENT_ID = os.environ.get("RI_CLIENT_ID", "sample-resource-client")
_CLIENT_SECRET = os.environ.get("RI_CLIENT_SECRET", "resource-demo-secret")
_REDIRECT_URI = os.environ.get("RI_REDIRECT_URI", "http://127.0.0.1:8000/callback")
_RESOURCE = os.environ.get("RI_RESOURCE", "http://127.0.0.1:8000/protected-resource")
_SCOPE = os.environ.get("RI_SCOPE", "openid profile offline_access")


def _discovery() -> dict[str, object]:
    """Charge le document de discovery du serveur."""
    response = httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", ".well-known/openid-configuration"),
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _authorize(authorization_endpoint: str, resource: str) -> str:
    """Lance une demande d'autorisation et retourne l'en-tête `Location`."""
    response = httpx.get(
        authorization_endpoint,
        params={
            "response_type": "code",
            "client_id": _CLIENT_ID,
            "redirect_uri": _REDIRECT_URI,
            "scope": _SCOPE,
            "state": "ri-state-1",
            "resource": resource,
        },
        timeout=_HTTP_TIMEOUT,
        follow_redirects=False,
    )
    if response.status_code != 302:
        print(f"Réponse inattendue de /authorize : HTTP {response.status_code}")
        print(response.text)
        raise SystemExit(1)
    return str(response.headers["location"])


def _exchange(token_endpoint: str, code: str) -> httpx.Response:
    """Échange le code d'autorisation contre les jetons."""
    return httpx.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT_URI,
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
        },
        timeout=_HTTP_TIMEOUT,
    )


def _friendly(token: str) -> dict[str, object]:
    """Décode les claims du JWT sans en vérifier la signature (démo)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def _call_resource(resource_url: str, token: str | None) -> httpx.Response:
    """Appelle la ressource protégée intégrée, avec ou sans Bearer."""
    headers = {"x-fapi-interaction-id": "ri-demo-1"} if token else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.get(resource_url, headers=headers, timeout=_HTTP_TIMEOUT)


def main() -> None:
    """Joue le scénario Resource Indicators et affiche le résultat de chaque étape."""
    metadata = _discovery()
    authorization_endpoint = str(metadata["authorization_endpoint"])
    token_endpoint = str(metadata["token_endpoint"])
    resource_url = _ISSUER.rstrip("/") + "/protected-resource"

    print(f"Resource Indicators contre {_ISSUER}")
    print(f"  client : {_CLIENT_ID}")
    print(f"  resource cible : {_RESOURCE}")

    location = _authorize(authorization_endpoint, _RESOURCE)
    query = parse_qs(urlparse(location).query)
    if "error" in query:
        print(f"\nÉchec de /authorize : error={query['error'][0]}")
        raise SystemExit(1)
    response = _exchange(token_endpoint, query["code"][0])
    if response.status_code != 200:
        print(f"\nÉchec de l'échange : HTTP {response.status_code} - {response.text}")
        raise SystemExit(1)
    body = response.json()
    claims = _friendly(str(body["access_token"]))
    print("\n1. /authorize avec resource enregistrée -> code échangé (HTTP 200)")
    print(f"   aud = {claims.get('aud')!r}   (attendu : {_RESOURCE!r})")
    print(
        json.dumps(
            {key: claims[key] for key in ("iss", "sub", "aud", "scope", "exp") if key in claims},
            indent=2,
            ensure_ascii=False,
        )
    )

    location = _authorize(authorization_endpoint, "https://unknown.example/api")
    query = parse_qs(urlparse(location).query)
    error = query.get("error", ["?"])[0]
    print(f"\n2. /authorize avec resource inconnue -> error={error} (invalid_target)")
    print("   la redirection porte error=invalid_target + state conservé (RFC 8707 §2.2)")

    response = _call_resource(resource_url, str(body["access_token"]))
    print(f"\n3. GET /protected-resource (Bearer) -> HTTP {response.status_code}")
    print(f"   x-fapi-interaction-id : {response.headers.get('x-fapi-interaction-id')}")
    print(f"   Date                  : {response.headers.get('date')}")
    if response.status_code == 200:
        print(f"   corps                 : {response.json()}")

    response = _call_resource(resource_url, None)
    challenge = response.headers.get("www-authenticate", "")
    print(f"\n4. GET /protected-resource (sans jeton) -> HTTP {response.status_code}")
    print(f"   WWW-Authenticate      : {challenge}")
    if response.status_code == 401:
        print(f"   corps                 : {response.json()}")

    print("\nÉtapes 1-2 rejouables en curl :")
    print(
        f'  curl -i -G "{authorization_endpoint}" \\\n'
        f'    --data-urlencode "response_type=code" \\\n'
        f'    --data-urlencode "client_id={_CLIENT_ID}" \\\n'
        f'    --data-urlencode "redirect_uri={_REDIRECT_URI}" \\\n'
        f'    --data-urlencode "scope={_SCOPE}" \\\n'
        f'    --data-urlencode "state=ri-state-1" \\\n'
        f'    --data-urlencode "resource={_RESOURCE}"'
    )


if __name__ == "__main__":
    main()
