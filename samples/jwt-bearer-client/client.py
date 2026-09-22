"""Client de démonstration : grant jwt-bearer (RFC 7523 §2.1) + client_secret_jwt.

Issue #46 : un client *machine à machine* s'authentifie au token endpoint
sans envoyer son secret en clair (métadonnée ``token_endpoint_auth_method =
client_secret_jwt``) puis délègue un ``sub`` (ici ``alice``) grâce à une
assertion JWT signée partagée (*grant* ``urn:ietf:params:oauth:grant-type:
jwt-bearer``).

Le client est créé *dynamiquement* via ``/register`` (RFC 7591) avec la
métadonnée ``token_endpoint_auth_method: "client_secret_jwt"`` ; le serveur
le stocke chiffré (RSA-OAEP, clé de scellement auto-rotée) et ne l'émet
qu'une seule fois en clair.

Usage (depuis la racine du dépôt, serveur PurIdentityServer déjà démarré sur
le port ``8000`` par défaut - voir README.md) :

    uv run python samples/jwt-bearer-client/client.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx
import jwt as pyjwt

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("JWB_ISSUER", "http://127.0.0.1:8000")
_REGISTER_TOKEN = os.environ.get("JWB_REGISTER_TOKEN", "dev-registrar-token")
_SUBJECT = os.environ.get("JWB_SUBJECT", "alice")
_SCOPE = os.environ.get("JWB_SCOPE", "openid profile email")

_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _discovery() -> dict[str, object]:
    """Charge le document de discovery du serveur."""
    response = httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", ".well-known/openid-configuration"),
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _register(register_endpoint: str) -> dict[str, object]:
    """Enregistre un client ``client_secret_jwt`` (RFC 7591) et rend son secret."""
    response = httpx.post(
        register_endpoint,
        headers={"Authorization": f"Bearer {_REGISTER_TOKEN}"},
        json={
            "redirect_uris": ["http://127.0.0.1:8000/callback"],
            "token_endpoint_auth_method": "client_secret_jwt",
            "scope": _SCOPE,
        },
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _assertion(*, iss: str, sub: str, aud: str, secret: str, expires_in: int = 600) -> str:
    """Signe une assertion JWT HMAC partagée (``exp``/``iat`` valides)."""
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "exp": int(now.timestamp()) + expires_in,
            "iat": int(now.timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def _token(endpoint: str, data: dict[str, object]) -> httpx.Response:
    """Appelle ``/token`` avec les paramètres fournis."""
    return httpx.post(endpoint, data=data, timeout=_HTTP_TIMEOUT)


def _friendly_claims(token: str) -> dict[str, object]:
    """Décode les claims du JWT sans en vérifier la signature (démo)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def main() -> None:
    """Enregistre un client JWT, puis joue les deux flux #46."""
    metadata = _discovery()
    token_endpoint = metadata["token_endpoint"]  # type: ignore[arg-type]
    registered = _register(metadata["registration_endpoint"])  # type: ignore[arg-type]
    client_id = registered["client_id"]
    client_secret = registered["client_secret"]
    print(f"Registration (RFC 7591) : client_id={client_id}, auth=client_secret_jwt")

    response = _token(
        token_endpoint,
        {
            "grant_type": _GRANT,
            "client_id": client_id,
            "assertion": _assertion(
                iss=client_id, sub=_SUBJECT, aud=token_endpoint, secret=client_secret
            ),
            "scope": _SCOPE,
        },
    )
    if response.status_code != 200:
        print(f"Échec du grant jwt-bearer : HTTP {response.status_code} - {response.text}")
        sys.exit(1)
    body = response.json()
    print(f"Grant jwt-bearer contre {_ISSUER} : token au nom de {_SUBJECT}")  # type: ignore[union-attr]
    print(f"  scope     : {body['scope']}")

    response = _token(
        token_endpoint,
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_assertion_type": _ASSERTION_TYPE,
            "client_assertion": _assertion(
                iss=client_id, sub=client_id, aud=token_endpoint, secret=client_secret
            ),
        },
    )
    if response.status_code != 200:
        print(f"Échec client_secret_jwt : HTTP {response.status_code} - {response.text}")
        sys.exit(1)
    body = response.json()
    print("client_secret_jwt (RFC 7523 §2.2) : token au nom du client lui-même")
    print(f"  scope     : {body['scope']}")

    claims = _friendly_claims(body["access_token"])
    print("\nClaims du access_token (décodés, non vérifiés - démo) :")
    print(json.dumps(claims, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
