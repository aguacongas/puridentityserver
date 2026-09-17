"""Client de démonstration : grand client_credentials (RFC 6749 §4.4).

Requête *machine à machine* : le client confidentiel s'authentifie avec
son ``client_secret`` au endpoint ``/token`` et reçoit un access token
émis **en son nom propre** (le ``sub`` du jeton est le ``client_id`` :
pas d'utilisateur final, donc aucun ``id_token``).

Usage (depuis la racine du dépôt, avec le serveur dédié sur le port
8102 — voir README.md) :

    uv run python samples/client-credentials-client/client.py
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urljoin

import httpx
import jwt as pyjwt

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("CC_ISSUER", "http://127.0.0.1:8102")
_CLIENT_ID = os.environ.get("CC_CLIENT_ID", "sample-cc-client")
_CLIENT_SECRET = os.environ.get("CC_CLIENT_SECRET", "cc-demo-secret")
_SCOPE = os.environ.get("CC_SCOPE", "openid profile")


def _discovery() -> dict[str, object]:
    """Charge le document de discovery du serveur."""
    response = httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", ".well-known/openid-configuration"),
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _fetch_token(endpoint: str) -> httpx.Response:
    """Demande un access token avec le grand client_credentials."""
    return httpx.post(
        endpoint,
        data={
            "grant_type": "client_credentials",
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "scope": _SCOPE,
        },
        timeout=_HTTP_TIMEOUT,
    )


def _friendly_claims(token: str) -> dict[str, object]:
    """Décode les claims du JWT sans en vérifier la signature (démo)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def main() -> None:
    """Récupère un access token service-à-service et affiche ses claims."""
    metadata = _discovery()
    response = _fetch_token(metadata["token_endpoint"])  # type: ignore[arg-type]
    if response.status_code != 200:
        print(f"Échec de l'échange : HTTP {response.status_code} — {response.text}")
        return
    body = response.json()
    token = body["access_token"]
    claims = _friendly_claims(token)

    print(f"Grant client_credentials contre {_ISSUER}")
    print(f"  client_id : {_CLIENT_ID}")
    print(f"  scope     : {body['scope']}")
    print(f"  expires_in: {body['expires_in']} s")
    print(f"  id_token  : {'oui' if body.get('id_token') else 'aucun (normal)'}")
    print("\nClaims du access_token (décodés, non vérifiés — démo) :")
    print(json.dumps(claims, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
