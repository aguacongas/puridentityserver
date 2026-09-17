"""Client de démonstration : Device Authorization Grant (RFC 8628).

Tente l'OIDC device flow contre le serveur configuré (défaut
``http://127.0.0.1:8000``) : affiche le ``user_code`` à saisir sur
la page de vérification, puis boucle en poll sur le token endpoint
jusqu'à obtenir les jetons ou un refus/expiry.

Utilise ``httpx`` pour les appels HTTP et ``pyjwt`` pour décoder
l'``id_token``.

Usage::

    python client.py                     # défaut http://127.0.0.1:8000
    python client.py https://auth.example  # issuer explicite
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx
import jwt

_DEFAULT_ISSUER = "http://127.0.0.1:8000"
_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _discovery(issuer: str) -> dict[str, object]:
    """Charge le document de discovery."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with httpx.Client(timeout=10) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _request_device_code(
    client: httpx.Client, device_authorization_endpoint: str, client_id: str
) -> dict[str, object]:
    """Demande un device_code + user_code au serveur (RFC 8628 §3.1)."""
    resp = client.post(
        device_authorization_endpoint,
        data={"client_id": client_id},
    )
    if resp.status_code >= 400:
        print(f"ERREUR {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def _poll_tokens(
    client: httpx.Client, token_endpoint: str, client_id: str, device_code: str
) -> dict[str, object]:
    """Interroge le token endpoint jusqu'à succès, refus ou expiration."""
    while True:
        resp = client.post(
            token_endpoint,
            data={
                "grant_type": _DEVICE_GRANT,
                "device_code": device_code,
                "client_id": client_id,
            },
        )
        body = resp.json()
        error = body.get("error")
        if error is None:
            return body
        if error in ("access_denied", "expired_token"):
            print(f"\nErreur : {error} — {body.get('error_description', '')}")
            sys.exit(1)
        print(f"  ... {error} ({body.get('error_description', '')})")
        time.sleep(5)


def _decode_claims(token: str) -> dict[str, object]:
    """Décode le payload JWT sans vérifier la signature (démo uniquement)."""
    # PyJWT gère le padding automatiquement.
    return jwt.decode(token, options={"verify_signature": False})


def main() -> None:
    """Point d'entrée du client démo : device flow (RFC 8628)."""
    issuer = os.environ.get("DEVICE_ISSUER", _DEFAULT_ISSUER).strip().rstrip("/")
    client_id = os.environ.get("DEVICE_CLIENT_ID", "sample-device-client")

    print(f"Device Authorization Grant (RFC 8628) contre {issuer}\n")

    metadata = _discovery(issuer)
    device_authorization_endpoint = metadata["device_authorization_endpoint"]
    token_endpoint = metadata["token_endpoint"]
    print(f"[1] Discovery chargé — device_authorization_endpoint = {device_authorization_endpoint}")

    with httpx.Client(base_url=issuer, timeout=15) as client:
        data = _request_device_code(client, device_authorization_endpoint, client_id)
        device_code = data["device_code"]
        user_code = data["user_code"]
        verification_uri = data["verification_uri"]
        expires_in = data["expires_in"]

        print(f"[2] Codes obtenus (expiré dans {expires_in}s)")
        print(f"    Ouvrez {verification_uri}")
        print(f"    Saisissez le code : {user_code}")
        print("\n  [3] Poll en cours... ", end="", flush=True)

        tokens = _poll_tokens(client, token_endpoint, client_id, device_code)

        print("OK !\n")
        print("Tokens reçus :")
        print(f"  access_token : {tokens['access_token'][:50]}...")
        if tokens.get("id_token"):
            print(f"  id_token     : {tokens['id_token'][:50]}...")
        if tokens.get("refresh_token"):
            print(f"  refresh_token: {tokens['refresh_token'][:50]}...")
        print(f"  expires_in   : {tokens.get('expires_in')}")
        print(f"  scope        : {tokens.get('scope', '')}")

        if tokens.get("id_token"):
            claims = _decode_claims(tokens["id_token"])
            print("\nClaims du id_token (décodage sans vérification) :")
            print(json.dumps(claims, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
