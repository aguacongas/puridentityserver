#!/usr/bin/env python3
"""Smoke test bout-en-bout du flux pre-autorise OpenID4VCI.

Enchaine : jeton client -> creation d'une offre -> dereferencement de
``credential_offer_uri`` -> echange du code pre-autorise au token endpoint
-> emission du credential avec une preuve de possession.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "sample-oid4vci-client")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "oid4vci-demo-secret")
SUBJECT = os.environ.get("SUBJECT", "alice@example.com")
USE_TX_CODE = os.environ.get("USE_TX_CODE", "true").lower() not in {"0", "false", "no"}


def _post(path: str, data: dict[str, str], token: str = "") -> tuple[int, dict[str, object]]:
    """Poste un formulaire et renvoie le statut et le corps JSON."""
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(BASE_URL + path, data=body, method="POST")  # ruff: ignore[suspicious-url-open-usage]
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    return _send(request)


def _post_json(
    path: str, payload: dict[str, object], token: str = ""
) -> tuple[int, dict[str, object]]:
    """Poste un corps JSON et renvoie le statut et le corps JSON."""
    request = urllib.request.Request(  # ruff: ignore[suspicious-url-open-usage]
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    return _send(request)


def _get(url: str) -> tuple[int, dict[str, object]]:
    """Lit une URL et renvoie le statut et le corps JSON."""
    return _send(urllib.request.Request(url))  # ruff: ignore[suspicious-url-open-usage]


def _send(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    """Execute une requete et normalise la reponse JSON."""
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        payload = error.read().decode()
        try:
            return error.code, json.loads(payload or "{}")
        except json.JSONDecodeError:
            return error.code, {"error": payload}


def _client_token() -> str:
    """Obtient un access token machine portant le scope ``openid4vci``."""
    status, body = _post(
        "/token",
        {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "openid4vci",
        },
    )
    if status != 200:
        raise SystemExit(f"jeton client refuse ({status}) : {body}")
    return str(body["access_token"])


def _proof(issuer: str, nonce: str) -> tuple[str, dict[str, object]]:
    """Construit une preuve de possession ES256 et sa cle publique JWK."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=False)
    )
    public_jwk["kid"] = "sample-oid4vci-key"
    headers = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": public_jwk}
    proof = jwt.encode(
        {"aud": issuer, "nonce": nonce, "iat": int(time.time())},
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        algorithm="ES256",
        headers=headers,
    )
    return proof, public_jwk


def main() -> int:
    """Point d entree du smoke test."""
    print("=== OID4VCI pre-authorized code smoke ===")
    print(f"BASE_URL={BASE_URL}")

    access_token = _client_token()
    print("1. jeton client obtenu")

    status, created = _post_json(
        "/credential-offer",
        {
            "subject": SUBJECT,
            "credential_configuration_ids": ["puridentityserver-sdjwt-vc"],
            "tx_code": USE_TX_CODE,
        },
        token=access_token,
    )
    if status != 200:
        print(f"creation d offre refusee ({status}) : {created}")
        return 1
    print(f"2. offre creee : {created['credential_offer_uri']}")

    offer_uri = str(created["credential_offer_uri"])
    status, offer = _get(offer_uri)
    if status != 200:
        print(f"dereferencement refuse ({status}) : {offer}")
        return 1
    grant = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    print(f"3. offre dereferencee (tx_code annonce : {'tx_code' in grant})")

    token_request = {
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": str(grant["pre-authorized_code"]),
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    if "tx_code" in created:
        token_request["tx_code"] = str(created["tx_code"])
    status, tokens = _post("/token", token_request)
    if status != 200:
        print(f"echange du code refuse ({status}) : {tokens}")
        return 1
    print("4. code pre-autorise echange contre un access token")

    issuer = str(offer["credential_issuer"])
    status, nonce_body = _post("/nonce", {})
    if status != 200:
        print(f"nonce refuse ({status}) : {nonce_body}")
        return 1
    proof, public_jwk = _proof(issuer, str(nonce_body["c_nonce"]))
    status, credential = _post_json(
        "/credential",
        {
            "credential_configuration_id": "puridentityserver-sdjwt-vc",
            "proofs": {"jwt": [proof]},
        },
        token=str(tokens["access_token"]),
    )
    if status != 200:
        print(f"emission refusee ({status}) : {credential}")
        return 1
    issued = str(credential["credentials"][0]["credential"])
    header = jwt.get_unverified_header(issued.split("~")[0])
    print(f"5. credential emis : typ={header.get('typ')} cnf={public_jwk['kid']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
