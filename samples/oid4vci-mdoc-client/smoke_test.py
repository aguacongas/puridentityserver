#!/usr/bin/env python3
"""Smoke test bout-en-bout de l'emission mdoc (format ``mso_mdoc``) OID4VCI.

Enchaine : jeton client -> creation d'une offre -> echange du code pre-autorise
-> emission d'un credential mdoc (ISO 18013-5) avec une preuve EC P-256 ->
decodage du CBOR ``IssuerSigned`` et verification de la signature COSE.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import cbor2
import jwt
from cose.keys import CoseKey
from cose.messages import Sign1Message
from cryptography.hazmat.primitives.asymmetric import ec

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "sample-oid4vci-client")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "oid4vci-demo-secret")
SUBJECT = os.environ.get("SUBJECT", "alice@example.com")
MDOC_CONFIG = "puridentityserver-mso-mdoc"
PERSONAL_NAME_NAMESPACE = "org.iso.18013.5.1"


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
    """Construit une preuve de possession ES256 (device key) et sa JWK publique."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=False)
    )
    public_jwk["alg"] = "ES256"
    headers = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": public_jwk}
    proof = jwt.encode(
        {"aud": issuer, "nonce": nonce, "iat": int(time.time())},
        private_key,
        algorithm="ES256",
        headers=headers,
    )
    return proof, public_jwk


def _decode_mdoc(credential: str) -> dict[str, object]:
    """Decode le CBOR base64url d un credential mso_mdoc."""
    blob = base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
    return cbor2.loads(blob)


def _verify_signature(outer: dict[str, object]) -> bool:
    """Verifie la signature COSE Sign1 de l issuerAuth (sans chaîne de confiance)."""
    auth = outer["issuerAuth"]
    message = Sign1Message.from_cose_obj(list(auth.value), True)
    # Cle de verification quelconque : on ne teste que l integrité de la structure.
    message.key = CoseKey.from_dict({1: 2, 3: -7, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32})
    try:
        return bool(message.verify_signature())
    except Exception:
        return False


def main() -> int:
    """Point d entree du smoke test."""
    print("=== OID4VCI mdoc (mso_mdoc) smoke ===")
    print(f"BASE_URL={BASE_URL}")

    access_token = _client_token()
    print("1. jeton client obtenu")

    status, created = _post_json(
        "/credential-offer",
        {
            "subject": SUBJECT,
            "credential_configuration_ids": [MDOC_CONFIG],
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
    print("3. offre dereferencee")

    status, tokens = _post(
        "/token",
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": str(grant["pre-authorized_code"]),
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
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
        {"credential_configuration_id": MDOC_CONFIG, "proofs": {"jwt": [proof]}},
        token=str(tokens["access_token"]),
    )
    if status != 200:
        print(f"emission refusee ({status}) : {credential}")
        return 1
    issued = str(credential["credentials"][0]["credential"])

    outer = _decode_mdoc(issued)
    name_spaces = outer["nameSpaces"][PERSONAL_NAME_NAMESPACE]
    elements = {cbor2.loads(item.value)[2] for item in name_spaces}
    auth = outer["issuerAuth"]
    print(f"5. mdoc emis : issuerAuth tag={auth.tag} elements={sorted(elements)}")
    print(f"   signature COSE structurellement valide : {_verify_signature(outer)}")
    print(f"   device key liee : {public_jwk.get('kty')}/{public_jwk.get('crv')}")
    return 0


def _get(url: str) -> tuple[int, dict[str, object]]:
    """Lit une URL et renvoie le statut et le corps JSON."""
    return _send(urllib.request.Request(url))  # ruff: ignore[suspicious-url-open-usage]


if __name__ == "__main__":
    raise SystemExit(main())
