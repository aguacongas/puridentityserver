#!/usr/bin/env python3
"""Smoke test du flux interactif OpenID4VCI (authorization code).

Deux modes d'authentification client :

- défaut : un client enregistré au préalable (voir README), échange du code
  sans credential client (client public) ;
- ``CLIENT_AUTH=attest_jwt_client_auth`` : le client est créé par DCR avec
  la méthode d'attestation (draft-ietf-oauth-attestation-based-client-auth),
  la demande est poussée via ``POST /par`` et l'échange ``/token`` porte les
  en-têtes ``OAuth-Client-Attestation`` / ``OAuth-Client-Attestation-PoP``.

Avec ``ENCRYPTION=1`` (OP démarré en ``oid4vci_encryption_enabled=true``), le
wallet demande le chiffrement de la réponse (OID4VCI 1.0 §8.2) et déchiffre
le JWE renvoyé en ``application/jwt``.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from puridentityserver.domain.jwe import ECDH_ES, JWEEncryptionMethod
from puridentityserver.infrastructure.jwe import (
    decrypt_compact_ecdh_es,
    ec_jwk,
    protected_header,
)

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "sample-oid4vci-authcode-client")
CLIENT_AUTH = os.environ.get("CLIENT_AUTH", "")
ATTEST_METHOD = "attest_jwt_client_auth"
ATTESTER_ISSUER = os.environ.get("ATTESTER_ISSUER", "https://client-attester.example.org/")
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN", "dev-registrar-token")
ENCRYPTION = os.environ.get("ENCRYPTION", "") == "1"
REDIRECT_URI = "http://127.0.0.1:8765/callback"
CALLBACK_PORT = 8765

#: Clé attester de DÉMONSTRATION (à jeter) : sa clé publique configure l'OP
#: via ``PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS`` (README du sample).
_ATTESTER_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzZXsNPkt6VFkTen0
qSSPSoyPmrsDGlFL6Hk5blj/2KOhRANCAART2mF3jWNlgUDgAuxp+y8MfNrwf0hi
SzQAYXEnL1YcN/Ou5PWr1XP9LqGsCGPD06TgZwQPlXHRT3HY2oxelRuX
-----END PRIVATE KEY-----"""


def _send(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    """Envoie une requete et renvoie le statut et le corps JSON."""
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:
        payload = error.read().decode()
        try:
            return error.code, json.loads(payload or "{}")
        except json.JSONDecodeError:
            return error.code, {"error": payload}


def _post_form(
    path: str, data: dict[str, str], headers: dict[str, str] | None = None
) -> tuple[int, dict[str, object]]:
    """Poste un formulaire et renvoie le statut et le corps JSON."""
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(BASE_URL + path, data=body, method="POST")  # ruff: ignore[suspicious-url-open-usage]
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
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


def _post_json_raw(path: str, payload: dict[str, object], token: str = "") -> tuple[int, str, str]:
    """Poste un corps JSON et renvoie statut, media type et corps brut.

    Sert aux réponses ``application/jwt`` (credential response chiffré,
    OID4VCI 1.0 §8.2) que ``_send`` ne peut pas parser en JSON.
    """
    request = urllib.request.Request(  # ruff: ignore[suspicious-url-open-usage]
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
            media_type = response.headers.get("Content-Type", "").partition(";")[0]
            return response.status, media_type, response.read().decode()
    except urllib.error.HTTPError as error:
        media_type = error.headers.get("Content-Type", "").partition(";")[0]
        return error.code, media_type, error.read().decode()


def _attester_key() -> ec.EllipticCurvePrivateKey:
    """Charge la cle privee attester de demonstration (PEM embarque)."""
    key = serialization.load_pem_private_key(_ATTESTER_PEM.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit("cle attester de demonstration invalide")
    return key


def _attestation_headers(client_id: str, wallet_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """Construit les en-tetes d'attestation + PoP d'une requete (§6.1).

    L'attestation (signee par l'attester de confiance) porte le ``cnf.jwk``
    de l'instance client ; chaque requete sonde un PoP neuf (``jti``
    unique — anti-replay §9-12) signe par cette cle.
    """
    now = int(time.time())
    wallet_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(wallet_key.public_key(), as_dict=False)
    )
    wallet_jwk.update(kid="wallet-demo", alg="ES256", use="sig")
    attestation = jwt.encode(
        {
            "iss": ATTESTER_ISSUER,
            "sub": client_id,
            "iat": now,
            "exp": now + 300,
            "cnf": {"jwk": wallet_jwk},
        },
        _attester_key(),
        algorithm="ES256",
        headers={"typ": "oauth-client-attestation+jwt", "kid": "ct-attester-demo"},
    )
    pop = jwt.encode(
        {"iss": client_id, "aud": BASE_URL, "iat": now, "jti": str(uuid.uuid4())},
        wallet_key,
        algorithm="ES256",
        headers={"typ": "oauth-client-attestation-pop+jwt", "kid": "wallet-demo"},
    )
    return {"OAuth-Client-Attestation": attestation, "OAuth-Client-Attestation-PoP": pop}


def _register_attest_client() -> str:
    """Cree le client du sample en DCR avec la methode attest_jwt_client_auth."""
    status, body = _post_json(
        "/register",
        {
            "redirect_uris": [REDIRECT_URI],
            "scope": "openid profile email",
            "token_endpoint_auth_method": ATTEST_METHOD,
        },
        token=REGISTRATION_TOKEN,
    )
    if status != 201:
        print(f"enregistrement refuse ({status}) : {body}")
        print(
            "verifiez que l'OP demarre avec PURIDENTITYSERVER_CLIENT_ATTESTATION_ISSUER "
            "et PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS (README)"
        )
        raise SystemExit(1)
    return str(body["client_id"])


def _resolve_client() -> tuple[str, ec.EllipticCurvePrivateKey | None]:
    """Retourne le client du sample et, en mode attestation, sa cle PoP."""
    if CLIENT_AUTH != ATTEST_METHOD:
        return CLIENT_ID, None
    wallet_key = ec.generate_private_key(ec.SECP256R1())
    client_id = _register_attest_client()
    print(f"client enregistre (DCR, {ATTEST_METHOD}) : {client_id}")
    return client_id, wallet_key


def _push_request(
    client_id: str, wallet_key: ec.EllipticCurvePrivateKey, params: dict[str, str]
) -> dict[str, str] | None:
    """Pousse la demande via /par avec les en-tetes d'attestation (RFC 9126).

    Retourne les parametres d'/authorize (``client_id`` + ``request_uri``)
    ou ``None`` si le push est refuse.
    """
    status, pushed = _post_form("/par", params, headers=_attestation_headers(client_id, wallet_key))
    if status != 201:
        print(f"push refuse ({status}) : {pushed}")
        return None
    print("demande poussee (PAR) :", pushed.get("request_uri"))
    return {"client_id": client_id, "request_uri": str(pushed.get("request_uri", ""))}


def _exchange_code(
    client_id: str, code: str, headers: dict[str, str] | None
) -> dict[str, object] | None:
    """Echange le code contre les jetons, avec les en-tetes d'attestation le cas echeant."""
    status, tokens = _post_form(
        "/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
        },
        headers=headers,
    )
    if status != 200:
        print(f"echange refuse ({status}) : {tokens}")
        return None
    return tokens


def _start_callback_server(captured: dict[str, str]) -> http.server.HTTPServer:
    """Demarre le serveur local qui recoit la redirect_uri du flow."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/callback":
                params = urllib.parse.parse_qs(parsed.query)
                captured["code"] = params.get("code", [""])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>OK - retournez au terminal</h1>")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _encryption_request() -> tuple[dict[str, object], ec.EllipticCurvePrivateKey] | None:
    """Verifie la capability et construit ``credential_response_encryption``.

    Retourne ``None`` (avec un message) si l OP n annonce pas les blocs de
    chiffrement des metadonnees.
    """
    status, metadata = _send(
        urllib.request.Request(  # ruff: ignore[suspicious-url-open-usage]
            BASE_URL + "/.well-known/openid-credential-issuer"
        )
    )
    if status != 200 or "credential_response_encryption" not in metadata:
        print("capability de chiffrement absente des metadonnees")
        return None
    print(
        "capability de chiffrement annoncee (enc_values :"
        f" {metadata['credential_response_encryption']['enc_values_supported']})"
    )
    # Le wallet chiffre avec sa propre paire EC P-256 (OID4VCI s8.2).
    enc_key = ec.generate_private_key(ec.SECP256R1())
    enc_jwk = ec_jwk(enc_key.public_key())
    enc_jwk["kid"] = "sample-oid4vci-encryption"
    enc_jwk["alg"] = ECDH_ES
    enc_jwk["use"] = "enc"
    return (
        {"jwk": enc_jwk, "enc": JWEEncryptionMethod.A256GCM.value},
        enc_key,
    )


def _emit_credential(
    payload: dict[str, object],
    token: str,
    enc_key: ec.EllipticCurvePrivateKey | None,
) -> int:
    """Emet le credential, dechiffre la reponse si le chiffrement etait demande."""
    if enc_key is None:
        status, cred = _post_json("/credential", payload, token=token)
        if status != 200:
            print(f"emission refusee ({status}) : {cred}")
            return 1
        print("credential emis :", str(cred["credentials"][0]["credential"])[:40], "...")
        return 0

    status, media_type, body = _post_json_raw("/credential", payload, token=token)
    if status != 200:
        print(f"emission refusee ({status}) : {body}")
        return 1
    if media_type != "application/jwt":
        print(f"reponse non chiffree inattendue ({media_type})")
        return 1
    header = protected_header(body)
    cred = json.loads(decrypt_compact_ecdh_es(body, private_key=enc_key))
    print(f"reponse chiffree (alg {header['alg']}, enc {header['enc']}, kid {header.get('kid')})")
    print("credential emis :", str(cred["credentials"][0]["credential"])[:40], "...")
    return 0


def main() -> int:
    """Point d entree du smoke test."""
    captured: dict[str, str] = {}
    server = _start_callback_server(captured)

    details = json.dumps(
        [{"type": "openid_credential", "credential_configuration_id": "puridentityserver-sdjwt-vc"}]
    )
    client_id, wallet_key = _resolve_client()
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid4vci",
        "authorization_details": details,
        "state": "sample-state",
    }
    if wallet_key is not None:
        pushed = _push_request(client_id, wallet_key, params)
        if pushed is None:
            return 1
        params = pushed
    auth_url = BASE_URL + "/authorize?" + urllib.parse.urlencode(params)
    print("Ouvrez cette URL dans votre navigateur :")
    print(auth_url)
    webbrowser.open(auth_url)

    deadline = time.time() + 300
    while "code" not in captured and time.time() < deadline:
        time.sleep(0.5)
    server.shutdown()

    code = captured.get("code")
    if not code:
        print("aucun code recu")
        return 1
    print("code recu")

    token_headers = _attestation_headers(client_id, wallet_key) if wallet_key else None
    tokens = _exchange_code(client_id, code, token_headers)
    if tokens is None:
        return 1
    print("access token recu ; authorization_details present :", "authorization_details" in tokens)

    issuer = BASE_URL
    status, nb = _post_form("/nonce", {})
    if status != 200:
        print(f"nonce refuse ({status}) : {nb}")
        return 1
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(
        jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=False)
    )
    public_jwk["alg"] = "ES256"
    proof = jwt.encode(
        {"aud": issuer, "nonce": nb["c_nonce"], "iat": int(time.time())},
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        algorithm="ES256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": public_jwk},
    )

    payload: dict[str, object] = {
        "credential_identifier": "puridentityserver-sdjwt-vc",
        "proofs": {"jwt": [proof]},
    }
    enc_key: ec.EllipticCurvePrivateKey | None = None
    if ENCRYPTION:
        encryption = _encryption_request()
        if encryption is None:
            return 1
        requested, enc_key = encryption
        payload["credential_response_encryption"] = requested

    return _emit_credential(payload, str(tokens["access_token"]), enc_key)


if __name__ == "__main__":
    raise SystemExit(main())
