"""Test manuel des algorithmes d'``id_token`` — HS* + JWE (issue #47).

Smoke test du sample ``id-token-algos-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8115,
registration activée, algorithmes de signature ``RS256``/``HS*``, comptes de
connexion ``alice``), puis joue le scénario :

1. le discovery annonce ``HS256`` dans ``id_token_signing_alg_values_supported``,
   ``RSA-OAEP-256`` dans ``id_token_encryption_alg_values_supported`` et
   ``A256GCM`` dans ``id_token_encryption_enc_values_supported`` ;
2. ``POST /register`` d'un client ``HS256`` + ``RSA-OAEP-256``/``A256GCM`` avec
   un JWK RSA ``use: enc`` -> ``201``, puis flow Authorization Code + PKCE
   (login ``alice`` inclus) : l'``id_token`` retourné est un **JWE compact**
   (en-tête ``alg=RSA-OAEP-256``, ``enc=A256GCM``, ``cty=JWT``) que le script
   **déchiffre** (clé privée locale) et dont il vérifie la signature **HS256**,
   ``iss``/``aud``/``nonce`` ;
3. ``PUT /register`` (RFC 7592) bascule en **symétrique** ``dir`` +
   ``A256CBC-HS512`` : l'``id_token`` se déchiffre avec la clé dérivée du secret
   partagé, signature HS256 toujours vérifiée ;
4. **défense structurelle** : un JWK RSA de 1024 bits -> ``400
   invalid_client_metadata`` (RFC 7518 §4.3 : minimum 2048 bits) ;
5. **défense d'usage** : un JWK RSA déclaré ``use: sig`` pour un
   ``RSA-OAEP-256`` -> ``400 invalid_client_metadata`` ;
6. **intégrité** : altérer un octet du JWE -> le déchiffrement lève
   (tag GCM / CBC-HMAC rejeté) ;
7. l'``id_token`` HS256 seul (sans chiffrement) est émis pour un client qui ne
   configure pas de ``id_token_encrypted_response_alg``.

Le sous-processus est terminé dans tous les cas (``finally``) et un garde-fou
borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/id-token-algos-client/smoke_test.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from secrets import token_urlsafe
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

from puridentityserver.domain.jwe import (
    JWEEncryptionMethod,
    JWEKeyManagementAlgorithm,
)
from puridentityserver.infrastructure.jwe import (
    b64u,
    b64u_decode,
    decrypt_compact,
    derive_content_key,
)

SERVER_PORT = 8115
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

_INITIAL_TOKEN = "dev-registrar-token"
_EMAIL = "alice@example.com"
_PASSWORD = "password"
_SCOPE = "openid profile email"
_REDIRECT_URI = f"{SERVER_URL}/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90
_JWKS_ALGORITHMS = ("RS256", "HS256", "HS384", "HS512")


def _rsa_jwk(private: rsa.RSAPrivateKey, *, use: str, alg: str, kid: str) -> dict[str, str]:
    """Construit le JWK public (``kty``/``use``/``alg``/``kid``/``n``/``e``) d'une clé RSA."""
    public = private.public_key().public_numbers()
    modulus = public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")
    exponent = public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": use,
        "alg": alg,
        "kid": kid,
        "n": b64u(modulus),
        "e": b64u(exponent),
    }


def _register(
    http: httpx.Client,
    *,
    jwks: dict[str, object] | None,
    alg: str,
    enc: str = "",
    signing: str = "HS256",
) -> httpx.Response:
    """Enregistre un client OIDC (HS* + JWE) et rend la réponse brute."""
    payload: dict[str, object] = {
        "redirect_uris": [_REDIRECT_URI],
        "scope": _SCOPE,
        "token_endpoint_auth_method": "client_secret_basic",
        "id_token_signed_response_alg": signing,
        "id_token_encrypted_response_alg": alg,
    }
    if enc:
        payload["id_token_encrypted_response_enc"] = enc
    if jwks is not None:
        payload["jwks"] = jwks
    return http.post(
        f"{SERVER_URL}/register",
        headers={"Authorization": f"Bearer {_INITIAL_TOKEN}"},
        json=payload,
    )


def _authorization_code_id_token(
    http: httpx.Client,
    *,
    issuer: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
) -> tuple[str, str]:
    """Joue le flow Authorization Code + PKCE (login ``alice``) et rend (id_token, nonce)."""
    state = token_urlsafe(16)
    nonce = token_urlsafe(16)
    verifier = token_urlsafe(32)
    challenge = b64u(hashlib.sha256(verifier.encode("utf-8")).digest())
    authorize_url = f"{issuer}/authorize?client_id={client_id}&response_type=code&scope={_SCOPE}"
    authorize_url += f"&redirect_uri={_REDIRECT_URI}&state={state}&nonce={nonce}"
    authorize_url += f"&code_challenge={challenge}&code_challenge_method=S256"
    authorize_url = authorize_url.replace(" ", "%20")

    response = http.post(
        f"{issuer}/login",
        data={"username": _EMAIL, "password": _PASSWORD, "next": authorize_url},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text

    response = http.get(authorize_url, follow_redirects=False)
    assert response.status_code in (302, 303), response.text
    callback = response.headers.get("location", "")
    query: dict[str, list[str]] = parse_qs(urlparse(callback).query)
    code = query.get("code", [""])[0]
    assert code and query.get("state") == [state], callback

    response = http.post(
        f"{issuer}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(client_id, client_secret),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body.get("id_token"), body
    return body["id_token"], nonce


def _assert_jwe(
    sealed: str,
    *,
    issuer: str,
    client_id: str,
    client_secret: str,
    nonce: str,
    private: rsa.RSAPrivateKey | None = None,
) -> dict[str, object]:
    """Valide l'``id_token`` JWE : en-tête, déchiffrement, signature HS256, claims."""
    parts = sealed.split(".")
    assert len(parts) == 5, "l'id_token n'est pas un JWE compact"
    header = json.loads(b64u_decode(parts[0]).decode("utf-8"))
    assert header["cty"] == "JWT"
    method = JWEEncryptionMethod(header["enc"])
    if header["alg"] in ("RSA-OAEP", "RSA-OAEP-256"):
        assert private is not None
        plaintext = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm(header["alg"]),
            method=method,
            rsa_private_key=private,
        )
    else:
        plaintext = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm(header["alg"]),
            method=method,
            shared_kek=derive_content_key(client_secret, method.cek_size),
        )
    claims = pyjwt.decode(
        plaintext.decode("utf-8"),
        client_secret,
        algorithms=["HS256", "HS384", "HS512"],
        audience=client_id,
        issuer=issuer,
    )
    assert claims["nonce"] == nonce
    assert claims.get("sub")
    return header


def _run_scenario() -> None:
    """Joue le scénario #47 de bout en bout (HS* + JWE + défenses)."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        issuer = metadata["issuer"]
        token_endpoint = metadata["token_endpoint"]
        assert "HS256" in metadata["id_token_signing_alg_values_supported"]
        assert "RSA-OAEP-256" in metadata["id_token_encryption_alg_values_supported"]
        assert "A256GCM" in metadata["id_token_encryption_enc_values_supported"]
        print("  [1/7] discovery OK (HS256 + RSA-OAEP-256 + A256GCM annoncés)")

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwks = {"keys": [_rsa_jwk(private, use="enc", alg="RSA-OAEP-256", kid="idtoken-rsa")]}
        response = _register(
            http,
            jwks=jwks,
            alg="RSA-OAEP-256",
            enc="A256GCM",
        )
        assert response.status_code == 201, response.text
        registered = response.json()
        client_id = registered["client_id"]
        client_secret = registered["client_secret"]
        assert registered["id_token_encrypted_response_alg"] == "RSA-OAEP-256"
        sealed, nonce = _authorization_code_id_token(
            http,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
        )
        header = _assert_jwe(
            sealed,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            nonce=nonce,
            private=private,
        )
        assert header["alg"] == "RSA-OAEP-256" and header["enc"] == "A256GCM"
        print("  [2/7] POST /register asym + flow -> id_token JWE (RSA-OAEP-256/A256GCM) OK")

        registry_uri = registered["registration_client_uri"]
        registry_token = registered["registration_access_token"]
        update = {
            "redirect_uris": [_REDIRECT_URI],
            "scope": _SCOPE,
            "id_token_signed_response_alg": "HS256",
            "id_token_encrypted_response_alg": "dir",
            "id_token_encrypted_response_enc": "A256CBC-HS512",
        }
        response = http.put(
            registry_uri,
            headers={"Authorization": f"Bearer {registry_token}"},
            json=update,
        )
        assert response.status_code == 200, response.text
        assert response.json()["id_token_encrypted_response_alg"] == "dir"
        sealed, nonce = _authorization_code_id_token(
            http,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
        )
        header = _assert_jwe(
            sealed,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            nonce=nonce,
        )
        assert header["alg"] == "dir" and header["enc"] == "A256CBC-HS512"
        print("  [3/7] PUT /register -> dir + A256CBC-HS512 (dérivé du secret partagé) OK")

        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        response = _register(
            http,
            jwks={"keys": [_rsa_jwk(weak, use="enc", alg="RSA-OAEP", kid="weak")]},
            alg="RSA-OAEP",
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client_metadata"
        print("  [4/7] module RSA de 1024 bits -> 400 invalid_client_metadata (RFC 7518 §4.3) OK")

        enc_only = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        response = _register(
            http,
            jwks={
                "keys": [_rsa_jwk(enc_only, use="sig", alg="RSA-OAEP-256", kid="sig-key")],
            },
            alg="RSA-OAEP-256",
            enc="A256GCM",
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client_metadata"
        print("  [5/7] clé RSA use:sig pour RSA-OAEP -> 400 invalid_client_metadata OK")

        tampered = (
            sealed[: len(sealed) // 2]
            + (chr(ord(sealed[len(sealed) // 2]) ^ 0x20))
            + sealed[len(sealed) // 2 + 1 :]
        )
        try:
            _assert_jwe(
                tampered,
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                nonce=nonce,
            )
        except Exception:
            print("  [6/7] id_token altéré -> déchiffrement rejeté (intégrité) OK")
        else:
            raise AssertionError("un JWE altéré a été déchiffré sans erreur")

        response = _register(
            http,
            jwks=None,
            alg="",
            signing="HS256",
        )
        assert response.status_code == 201, response.text
        clean_client = response.json()
        sealed, nonce = _authorization_code_id_token(
            http,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=clean_client["client_id"],
            client_secret=clean_client["client_secret"],
        )
        header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
        assert header.get("alg", "") == "HS256" and len(sealed.split(".")) == 3
        print("  [7/7] id_token HS256 seul (sans chiffrement) émis en JWS OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(),
            users={"alice": {"email": _EMAIL, "password": _PASSWORD}},
            registration_enabled=True,
            registration_initial_access_tokens=(_INITIAL_TOKEN,),
            jwks_algorithms=_JWKS_ALGORITHMS,
        ),
    ):
        print(f"\nScénario algorithmes d'id_token HS* + JWE (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
