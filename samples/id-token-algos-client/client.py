"""Client de démonstration : algorithmes d'``id_token`` — HS* + JWE (issue #47).

Un client est enregistré **dynamiquement** (RFC 7591) avec deux réglages
OIDC (Core 1.0 §3.1.3.1 / §3.1.3.6), puis un flow Authorization Code + PKCE
complet (login inclus) est joué pour en observer l'``id_token`` :

1. ``id_token_signed_response_alg: HS256`` — l'``id_token`` est **signé** avec
   le secret partagé du client (jamais publié au JWKS du serveur) ;
2. ``id_token_encrypted_response_alg: RSA-OAEP-256`` — l'``id_token`` signé est
   **chiffré** en JWE compact (RFC 7516) pour le client, avec sa clé publique
   RSA (JWK ``use: enc`` enregistrée dans le ``jwks`` du client).

Le script déchiffre le JWE (clé privée locale), vérifie la signature HS256 du
jeton imbriqué (``cty: JWT``) et contrôle ``iss``/``aud``/``nonce``. Il montre
ensuite la bascule en famille **symétrique** (``dir`` + ``A256CBC-HS512`` : la
clé de contenu est dérivée du secret partagé) par ``PUT /register`` (RFC
7592), et la **défense** du serveur contre une clé RSA courte/au ``use``
incohérent (``invalid_client_metadata``).

Usage (depuis la racine du dépôt, serveur PurIdentityServer déjà démarré sur
le port ``8000`` par défaut - voir README.md) :

    uv run python samples/id-token-algos-client/client.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from secrets import token_urlsafe
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from puridentityserver.domain.jwe import (
    ASYMMETRIC_ENCRYPTION_ALGORITHMS,
    JWEEncryptionMethod,
    JWEKeyManagementAlgorithm,
)
from puridentityserver.infrastructure.jwe import (
    b64u,
    b64u_decode,
    decrypt_compact,
    derive_content_key,
)

_HTTP_TIMEOUT = 10

_ISSUER = os.environ.get("ITA_ISSUER", "http://127.0.0.1:8000")
_REGISTER_TOKEN = os.environ.get("ITA_REGISTER_TOKEN", "dev-registrar-token")
_EMAIL = os.environ.get("ITA_EMAIL", "alice@example.com")
_PASSWORD = os.environ.get("ITA_PASSWORD", "password")
_SCOPE = os.environ.get("ITA_SCOPE", "openid profile email")


def _discovery() -> dict[str, object]:
    """Charge le document de discovery du serveur."""
    response = httpx.get(
        urljoin(_ISSUER.rstrip("/") + "/", ".well-known/openid-configuration"),
        timeout=_HTTP_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _rsa_jwk(
    private: RSAPrivateKey,
    *,
    use: str,
    alg: str,
    kid: str,
) -> dict[str, str]:
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
    register_endpoint: str,
    *,
    jwks: dict[str, object] | None,
    alg: str,
    enc: str,
    redirect_uri: str,
) -> dict[str, object]:
    """Enregistre un client OIDC mis en forme HS256 + JWE (RFC 7591)."""
    payload: dict[str, object] = {
        "redirect_uris": [redirect_uri],
        "scope": _SCOPE,
        "token_endpoint_auth_method": "client_secret_basic",
        "id_token_signed_response_alg": "HS256",
        "id_token_encrypted_response_alg": alg,
        "id_token_encrypted_response_enc": enc,
    }
    if jwks is not None:
        payload["jwks"] = jwks
    response = httpx.post(
        register_endpoint,
        headers={"Authorization": f"Bearer {_REGISTER_TOKEN}"},
        json=payload,
        timeout=_HTTP_TIMEOUT,
    )
    if response.status_code != 201:
        print(f"Échec de l'enregistrement : HTTP {response.status_code} - {response.text}")
        sys.exit(1)
    return response.json()


def _authorization_code_id_token(
    http: httpx.Client,
    *,
    issuer: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> tuple[str, str]:
    """Joue le flow Authorization Code + PKCE et rend ``(id_token, nonce)``."""
    state = token_urlsafe(16)
    nonce = token_urlsafe(16)
    verifier = token_urlsafe(32)
    challenge = b64u(hashlib.sha256(verifier.encode("utf-8")).digest())
    authorize_query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "scope": _SCOPE,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    authorize_url = f"{issuer}/authorize?{authorize_query}"

    response = http.post(
        f"{issuer}/login",
        data={"username": _EMAIL, "password": _PASSWORD, "next": authorize_url},
        follow_redirects=False,
    )
    if response.status_code != 302:
        raise RuntimeError(f"login : HTTP {response.status_code} - {response.text}")

    response = http.get(authorize_url, follow_redirects=False)
    if response.status_code not in (302, 303):
        raise RuntimeError(
            f"authorize (après login) : HTTP {response.status_code} - {response.text}"
        )
    callback = response.headers.get("location", "")
    query_params: dict[str, list[str]] = parse_qs(urlparse(callback).query)
    code = query_params.get("code", [""])[0]
    if not code or query_params.get("state") != [state]:
        raise RuntimeError(f"authorize sans code/state : {callback}")

    response = http.post(
        f"{issuer}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        auth=(client_id, client_secret),
    )
    if response.status_code != 200:
        raise RuntimeError(f"token : HTTP {response.status_code} - {response.text}")
    id_token = response.json().get("id_token", "")
    if not id_token:
        raise RuntimeError("token sans id_token (flow non OIDC ?)")
    return id_token, nonce


def _unwrap(
    sealed: str,
    *,
    algorithm: str,
    method: str,
    private: RSAPrivateKey | None = None,
    shared_secret: str = "",
) -> str:
    """Déchiffre un JWE compact et rend le JWS imbriqué (``cty: JWT``)."""
    if algorithm in tuple(item.value for item in ASYMMETRIC_ENCRYPTION_ALGORITHMS):
        if private is None:
            raise RuntimeError("un JWE RSA-OAEP exige la clé privée du client")
        sealed_bytes = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm(algorithm),
            method=JWEEncryptionMethod(method),
            rsa_private_key=private,
        )
    else:
        sealed_bytes = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm(algorithm),
            method=JWEEncryptionMethod(method),
            shared_kek=derive_content_key(shared_secret, JWEEncryptionMethod(method).cek_size),
        )
    return sealed_bytes.decode("utf-8")


def _verify(
    sealed: str,
    *,
    issuer: str,
    client_id: str,
    client_secret: str,
    nonce: str,
    private: RSAPrivateKey | None = None,
) -> None:
    """Déchiffre, vérifie la signature HS256 de l'``id_token`` et ses claims."""
    header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
    print(f"  JWE header : alg={header['alg']} enc={header['enc']} cty={header.get('cty')}")
    jws = _unwrap(
        sealed,
        algorithm=header["alg"],
        method=header["enc"],
        private=private,
        shared_secret=client_secret,
    )
    claims = pyjwt.decode(
        jws,
        client_secret,
        algorithms=["HS256"],
        audience=client_id,
        issuer=issuer,
    )
    if claims["nonce"] != nonce or not claims["sub"]:
        raise RuntimeError("id_token invalide (nonce/sub incohérents)")
    print("  id_token déchiffré + signature HS256 vérifiée :")
    print(f"    iss={claims['iss']} aud={claims['aud']} sub={claims['sub']}")


def main() -> None:
    """Enregistre un client, joue le flow, vérifie le JWE, bascule en symétrique."""
    metadata = _discovery()
    issuer = metadata["issuer"]  # type: ignore[union-attr]
    token_endpoint = metadata["token_endpoint"]  # type: ignore[arg-type]
    register_endpoint = metadata["registration_endpoint"]  # type: ignore[arg-type]
    print(f"Discovery : signing={', '.join(metadata['id_token_signing_alg_values_supported'])}")
    print(
        "JWE alg={} enc={}".format(  # type: ignore[union-attr]
            ", ".join(metadata["id_token_encryption_alg_values_supported"]),
            ", ".join(metadata["id_token_encryption_enc_values_supported"]),
        )
    )

    redirect_uri = f"{_ISSUER}/callback"
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {
        "keys": [_rsa_jwk(private, use="enc", alg="RSA-OAEP-256", kid="idtoken-rsa")],
    }
    registered = _register(
        register_endpoint,
        jwks=jwks,
        alg=JWEKeyManagementAlgorithm.RSA_OAEP_256.value,
        enc=JWEEncryptionMethod.A256GCM.value,
        redirect_uri=redirect_uri,
    )
    client_id = registered["client_id"]  # type: ignore[arg-type]
    client_secret = registered["client_secret"]  # type: ignore[arg-type]
    registry_token = registered["registration_access_token"]  # type: ignore[arg-type]
    registry_uri = registered["registration_client_uri"]  # type: ignore[arg-type]
    print(f"Registration (RFC 7591) : client_id={client_id}, HS256 + RSA-OAEP-256/A256GCM")

    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        sealed, nonce = _authorization_code_id_token(
            http,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )
        print("Flow Authorization Code + PKCE (login inclus) :")
        _verify(
            sealed,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            nonce=nonce,
            private=private,
        )

        response = httpx.put(
            registry_uri,
            headers={"Authorization": f"Bearer {registry_token}"},
            json={
                "redirect_uris": [redirect_uri],
                "scope": _SCOPE,
                "id_token_signed_response_alg": "HS256",
                "id_token_encrypted_response_alg": "dir",
                "id_token_encrypted_response_enc": "A256CBC-HS512",
            },
            timeout=_HTTP_TIMEOUT,
        )
        if response.status_code != 200:
            print(f"Échec du PUT /register : HTTP {response.status_code} - {response.text}")
            sys.exit(1)

        sealed_symmetric, nonce_symmetric = _authorization_code_id_token(
            http,
            issuer=issuer,
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )
        print("Bascule symétrique (PUT /register -> dir + A256CBC-HS512) :")
        _verify(
            sealed_symmetric,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            nonce=nonce_symmetric,
        )

    weak_private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    response = httpx.post(
        register_endpoint,
        headers={"Authorization": f"Bearer {_REGISTER_TOKEN}"},
        json={
            "redirect_uris": [redirect_uri],
            "id_token_encrypted_response_alg": "RSA-OAEP",
            "jwks": {"keys": [_rsa_jwk(weak_private, use="enc", alg="RSA-OAEP", kid="weak")]},
        },
        timeout=_HTTP_TIMEOUT,
    )
    print("Défense du serveur (module RSA de 1024 bits, RFC 7518 §4.3) :")
    print(f"  -> HTTP {response.status_code} : {response.text}")


if __name__ == "__main__":
    sys.exit(main())
