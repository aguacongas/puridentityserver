r"""Test manuel du request object signé RS256 d'un client standard (issue #188).

Smoke test du sample ``request-object-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8112, un
client seed **non-FAPI** portant des ``jwks`` RSA embarqués) puis joue le
scénario :

1. le discovery publie ``request_object_signing_alg_values_supported``
   avec ``RS256`` ;
2. ``/authorize`` avec ``request`` = JAR RS256 signé (``iss``/``aud`` +
   paramètres de demande) → ``302`` code d'autorisation (le client est
   résolu par le ``iss`` du jeton, sans ``client_id`` en query) ;
3. échange du code (PKCE) → ``200`` access_token + ``id_token`` ;
4. même demande, JAR signé par une **clé étrangère** → ``302``
   ``error=invalid_request_object`` redirigé au client (OIDC Core 1.0
   §10.3) ;
5. ``/authorize`` avec un JAR ``alg=none`` → ``302`` code : le request
   object non signé reste admis pour les clients standards.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/request-object-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8112
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-request-object-client"
REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"
_KID = "sample-request-object-key-1"

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _client_key() -> tuple[rsa.RSAPrivateKey, dict[str, object]]:
    """Paire RSA de test et la clé publique JWKS correspondante (``kid``/``alg``)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": _KID,
        "alg": "RS256",
        "n": n.rstrip(b"=").decode("ascii"),
        "e": e.rstrip(b"=").decode("ascii"),
    }
    return private, jwk


_PRIVATE, _PUBLIC_JWK = _client_key()

_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid profile email",
    "client_type": "public",
    "jwks": [_PUBLIC_JWK],
}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _claims(verifier: str) -> dict[str, object]:
    """Paramètres de demande d'autorisation de référence (PKCE + state/nonce)."""
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": "st-jar",
        "nonce": "n-jar-0123456789",
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
    }


def _signed_jar(
    private_key: rsa.RSAPrivateKey, verifier: str, *, claims: dict[str, object] | None = None
) -> str:
    """Signe un request object RS256 (OIDC Core 1.0 §10.1 : ``iss`` + ``aud``)."""
    payload: dict[str, object] = {"iss": CLIENT_ID, "aud": SERVER_URL, **_claims(verifier)}
    if claims is not None:
        payload.update(claims)
    return str(pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": _KID}))


def _unsigned_jar(verifier: str) -> str:
    """Construit un request object ``alg=none`` (RFC 9101 §5, sans signature)."""

    def segment(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{segment({'alg': 'none'})}.{segment(_claims(verifier))}."


def _code_of(response: httpx.Response) -> str:
    """Extrait le code d'autorisation du ``302`` attendu."""
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert "code" in query, query
    return str(query["code"][0])


def _run_scenario() -> None:
    """Joue le scénario request object RS256 de bout en bout."""
    verifier = "jar-verifier-0123456789"
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        algs = metadata["request_object_signing_alg_values_supported"]
        assert "RS256" in algs, algs
        print(f"  [1/5] discovery OK (request_object_signing_alg_values_supported={algs})")

        code = _code_of(
            http.get(f"{SERVER_URL}/authorize", params={"request": _signed_jar(_PRIVATE, verifier)})
        )
        print(
            "  [2/5] /authorize?request=JAR RS256 -> 302 (code émis, "
            "client résolu par le claim iss) OK"
        )

        response = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["id_token"]
        print("  [3/5] échange du code (PKCE) -> 200 access_token + id_token OK")

        foreign, _foreign_jwk = _client_key()
        response = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "request": _signed_jar(foreign, verifier),
            },
        )
        assert response.status_code == 302, response.text
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["error"] == ["invalid_request_object"], query
        assert query["state"] == ["st-jar"], query
        print("  [4/5] JAR signé par une clé étrangère -> 302 error=invalid_request_object OK")

        response = http.get(f"{SERVER_URL}/authorize", params={"request": _unsigned_jar(verifier)})
        _code_of(response)
        print("  [5/5] JAR alg=none -> 302 (request object non signé toujours admis) OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(port=SERVER_PORT, clients=(_CLIENT,)),
    ):
        print(
            f"\nScénario request object RS256 - client standard non-FAPI (deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
