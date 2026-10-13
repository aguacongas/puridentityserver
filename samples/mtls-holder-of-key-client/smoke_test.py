r"""Parcours de démonstration mTLS holder-of-key RFC 8705 (issue #127).

Lance un serveur PurIdentityServer en sous-processus (port 8118) avec un
client ``sample-hok-client`` (``private_key_jwt`` à clé RSA statique)
enregistré ``tls_client_certificate_bound_access_tokens = true`` et des
noms d'en-têtes mTLS **personnalisés** (``client_certificate_header =
"X-Proxy-Client-Cert"``) qui simulent un proxy de terminaison TLS — le
PEM du certificat client est envoyé dans cet en-tête, au format
``\\n``-échappé comme nginx / Cloudflare le font. Puis joue le flux
complet en 8 étapes :

1. discovery : ``tls_client_certificate_bound_access_tokens`` ;
2. ``POST /token`` (``client_credentials``) **sans** en-tête certificat →
   ``400 invalid_client`` (« Certificat client mTLS requis ») ;
3. idem **avec** le certificat → ``200`` : l'access token porte
   ``cnf.x5t#S256`` (empreinte SHA-256 du DER, RFC 8705 §3.1) ;
4. ``GET /protected-resource`` (Bearer + bon certificat) → ``200`` ;
5. idem avec un **autre** certificat → ``401`` (liaison opposée) ;
6. idem **sans** certificat → ``401`` ;
7. flow ``authorization_code`` (démo sans login) échange le code avec le
   certificat → ``200`` : access token lié **et** refresh token lié au
   certificat (``tls_cert_hash``) ;
8. ``grant_type=refresh_token`` : même certificat → ``200`` (jetons
   rotés) ; autre certificat → ``400 invalid_grant`` ; sans certificat →
   ``400 invalid_client`` (RFC 8705 §3.3).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/mtls-holder-of-key-client/smoke_test.py
"""

from __future__ import annotations

import base64
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8118
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-hok-client"
REDIRECT_URI = "http://127.0.0.1:5178/callback"
SCOPE = "openid offline_access"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
#: En-tête mTLS personnalisé (le serveur le lit à la place du défaut
#: ``X-SSL-Client-Cert`` — démonstration de la config par plateforme).
CERT_HEADER = "X-Proxy-Client-Cert"

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _rsa_jwks(kid: str) -> tuple[rsa.RSAPrivateKey, list[dict[str, object]]]:
    """Clé privée RSA de test et JWKS embarqué (``n``/``e`` base64url)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()

    def b64(value: int) -> str:
        length = (value.bit_length() + 7) // 8
        raw = value.to_bytes(length, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwk: dict[str, object] = {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": b64(numbers.n),
        "e": b64(numbers.e),
    }
    return private, [jwk]


def _self_signed_pem(common_name: str) -> tuple[str, bytes]:
    """Certificat auto-signé de test : couple ``(PEM, DER)``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(Encoding.PEM).decode("ascii")
    return pem, certificate.public_bytes(Encoding.DER)


def _thumbprint(der: bytes) -> str:
    """Empreinte ``x5t#S256`` (base64url sans padding, RFC 8705 §2.1.2)."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return base64.urlsafe_b64encode(digest.finalize()).rstrip(b"=").decode("ascii")


def _assertion(private: rsa.RSAPrivateKey, kid: str, issuer: str) -> str:
    """Assertion ``private_key_jwt`` fraîche (``iss = sub = client_id``)."""
    now = int(time.time())
    return str(
        pyjwt.encode(
            {
                "iss": CLIENT_ID,
                "sub": CLIENT_ID,
                "aud": f"{issuer}/token",
                "exp": now + 600,
                "iat": now,
            },
            private,
            algorithm="RS256",
            headers={"kid": kid},
        )
    )


def _escaped_pem(pem: str) -> str:
    r"""PEM au format ``\n``-échappé, comme un proxy de terminaison l'envoie."""
    return pem.replace("\n", "\\n")


def _cert_headers(pem: str | None) -> dict[str, str]:
    """En-tête de certificat personnalisé, ou dict vide (absence de mTLS)."""
    return {CERT_HEADER: _escaped_pem(pem)} if pem else {}


def _token(
    http: httpx.Client,
    private: rsa.RSAPrivateKey,
    kid: str,
    issuer: str,
    data: dict[str, str],
    certificate_pem: str | None,
) -> httpx.Response:
    """POST /token avec l'assertion ``private_key_jwt`` et le certificat éventuel."""
    form = {
        **data,
        "client_id": CLIENT_ID,
        "client_assertion": _assertion(private, kid, issuer),
        "client_assertion_type": ASSERTION_TYPE,
    }
    return http.post(f"{SERVER_URL}/token", data=form, headers=_cert_headers(certificate_pem))


def _resource(http: httpx.Client, access_token: str, certificate_pem: str | None) -> httpx.Response:
    """GET /protected-resource avec le Bearer et le certificat éventuel."""
    headers = {"Authorization": f"Bearer {access_token}"}
    headers.update(_cert_headers(certificate_pem))
    return http.get(f"{SERVER_URL}/protected-resource", headers=headers)


def _authorize(http: httpx.Client) -> str:
    """Appelle ``/authorize`` (démo sans login) et retourne le ``code`` émis."""
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": "hok-state",
        },
    )
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert urlparse(location).query, location
    return parse_qs(urlparse(location).query)["code"][0]


def _run_scenario() -> None:
    """Joue les 8 étapes du parcours mTLS holder-of-key."""
    pem, der = _self_signed_pem("sample-hok-client.example")
    other_pem, _ = _self_signed_pem("other-client.example")
    expected_thumbprint = _thumbprint(der)
    private, jwks = _rsa_jwks("sample-hok-kid")

    clients = (
        {
            "client_id": CLIENT_ID,
            "redirect_uris": [REDIRECT_URI],
            "scopes": SCOPE,
            "client_type": "confidential",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks,
            "tls_client_certificate_bound_access_tokens": True,
        },
    )

    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=clients,
            extra_settings={
                "client_certificate_header": CERT_HEADER,
                "client_certificate_dn_header": "X-Proxy-Subject-DN",
                "protected_resource_enabled": True,
            },
        ) as server_url,
    ):
        print(f"OP mTLS démarré sur {server_url} (en-tête certificat {CERT_HEADER})")
        issuer = server_url
        with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
            metadata = http.get(f"{server_url}/.well-known/openid-configuration").json()
            assert metadata.get("tls_client_certificate_bound_access_tokens") is True, sorted(
                metadata
            )
            print("étape 1/8  discovery : tls_client_certificate_bound_access_tokens  OK")

            refused = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {"grant_type": "client_credentials", "scope": "openid"},
                None,
            )
            payload = dict(refused.json())
            assert refused.status_code == 400, (refused.status_code, payload)
            assert payload.get("error") == "invalid_client", payload
            print("étape 2/8  client_credentials sans certificat -> 400 invalid_client  OK")

            issued = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {"grant_type": "client_credentials", "scope": "openid"},
                pem,
            )
            assert issued.status_code == 200, (issued.status_code, issued.text[:300])
            access_token = str(issued.json()["access_token"])
            claims = pyjwt.decode(  # NOSONAR(S5659) - lecture seule du jeton émis par le OP local
                access_token, options={"verify_signature": False}
            )
            cnf = claims.get("cnf")
            assert isinstance(cnf, dict), claims
            assert cnf.get("x5t#S256") == expected_thumbprint, cnf
            print(f"étape 3/8  cnf.x5t#S256 = {expected_thumbprint[:16]}…            OK")

            accepted = _resource(http, access_token, pem)
            assert accepted.status_code == 200, (accepted.status_code, accepted.text[:300])
            print("étape 4/8  /protected-resource + bon certificat -> 200            OK")

            mismatched = _resource(http, access_token, other_pem)
            assert mismatched.status_code == 401, (mismatched.status_code, mismatched.text[:300])
            print("étape 5/8  /protected-resource + autre certificat -> 401          OK")

            without = _resource(http, access_token, None)
            assert without.status_code == 401, (without.status_code, without.text[:300])
            print("étape 6/8  /protected-resource sans certificat -> 401             OK")

            code = _authorize(http)
            exchanged = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                pem,
            )
            assert exchanged.status_code == 200, (exchanged.status_code, exchanged.text[:300])
            tokens = dict(exchanged.json())
            assert tokens.get("refresh_token"), sorted(tokens)
            print("étape 7/8  /authorize + /token(code) avec certificat -> 200       OK")

            rotated = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])},
                pem,
            )
            assert rotated.status_code == 200, (rotated.status_code, rotated.text[:300])
            rotated_token = str(rotated.json()["refresh_token"])
            assert rotated_token and rotated_token != tokens["refresh_token"], sorted(
                rotated.json()
            )

            cross = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {"grant_type": "refresh_token", "refresh_token": rotated_token},
                other_pem,
            )
            cross_payload = dict(cross.json())
            assert cross.status_code == 400, (cross.status_code, cross_payload)
            assert cross_payload.get("error") == "invalid_grant", cross_payload

            no_cert = _token(
                http,
                private,
                "sample-hok-kid",
                issuer,
                {"grant_type": "refresh_token", "refresh_token": rotated_token},
                None,
            )
            no_cert_payload = dict(no_cert.json())
            assert no_cert.status_code == 400, (no_cert.status_code, no_cert_payload)
            assert no_cert_payload.get("error") == "invalid_client", no_cert_payload
            print("étape 8/8  refresh : même cert 200, autre 400, aucun 400          OK")


def main() -> int:
    """Démarre l'OP, joue les 8 étapes puis termine le serveur (code 0 = OK)."""
    started_at = time.monotonic()
    _run_scenario()
    elapsed = time.monotonic() - started_at
    print(f"=== PARCOURS mTLS HOLDER-OF-KEY OK en {elapsed:.1f}s ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
