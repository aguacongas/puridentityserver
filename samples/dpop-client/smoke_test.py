r"""Test manuel de l'extension DPoP (RFC 9449).

Smoke test du sample ``dpop-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8110, un
client seed public **avec ``require_dpop = true``**) puis joue le scénario :

1. le discovery annonce ``dpop_signing_alg_values_supported`` (RS256, sans
   ``none`` ni famille symétrique HS*) ;
2. ``/token`` échange du code **sans** preuve DPoP -> ``400 invalid_request``
   : le client exige une preuve (RFC 9449 §5.2) ;
3. ``/token`` avec une preuve valide -> ``200`` ``token_type: DPoP`` et
   access token lié (claim ``cnf.jkt``, RFC 9449 §5.1) ;
4. rejeu de la même preuve (``jti`` déjà présenté) -> ``400
   invalid_dpop_proof`` (anti-replay, RFC 9449 §11) ;
5. ``/userinfo`` du jeton lié avec le scheme ``Bearer`` -> ``401`` +
   ``WWW-Authenticate: DPoP error="invalid_token"`` (RFC 9449 §7.2) ;
6. ``/userinfo`` avec le scheme ``DPoP`` + preuve portant ``ath`` -> ``200``
   (claims) ;
7. ``/token`` grant ``refresh_token`` : sans preuve -> ``400
   invalid_request`` (refresh lié), avec preuve -> ``200`` ``token_type:
   DPoP`` (le lien se conserve au renouvellement, RFC 9449 §5.1) ;
8. ``/authorize`` avec ``dpop_jkt`` (autre clé) puis ``/token`` avec la
   preuve d'une autre clé -> ``400 invalid_grant`` (mismatch d'empreinte,
   RFC 9449 §10).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/dpop-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8110
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-dpop-client"
REDIRECT_URI = f"{SERVER_URL}/callback"
PKCE_VERIFIER = "dpop-verifier-0123456789"
DPOP_PROOF_TYPE = "dpop+jwt"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid profile email offline_access",
    "client_type": "public",
    "require_dpop": True,
}


def _b64url(value: int, size: int) -> str:
    """Encode un entier en base64url big-endian sur ``size`` octets."""
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode("ascii")


def _jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """JWK public EC (P-256) d'une clé privée (RFC 7518 §6.2.1)."""
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x, 32),
        "y": _b64url(numbers.y, 32),
    }


def _thumbprint(key: ec.EllipticCurvePrivateKey) -> str:
    """Empreinte RFC 7638 de la clé publique (claim ``cnf.jkt``)."""
    jwk = _jwk(key)
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _access_token_hash(token: str) -> str:
    """``ath`` : base64url du SHA-256 de l'access token (RFC 9449 §4.3)."""
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    htu: str,
    method: str = "POST",
    ath: str = "",
    jti: str = "",
) -> str:
    """Signe une preuve DPoP (``dpop+jwt``, ES256) pour ``htu``/``method``."""
    payload: dict[str, object] = {
        "jti": jti or secrets.token_urlsafe(16),
        "htm": method,
        "htu": htu,
        "iat": int(time.time()),
    }
    if ath:
        payload["ath"] = ath
    return str(
        pyjwt.encode(
            payload,
            key,
            algorithm="ES256",
            headers={"typ": DPOP_PROOF_TYPE, "jwk": _jwk(key)},
        )
    )


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize(http: httpx.Client, *, dpop_jkt: str = "") -> str:
    """Obtient un code d'autorisation (PKCE) ; ``dpop_jkt`` lie la clé déclarée."""
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email offline_access",
        "state": "st-dpop",
        "code_challenge": _s256_challenge(PKCE_VERIFIER),
        "code_challenge_method": "S256",
    }
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    response = http.get(f"{SERVER_URL}/authorize", params=params)
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def _token(http: httpx.Client, code: str, *, proof: str = "") -> httpx.Response:
    """Échange ``code`` contre les jetons, avec ``proof`` (en-tête ``DPoP``) optionnel."""
    headers = {"DPoP": proof} if proof else {}
    return http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": PKCE_VERIFIER,
        },
        headers=headers,
    )


def _run_scenario() -> None:
    """Joue le scénario DPoP (RFC 9449) de bout en bout."""
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    token_url = f"{SERVER_URL}/token"
    userinfo_url = f"{SERVER_URL}/userinfo"

    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        algorithms = metadata["dpop_signing_alg_values_supported"]
        assert "RS256" in algorithms, algorithms
        assert "none" not in algorithms, algorithms
        assert not any(name.startswith("HS") for name in algorithms), algorithms
        print(f"  [1/8] discovery OK (dpop_signing_alg_values_supported={algorithms})")

        code = _authorize(http)
        response = _token(http, code)
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request", response.text
        print("  [2/8] /token sans preuve -> 400 invalid_request (require_dpop) OK")

        proof = _proof(key, htu=token_url)
        response = _token(http, code, proof=proof)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["token_type"] == "DPoP", payload
        claims = pyjwt.decode(
            payload["access_token"], options={"verify_signature": False, "verify_exp": False}
        )
        assert claims["cnf"]["jkt"] == _thumbprint(key), claims["cnf"]
        access_token = payload["access_token"]
        refresh_token = payload["refresh_token"]
        print("  [3/8] /token avec preuve -> 200 token_type=DPoP + cnf.jkt OK")

        code = _authorize(http)
        response = _token(http, code, proof=proof)
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_dpop_proof", response.text
        print("  [4/8] rejeu de la preuve (jti déjà présenté) -> 400 invalid_dpop_proof OK")

        response = http.get(f"{userinfo_url}", headers={"Authorization": f"Bearer {access_token}"})
        assert response.status_code == 401, response.text
        assert response.headers["www-authenticate"].startswith('DPoP error="invalid_token"')
        print("  [5/8] /userinfo Bearer sur jeton lié -> 401 + WWW-Authenticate: DPoP OK")

        userinfo_proof = _proof(
            key, htu=userinfo_url, method="GET", ath=_access_token_hash(access_token)
        )
        response = http.get(
            userinfo_url,
            headers={"Authorization": f"DPoP {access_token}", "DPoP": userinfo_proof},
        )
        assert response.status_code == 200, response.text
        assert "sub" in response.json(), response.json()
        print("  [6/8] /userinfo scheme DPoP + ath -> 200 (claims) OK")

        response = http.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": CLIENT_ID,
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request", response.text
        print("  [7a/8] refresh lié sans preuve -> 400 invalid_request OK")

        response = http.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": CLIENT_ID,
            },
            headers={"DPoP": _proof(key, htu=token_url)},
        )
        assert response.status_code == 200, response.text
        refreshed = response.json()
        assert refreshed["token_type"] == "DPoP", refreshed
        refreshed_claims = pyjwt.decode(
            refreshed["access_token"], options={"verify_signature": False, "verify_exp": False}
        )
        assert refreshed_claims["cnf"]["jkt"] == _thumbprint(key), refreshed_claims["cnf"]
        print("  [7b/8] refresh avec preuve -> 200 token_type=DPoP (lien conservé) OK")

        code = _authorize(http, dpop_jkt=_thumbprint(other_key))
        response = _token(http, code, proof=_proof(key, htu=token_url))
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_grant", response.text
        print("  [8/8] preuve d'une autre clé que dpop_jkt -> 400 invalid_grant OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(port=SERVER_PORT, clients=(_CLIENT,)),
    ):
        print(f"\nScénario DPoP (RFC 9449) - client require_dpop (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
