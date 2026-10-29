#!/usr/bin/env python3
"""Smoke test minimal pour l issuer OpenID4VCI (DoD placeholder).

Exerce l endpoint de metadonnees, y compris la variante signee
(``Accept: application/jwt``), contre un OP deja demarre.
"""

from __future__ import annotations

import json
import os
import urllib.request

import jwt

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def _get(path: str, accept: str | None = None) -> tuple[int, str, str]:
    """Lit une ressource HTTP de l OP et renvoie (statut, content-type, corps)."""
    url = BASE_URL + path
    request = urllib.request.Request(url)  # ruff: ignore[suspicious-url-open-usage]
    if accept is not None:
        request.add_header("Accept", accept)
    with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
        return response.status, response.headers.get("Content-Type", ""), response.read().decode()


def main() -> int:
    """Point d entree du smoke test."""
    print("=== OID4VCI issuer smoke ===")
    print(f"BASE_URL={BASE_URL}")

    status, content_type, body = _get("/.well-known/openid-credential-issuer")
    print(f"metadata json: {status} {content_type}")
    if status != 200:
        print(body)
        return 1

    status, content_type, token = _get(
        "/.well-known/openid-credential-issuer", accept="application/jwt"
    )
    print(f"metadata signed: {status} {content_type}")
    if status != 200 or "application/jwt" not in content_type:
        print(token)
        return 1

    header = jwt.get_unverified_header(token)
    print(f"typ={header.get('typ')} kid={header.get('kid')} alg={header.get('alg')}")

    public_key = None
    jwk = header.get("jwk")
    if isinstance(jwk, dict):
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm

        if jwk.get("kty") == "RSA":
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        else:
            public_key = ECAlgorithm.from_jwk(json.dumps(jwk))

    if public_key is None:
        print("aucune cle publique exploitable dans l en-tete")
        return 1

    algorithms = [str(header["alg"])]
    claims = jwt.decode(
        token,
        public_key,
        algorithms=algorithms,
        options={"verify_aud": False},
    )
    print(
        "sub=",
        claims.get("sub"),
        "iat=",
        claims.get("iat"),
        "credential_issuer=",
        claims.get("credential_issuer"),
    )
    if claims.get("sub") != BASE_URL:
        print("ERREUR: sub different de l URL d issuer")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
