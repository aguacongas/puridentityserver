r"""Test manuel de la response mode JWT (JARM Final 1.0).

Smoke test du sample ``jarm-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8120,
``require_login = true``, client seed public ``sample-jarm-client`` avec
``authorization_signed_response_alg = "RS256"`` et un second client sans
algorithme) puis joue le scénario :

1. le discovery annonce ``jwt`` dans ``response_modes_supported`` et publie
   ``authorization_signing_alg_values_supported`` ;
2. ``/authorize`` avec ``response_mode=jwt`` + ``prompt=none`` (sans
   session) -> ``302`` : l'URL ne porte **que** ``?response=<jwt>`` et
   l'enveloppe est une erreur ``login_required`` **signée** (kid opposable,
   vérifiable via le JWKS de l'OP) ;
3. ``POST /login`` (alice) -> session authentifiée ;
4. ``/authorize`` avec ``response_mode=jwt`` -> ``302`` : toujours
   uniquement ``?response=<jwt>`` (aucun ``code``/``state`` en clair, pas de
   fragment) ; l'enveloppe contient ``code`` + ``state`` avec ``iss``,
   ``aud`` = client_id et ``exp`` - ``iat`` = 600 s ;
5. vérification de la signature de l'enveloppe contre le JWKS de l'OP
   (``kid`` du header opposé à la clé publiée) ;
6. ``/token`` échange du code extrait de l'enveloppe (PKCE) -> ``200``
   access_token ;
7. un client **sans** ``authorization_signed_response_alg`` qui demande
   ``response_mode=jwt`` reçoit ``unsupported_response_mode`` en
   **transport clair** (le refus ne peut pas être porté par l'enveloppe qu'il
   refuse — JARM Final 1.0 §4).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/jarm-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8120
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-jarm-client"
PLAIN_CLIENT_ID = "sample-jarm-plain-client"

REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": "openid profile email",
        "client_type": "public",
        "authorization_signed_response_alg": "RS256",
    },
    {
        "client_id": PLAIN_CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": "openid profile email",
        "client_type": "public",
    },
)

_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(*, client_id: str, state: str, verifier: str, **extra: str) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation JARM (code flow + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
        "response_mode": "jwt",
    }
    params.update(extra)
    return params


def _envelope_from_location(
    location: str, jwks: list[dict[str, Any]], *, audience: str
) -> dict[str, Any]:
    """Extrait le JWT de ``response`` et vérifie sa signature contre le JWKS."""
    parsed = urlparse(location)
    assert not parsed.fragment, f"l'enveloppe voyage en query, jamais en fragment : {location}"
    query = parse_qs(parsed.query)
    assert set(query) == {"response"}, f"paramètres inattendus : {sorted(query)}"
    envelope = query["response"][0]
    header = pyjwt.get_unverified_header(envelope)
    assert header["kid"], header
    key = next(jwk for jwk in jwks if jwk.get("kid") == header["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(key))
    claims: dict[str, Any] = cast(
        dict[str, Any],
        pyjwt.decode(
            envelope,
            key=public_key,
            algorithms=[header["alg"]],
            audience=audience,
            issuer=SERVER_URL,
        ),
    )
    return claims


def _run_scenario() -> None:
    """Joue le scénario JARM (Final 1.0) de bout en bout."""
    verifier = "jarm-verifier-0123456789"
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "jwt" in metadata["response_modes_supported"], sorted(metadata)
        signing_algs = metadata["authorization_signing_alg_values_supported"]
        assert "RS256" in signing_algs, signing_algs
        print(f"  [1/7] discovery OK (response_modes_supported contient jwt, algos={signing_algs})")

        jwks = http.get(f"{SERVER_URL}/.well-known/jwks.json").json()["keys"]

        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(
                client_id=CLIENT_ID, state="st-error", verifier=verifier, prompt="none"
            ),
        )
        assert response.status_code == 302, response.text
        error_claims = _envelope_from_location(
            response.headers["location"], jwks, audience=CLIENT_ID
        )
        assert error_claims["error"] == "login_required", sorted(error_claims)
        assert error_claims["state"] == "st-error"
        assert "code" not in error_claims
        print("  [2/7] prompt=none sans session -> login_required signé dans l'enveloppe OK")

        login = http.post(
            f"{SERVER_URL}/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
        )
        assert login.status_code == 302, login.text
        print("  [3/7] POST /login (alice) -> session authentifiée OK")

        state = "st-jarm-ok"
        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(client_id=CLIENT_ID, state=state, verifier=verifier),
        )
        assert response.status_code == 302, response.text
        claims = _envelope_from_location(response.headers["location"], jwks, audience=CLIENT_ID)
        code = str(claims["code"])
        assert claims["state"] == state
        assert claims["iss"] == SERVER_URL
        assert claims["exp"] - claims["iat"] == 600
        print(
            "  [4/7] /authorize response_mode=jwt -> 302 (?response= seul, "
            "code+state dans l'enveloppe) OK"
        )

        print("  [5/7] signature de l'enveloppe vérifiée via le JWKS de l'OP (kid) OK")

        token = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200, token.text
        body = token.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"]
        print("  [6/7] échange du code (extrait de l'enveloppe) au /token -> 200 OK")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(
                client_id=PLAIN_CLIENT_ID, state="st-plain", verifier=verifier
            ),
        )
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert location.startswith(REDIRECT_URI + "?"), location
        query = parse_qs(urlparse(location).query)
        assert query["error"] == ["unsupported_response_mode"], sorted(query)
        assert "response" not in query
        print(
            "  [7/7] client sans authorization_signed_response_alg -> "
            "unsupported_response_mode en clair OK"
        )
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
            users=_USERS,
            extra_settings={"require_login": True},
        ),
    ):
        print(f"\nScénario JARM (Final 1.0) - response_mode=jwt (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
