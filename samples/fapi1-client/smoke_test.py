r"""Parcours de démonstration FAPI1 Advanced Final (issue #110).

Lance un serveur PurIdentityServer en sous-processus (port 8107,
issuer ``https://id.example``, clients seedés ``fapi-app`` / ``fapi-app-2``
à clés PS256 statiques et ``token_endpoint_auth_method=private_key_jwt``,
repris de ``tests/conformance/fapi_harness.py``) puis joue le flux complet
FAPI1 en 8 étapes :

1. discovery : ``request_object_signing_alg_values_supported`` ⊇
   {PS256, ES256}, ``request_parameter_supported``, endpoint ``/par``,
   ``code_challenge_methods_supported`` ⊇ ``S256`` ;
2. ``POST /par`` (JAR ``PS256`` + ``client_assertion`` ``private_key_jwt``
   + défi PKCE ``S256``) → ``201`` ``request_uri`` opaque ;
3. rejet de ``response_mode=query`` sur ``code id_token`` → ``400``
   ``invalid_request`` au ``/par`` (OIDC Core 1.0 §3.1.2.1, jamais de
   ``code`` en query) ;
4. ``/authorize?request_uri=…`` → login + consentement → callback en
   **fragment** : ``code``, ``state``, id_token ``PS256`` avec ``nonce``
   et ``s_hash`` ;
5. ``/token`` avec un ``code_verifier`` erroné → ``400 invalid_grant``
   (le code reste intact) ;
6. ``/token`` avec l'assertion ``private_key_jwt`` et le bon
   ``code_verifier`` → ``200`` : access_token, id_token ``PS256`` (+
   ``kid``, ``nonce``) et refresh_token ;
7. ``/protected-resource`` (Bearer + ``x-fapi-interaction-id``) → ``200`` ;
8. réutilisation de la ``request_uri`` après consommation → callback en
   erreur ``invalid_request_uri``, jamais de code (PAR-2.2.2).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/fapi1-client/smoke_test.py
"""

from __future__ import annotations

import os
import secrets
import sys
import time
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog  # ruff: ignore[module-import-not-at-top-of-file]

sys.path.insert(0, str(REPO_ROOT / "tests" / "conformance"))

from conftest import _IDENTITY_USERS  # ruff: ignore[module-import-not-at-top-of-file]
from fapi_harness import (  # ruff: ignore[module-import-not-at-top-of-file]
    FAPI_CLIENT_2_SEED,
    FAPI_CLIENT_SEED,
    FapiHarness,
)
from fastapi import FastAPI  # ruff: ignore[module-import-not-at-top-of-file]
from harness import (  # ruff: ignore[module-import-not-at-top-of-file]
    decode_id_token_claims,
    decode_id_token_header,
    new_verifier,
)

SERVER_PORT = 8107
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

#: Même canonique que ``tests/conformance/conftest.py`` : l'issuer du JAR,
#: du discovery et des id_tokens ; les redirect_uris seedés pointent vers
#: des hôtes externes (jamais suivis par le harness).
ISSUER = "https://id.example"

_DEADLINE = 120


def _check_discovery(harness: FapiHarness) -> None:
    """Étape 1 : les métadonnées déclarent JAR, PAR et PKCE ``S256``."""
    metadata = harness.discovery()
    jar_algs = metadata.get("request_object_signing_alg_values_supported", [])
    assert "PS256" in jar_algs and "ES256" in jar_algs, jar_algs
    challenge = metadata.get("code_challenge_methods_supported", [])
    assert "S256" in challenge, challenge
    assert metadata.get("request_parameter_supported") is True, sorted(metadata)
    par_endpoint = metadata.get("pushed_authorization_request_endpoint")
    assert par_endpoint, sorted(metadata)
    print(f"étape 1/8  discovery FAPI1 (JAR PS256, {par_endpoint}, S256)   OK")


def _check_push(harness: FapiHarness, jar: str) -> str:
    """Étape 2 : ``POST /par`` accepte le JAR signé et rend ``request_uri``."""
    request_uri = harness.push_ok(jar)
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:"), request_uri
    print(f"étape 2/8  POST /par -> 201 {request_uri[:52]}...  OK")
    return request_uri


def _check_query_mode_rejected(harness: FapiHarness, *, state: str, nonce: str) -> None:
    """Étape 3 : ``response_mode=query`` refusé sur ``code id_token``."""
    jar = harness.jar(new_verifier(), state=state, nonce=nonce, response_mode="query")
    response = harness.push(jar)
    payload = dict(response.json())
    assert response.status_code == 400, (response.status_code, payload)
    assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload
    print("étape 3/8  response_mode=query -> 400 invalid_request        OK")


def _check_callback(harness: FapiHarness, request_uri: str, *, state: str, nonce: str) -> str:
    """Étape 4 : ``/authorize`` → login + consentement → callback en fragment."""
    result = harness.run_flow(request_uri=request_uri, client_id=harness.client.client_id)
    assert result.code, f"callback sans code : {result.callback_url or result.body}"
    assert not result.error, f"callback en erreur : {result.error}"
    assert not result.query.get("code"), f"code en query (OIDCC-3.3.2.5) : {result.callback_url}"
    assert result.fragment.get("state") == state, sorted(result.fragment)
    front_id_token = result.fragment.get("id_token", "")
    assert front_id_token, sorted(result.fragment)
    front_claims = decode_id_token_claims(front_id_token)
    assert front_claims.get("nonce") == nonce, front_claims.get("nonce")
    assert front_claims.get("s_hash"), sorted(front_claims)
    print("étape 4/8  /authorize -> login -> consent -> callback frag    OK")
    return result.code


def _check_rejected_exchange(harness: FapiHarness, code: str) -> None:
    """Étape 5 : un ``code_verifier`` neuf est refusé (RFC 7636 §4.6)."""
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": harness.client.redirect_uri,
            "code_verifier": new_verifier(),
        }
    )
    payload = dict(response.json())
    assert response.status_code == 400, (response.status_code, payload)
    assert payload.get("error") == "invalid_grant", payload
    print("étape 5/8  code_verifier erroné -> 400 invalid_grant         OK")


def _check_token_exchange(
    harness: FapiHarness, code: str, *, verifier: str, nonce: str
) -> dict[str, object]:
    """Étape 6 : l'échange nominal renvoie les trois jetons (FAPI1-ADV)."""
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": harness.client.redirect_uri,
            "code_verifier": verifier,
        }
    )
    assert response.status_code == 200, (response.status_code, response.text[:300])
    tokens = dict(response.json())
    assert tokens.get("refresh_token"), sorted(tokens)
    header = decode_id_token_header(str(tokens["id_token"]))
    assert header.get("alg") == "PS256" and header.get("kid"), header
    claims = decode_id_token_claims(str(tokens["id_token"]))
    assert claims.get("nonce") == nonce, claims.get("nonce")
    print("étape 6/8  /token -> 200 (id_token PS256 + refresh)          OK")
    return tokens


def _check_resource(harness: FapiHarness, access_token: str) -> None:
    """Étape 7 : la ressource protégée répond au Bearer FAPI."""
    interaction_id = secrets.token_urlsafe(12)
    response = harness.resource(access_token, interaction_id=interaction_id)
    assert response.status_code in (200, 201), (response.status_code, response.text[:300])
    print("étape 7/8  /protected-resource -> 200                        OK")


def _check_request_uri_reuse(harness: FapiHarness, request_uri: str) -> None:
    """Étape 8 : la ``request_uri`` consommée ne se réutilise pas (PAR-2.2.2).

    Issue admise par la suite : callback ``error=invalid_request_uri`` ou
    page d'erreur non redirigeante portant la même erreur — jamais de code.
    """
    result = harness.run_flow(request_uri=request_uri, client_id=harness.client.client_id)
    assert not result.code, f"request_uri réutilisée après consommation : {result.callback_url}"
    observed = result.error or result.body
    assert "invalid_request_uri" in observed, result.body[:200]
    print("étape 8/8  request_uri réutilisée -> invalid_request_uri     OK")


def _play_scenario() -> None:
    """Enchaîne les 8 étapes du parcours FAPI1 contre l'OP distant."""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier = new_verifier()
    # ``cast`` : en mode OP distant (env var), ``ConformanceHarness`` ne
    # touche jamais à l'application — elle n'est construite que pour le
    # mode in-process.
    with FapiHarness(cast(FastAPI, None)) as harness:
        _check_discovery(harness)
        jar = harness.jar(verifier, state=state, nonce=nonce)
        request_uri = _check_push(harness, jar)
        _check_query_mode_rejected(harness, state=state, nonce=nonce)
        code = _check_callback(harness, request_uri, state=state, nonce=nonce)
        _check_rejected_exchange(harness, code)
        tokens = _check_token_exchange(harness, code, verifier=verifier, nonce=nonce)
        _check_resource(harness, str(tokens["access_token"]))
        _check_request_uri_reuse(harness, request_uri)


def main() -> int:
    """Démarre l'OP, joue les 8 étapes puis termine le serveur (code 0 = OK)."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(FAPI_CLIENT_SEED, FAPI_CLIENT_2_SEED),
            users=_IDENTITY_USERS,
            issuer=ISSUER,
            jwks_algorithms=("RS256", "PS256"),
            extra_settings={"require_login": True, "protected_resource_enabled": True},
        ) as server_url,
    ):
        print(f"OP FAPI1 démarré sur {server_url} (issuer {ISSUER})")
        os.environ["PURIDENTITYSERVER_CONFORMANCE_URL"] = server_url
        _play_scenario()
    elapsed = time.monotonic() - started_at
    print(f"=== PARCOURS FAPI1 OK en {elapsed:.1f}s ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
