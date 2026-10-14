r"""Parcours de démonstration FAPI2 Security Profile (issue #111).

Lance un serveur PurIdentityServer en sous-processus (port 8108,
issuer ``https://id.example``, clients seedés ``fapi2-app`` / ``fapi2-app-2``
à clés statiques, ``token_endpoint_auth_method=private_key_jwt`` et
``fapi2_enabled=true``, repris de ``samples/oidc_harness/fapi2_harness.py``)
puis joue le flux complet FAPI2 en 8 étapes :

1. discovery : ``require_pushed_authorization_requests``,
   ``authorization_response_iss_parameter_supported``, endpoint ``/par``,
   ``code_challenge_methods_supported`` ⊇ ``S256`` (seul accepté pour un
   client FAPI2) ;
2. ``POST /par`` en **params plats** (profil ``unsigned``) : défi PKCE
   ``S256``, ``dpop_jkt`` (empreinte de la clé DPoP éphémère) et
   ``client_assertion`` ``private_key_jwt`` → ``201`` ``request_uri`` ;
3. push sans PKCE → ``400 invalid_request`` (FAPI2-SP-5.3.2.2-5) ;
4. ``/authorize?request_uri=…`` → login + consentement → callback en
   **query** : ``code``, ``state`` et ``iss`` (RFC 9207) ;
5. ``/token`` avec un ``code_verifier`` erroné → ``400 invalid_grant``
   (le code reste intact) ;
6. ``/token`` **sans preuve DPoP** → ``400 invalid_dpop_proof`` ; avec la
   bonne preuve fraîche → ``200`` : ``token_type=DPoP``, ``cnf.jkt`` dans
   l'access token, id_token ``PS256`` et refresh_token ;
7. ``/protected-resource`` sans preuve → ``401`` ; avec preuve (``ath``)
   → ``200`` ;
8. réutilisation de la ``request_uri`` après consommation → erreur
   ``invalid_request_uri``, jamais de code (RFC 9126 §2.2.2).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/fapi2-client/smoke_test.py
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

sys.path.insert(0, str(REPO_ROOT / "samples" / "oidc_harness"))

from fapi2_harness import (  # ruff: ignore[module-import-not-at-top-of-file]
    FAPI2_CLIENT_2_SEED,
    FAPI2_CLIENT_SEED,
    Fapi2Harness,
)
from fastapi import FastAPI  # ruff: ignore[module-import-not-at-top-of-file]
from harness import (  # ruff: ignore[module-import-not-at-top-of-file]
    IDENTITY_USERS,
    decode_id_token_claims,
    decode_id_token_header,
    pkce_challenge,
)

SERVER_PORT = 8108
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

#: Même canonique que le harness : l'issuer des
#: assertions client et des id_tokens ; le discovery publie les endpoints
#: dérivés de la base URL réelle du serveur.
ISSUER = "https://id.example"

_DEADLINE = 120


def _check_discovery(harness: Fapi2Harness) -> None:
    """Étape 1 : métadonnées FAPI2 (PAR obligatoire, iss, S256 seul)."""
    metadata = harness.discovery()
    assert metadata.get("require_pushed_authorization_requests") is True, sorted(metadata)
    assert metadata.get("authorization_response_iss_parameter_supported") is True, sorted(metadata)
    challenge = metadata.get("code_challenge_methods_supported", [])
    assert "S256" in challenge, challenge
    assert "PS256" in metadata.get("token_endpoint_auth_signing_alg_values_supported", [])
    print("étape 1/8  discovery FAPI2 (PAR requis, iss RFC 9207, S256)  OK")


def _check_push(harness: Fapi2Harness, form: dict[str, str]) -> str:
    """Étape 2 : ``POST /par`` params plats + ``dpop_jkt`` + assertion."""
    request_uri = harness.push_ok(form)
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:"), request_uri
    print("étape 2/8  POST /par (params plats + dpop_jkt) -> 201        OK")
    return request_uri


def _check_pkce_required(harness: Fapi2Harness) -> None:
    """Étape 3 : un push sans PKCE est refusé (FAPI2-SP-5.3.2.2-5)."""
    form = harness.authorize_params()
    form.pop("code_challenge")
    form.pop("code_challenge_method")
    response = harness.push_form(form)
    payload = dict(response.json())
    assert response.status_code == 400, (response.status_code, payload)
    assert payload.get("error") == "invalid_request", payload
    print("étape 3/8  push sans PKCE -> 400 invalid_request             OK")


def _check_callback(harness: Fapi2Harness, request_uri: str, *, state: str) -> str:
    """Étape 4 : login + consentement → callback query ``code``+``state``+``iss``."""
    result = harness.run_flow(request_uri=request_uri, client_id=harness.client.client_id)
    assert result.code, f"callback sans code : {result.callback_url or result.body}"
    assert not result.error, f"callback en erreur : {result.error}"
    assert result.query.get("state") == state, sorted(result.query)
    assert result.query.get("iss") == ISSUER, sorted(result.query)
    print("étape 4/8  /authorize -> login -> consent -> code + iss      OK")
    return result.code


def _check_rejected_exchange(harness: Fapi2Harness, code: str, *, verifier: str) -> None:
    """Étape 5 : un ``code_verifier`` neuf est refusé (RFC 7636 §4.6)."""
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": harness.client.redirect_uri,
            "code_verifier": secrets.token_urlsafe(48),
        },
        dpop=harness.dpop.proof(harness.token_endpoint),
    )
    payload = dict(response.json())
    assert response.status_code == 400, (response.status_code, payload)
    assert payload.get("error") == "invalid_grant", payload
    assert verifier, "verifier nominal réservé à l'étape 6"
    print("étape 5/8  code_verifier erroné -> 400 invalid_grant         OK")


def _check_bound_token(harness: Fapi2Harness, code: str, *, verifier: str) -> dict[str, object]:
    """Étape 6 : sans preuve → 401 ; avec preuve → token bound DPoP."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": harness.client.redirect_uri,
        "code_verifier": verifier,
    }
    refused = harness.token_request(form)
    payload = dict(refused.json())
    assert refused.status_code in (400, 401), (refused.status_code, payload)
    assert payload.get("error") == "invalid_dpop_proof", payload
    proof = harness.dpop.proof(harness.token_endpoint)
    response = harness.token_request(form, dpop=proof)
    assert response.status_code == 200, (response.status_code, response.text[:300])
    tokens = dict(response.json())
    assert tokens.get("token_type") == "DPoP", sorted(tokens)
    header = decode_id_token_header(str(tokens["id_token"]))
    assert header.get("alg") == "PS256" and header.get("kid"), header
    claims = decode_id_token_claims(str(tokens["id_token"]))
    assert claims.get("nonce"), sorted(claims)
    access_claims = decode_id_token_claims(str(tokens["access_token"]))
    assert access_claims.get("cnf", {}).get("jkt") == harness.dpop.thumbprint, access_claims
    print("étape 6/8  /token sans preuve -> 400 ; avec preuve -> DPoP   OK")
    return tokens


def _check_resource(harness: Fapi2Harness, access_token: str) -> None:
    """Étape 7 : ressource sans preuve refusée, avec preuve acceptée."""
    refused = harness.resource(access_token, dpop=False)
    assert refused.status_code == 401, (refused.status_code, refused.text[:200])
    accepted = harness.resource(access_token)
    assert accepted.status_code == 200, (accepted.status_code, accepted.text[:300])
    print("étape 7/8  /protected-resource sans preuve 401, avec 200    OK")


def _check_request_uri_reuse(harness: Fapi2Harness, request_uri: str) -> None:
    """Étape 8 : la ``request_uri`` consommée ne se réutilise pas (RFC 9126)."""
    result = harness.run_flow(request_uri=request_uri, client_id=harness.client.client_id)
    assert not result.code, f"request_uri réutilisée après consommation : {result.callback_url}"
    observed = result.error or result.body
    assert "invalid_request_uri" in observed, result.body[:200]
    print("étape 8/8  request_uri réutilisée -> invalid_request_uri     OK")


def _play_scenario() -> None:
    """Enchaîne les 8 étapes du parcours FAPI2 contre l'OP distant."""
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    # ``cast`` : en mode OP distant (env var), ``ConformanceHarness`` ne
    # touche jamais à l'application — elle n'est construite que pour le
    # mode in-process.
    with Fapi2Harness(cast(FastAPI, None)) as harness:
        _check_discovery(harness)
        form = harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
        form["dpop_jkt"] = harness.dpop.thumbprint
        request_uri = _check_push(harness, form)
        _check_pkce_required(harness)
        code = _check_callback(harness, request_uri, state=state)
        _check_rejected_exchange(harness, code, verifier=verifier)
        tokens = _check_bound_token(harness, code, verifier=verifier)
        _check_resource(harness, str(tokens["access_token"]))
        _check_request_uri_reuse(harness, request_uri)


def main() -> int:
    """Démarre l'OP, joue les 8 étapes puis termine le serveur (code 0 = OK)."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(FAPI2_CLIENT_SEED, FAPI2_CLIENT_2_SEED),
            users=IDENTITY_USERS,
            issuer=ISSUER,
            jwks_algorithms=("RS256", "PS256"),
            extra_settings={
                "require_login": True,
                "protected_resource_enabled": True,
                "par_required": True,
            },
        ) as server_url,
    ):
        print(f"OP FAPI2 démarré sur {server_url} (issuer {ISSUER})")
        os.environ["PURIDENTITYSERVER_CONFORMANCE_URL"] = server_url
        _play_scenario()
    elapsed = time.monotonic() - started_at
    print(f"=== PARCOURS FAPI2 OK en {elapsed:.1f}s ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
