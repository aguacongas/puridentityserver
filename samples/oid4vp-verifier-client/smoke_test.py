r"""Smoke test du verifier OpenID4VP 1.0 (issue #224).

Smoke test du sample ``oid4vp-verifier-client``.

Lance un serveur PurIdentityServer dédié (port 8127, configuration générée
par ``smoke_common.py`` : ``oid4vp_enabled = true`` et
``oid4vp_credential_jwks`` alimenté avec la clé publique générée au démarrage
de ce test — le contrôle de signature du credential n'est donc pas escamoté
en mode witness) puis joue le round-trip wallet complet en ``direct_post.jwt`` :

1. ``POST /oid4vp/presentation_requests`` -> 201 : ``client_id``
   ``x509_hash:``, ``nonce``, ``request_uri`` et request object signé
   ``oauth-authz-req+jwt`` ;
2. ``GET /oid4vp/request_uri/{request_id}`` -> 200
   ``application/oauth-authz-req+jwt`` portant ``aud =
   https://self-issued.me/v2``, la requête DCQL PID et le ``client_metadata``
   (clé de chiffrement éphémère ECDH-ES) ;
3. ``POST /oid4vp/request_uri/{request_id}`` avec ``wallet_nonce`` -> request
   object re-signé portant ce claim (OID4VP 1.0 Final §5.10,
   ``request_uri_method = post``) ;
4. ``POST /oid4vp/vp_response/{request_id}`` avec le JWE ``ECDH-ES``/
   ``A128GCM`` du wallet (credential SD-JWT signé + kb-jwt lié au nonce) ->
   200 ``{"redirect_uri": ...}`` ;
5. ``GET <redirect_uri>`` -> page ``Presentation acceptee`` listant les
   claims du credential présenté (issue #302) ;
6. contre-épreuve : credential signé par une clé étrangère -> 400
   « signature du credential non appariee au JWKS de confiance ».

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/oid4vp-verifier-client/smoke_test.py
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from puridentityserver.domain.jwe import JWEEncryptionMethod
from puridentityserver.infrastructure.jwe import (
    b64u,
    ec_jwk,
    ec_public_key,
    encrypt_compact_ecdh_es,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8127
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

#: ``vct`` du credential PID (profil HAIP, requête DCQL de défaut de l'OP).
_VCT = "urn:eudi:pid:1"

#: ``kid`` de la clé d'émission de ce test, aligné sur son JWKS de confiance.
_CREDENTIAL_KID = "sample-oid4vp-credential"

#: Audience du request object, fixée par OID4VP §5.8 sur l'issuer SIOP v2.
_SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2"


def _credential_jwks(issuer_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """Construit le JWKS public de confiance de la clé d'émission SD-JWT.

    Args:
        issuer_key: clé privée qui signe les credentials de ce test.

    Returns:
        L'objet JWKS public transmis à l'OP via ``oid4vp_credential_jwks``
        (le verifier contrôle alors la signature du credential au lieu du
        mode witness).
    """
    jwk = ec_jwk(issuer_key.public_key())
    jwk.update({"kid": _CREDENTIAL_KID, "alg": "ES256", "use": "sig"})
    return {"keys": [jwk]}


def _presented_credential(
    holder_key: ec.EllipticCurvePrivateKey,
    *,
    issuer_key: ec.EllipticCurvePrivateKey,
    nonce: str,
    client_id: str,
) -> str:
    """Émet la chaîne SD-JWT présentée : credential + disclosure + kb-jwt.

    Args:
        holder_key: clé du détenteur, référence ``cnf.jwk`` du credential.
        issuer_key: clé qui signe le credential (clé étrangère pour la
            contre-épreuve de signature).
        nonce: nonce du request object à reprendre dans le kb-jwt.
        client_id: audience du kb-jwt (``client_id`` ``x509_hash:``).

    Returns:
        La chaîne ``credential~disclosure~kb-jwt`` postée dans le ``vp_token``.
    """
    now = int(time.time())
    credential = pyjwt.encode(
        {
            "iss": "https://issuer.example",
            "sub": "alice",
            "iat": now,
            "exp": now + 600,
            "vct": _VCT,
            "cnf": {"jwk": ec_jwk(holder_key.public_key())},
        },
        issuer_key,
        algorithm="ES256",
        headers={"typ": "dc+sd-jwt", "kid": _CREDENTIAL_KID},
    )
    disclosure = b64u(
        json.dumps(
            [b64u(secrets.token_bytes(16)), "given_name", "Alice"], separators=(",", ":")
        ).encode("utf-8")
    )
    # sd_hash : SHA-256 du préfixe présenté jusqu'au dernier "~" inclus
    # (RFC 9901 §3.2), ici la credential et sa disclosure.
    prefix = f"{credential}~{disclosure}~"
    sd_hash = b64u(hashlib.sha256(prefix.encode("ascii")).digest())
    key_binding = pyjwt.encode(
        {"iat": now, "aud": client_id, "nonce": nonce, "sd_hash": sd_hash},
        holder_key,
        algorithm="ES256",
        headers={"typ": "kb+jwt"},
    )
    return prefix + key_binding


def _encrypt_response(request_object: str, presented: str) -> str:
    """Chiffle le ``vp_token`` en JWE ECDH-ES vers la clé du request object.

    Args:
        request_object: JWT servi au ``request_uri`` (décodé sans vérification
            pour lire ``dcql_query`` et ``client_metadata``).
        presented: chaîne SD-JWT présentée (voir :func:`_presented_credential`).

    Returns:
        Le JWE compact ``ECDH-ES``/``A128GCM`` à poster au ``response_uri``.
    """
    claims = pyjwt.decode(request_object, options={"verify_signature": False})
    credentials = (claims.get("dcql_query") or {}).get("credentials") or [{}]
    credential_id = str(credentials[0].get("id", "pid"))
    recipient = claims["client_metadata"]["jwks"]["keys"][0]
    payload = {"vp_token": {credential_id: [presented]}}
    return encrypt_compact_ecdh_es(
        method=JWEEncryptionMethod.A128GCM,
        plaintext=json.dumps(payload).encode("utf-8"),
        recipient_public_key=ec_public_key(recipient),
        kid=str(recipient["kid"]),
    )


def _create_request(http: httpx.Client) -> dict[str, Any]:
    """Crée une demande de présentation et contrôle les champs rendus."""
    response = http.post(
        f"{SERVER_URL}/oid4vp/presentation_requests",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    for name in ("request_id", "client_id", "request_uri", "nonce", "request_object"):
        assert isinstance(payload.get(name), str) and payload[name], (name, payload)
    assert payload["client_id"].startswith("x509_hash:"), payload["client_id"]
    return payload


def _fetch_request_object(
    http: httpx.Client, request_id: str, *, wallet_nonce: str | None = None
) -> str:
    """Sert le request object via GET idempotent, ou re-signé via POST."""
    url = f"{SERVER_URL}/oid4vp/request_uri/{request_id}"
    response = (
        http.get(url)
        if wallet_nonce is None
        else http.post(url, data={"wallet_nonce": wallet_nonce})
    )
    assert response.status_code == 200, response.text
    content_type = response.headers.get("content-type", "")
    assert "application/oauth-authz-req+jwt" in content_type, content_type
    return response.text


def _post_response(http: httpx.Client, request_id: str, jwe: str) -> httpx.Response:
    """Poste la réponse chiffrée du wallet au ``response_uri``."""
    return http.post(f"{SERVER_URL}/oid4vp/vp_response/{request_id}", data={"response": jwe})


def _happy_flow(
    http: httpx.Client,
    holder_key: ec.EllipticCurvePrivateKey,
    issuer_key: ec.EllipticCurvePrivateKey,
) -> None:
    """Joue les étapes 1 à 5 : demande, request_uri, réponse acceptée, page."""
    created = _create_request(http)
    print("  [1/6] POST /oid4vp/presentation_requests -> 201 (client_id x509_hash, nonce) OK")

    request_object = _fetch_request_object(http, created["request_id"])
    header = pyjwt.get_unverified_header(request_object)
    claims = pyjwt.decode(request_object, options={"verify_signature": False})
    assert header.get("typ") == "oauth-authz-req+jwt", header
    assert header.get("x5c"), "request object non porteuse de la chaîne du verifier"
    assert claims["aud"] == _SELF_ISSUED_AUDIENCE, claims["aud"]
    assert claims["nonce"] == created["nonce"], claims["nonce"]
    assert claims["response_mode"] == "direct_post.jwt", claims["response_mode"]
    metadata = claims["client_metadata"]
    assert metadata["jwks"]["keys"][0]["alg"] == "ECDH-ES", metadata
    query = claims["dcql_query"]["credentials"][0]
    assert query["format"] == "dc+sd-jwt" and query["meta"]["vct_values"] == [_VCT], query
    print("  [2/6] GET request_uri -> oauth-authz-req+jwt (aud SIOP, DCQL, client_metadata) OK")

    wallet_nonce = b64u(secrets.token_bytes(16))
    reissued = _fetch_request_object(http, created["request_id"], wallet_nonce=wallet_nonce)
    reissued_claims = pyjwt.decode(reissued, options={"verify_signature": False})
    assert reissued_claims.get("wallet_nonce") == wallet_nonce, reissued_claims
    assert reissued_claims["nonce"] == created["nonce"], reissued_claims
    print("  [3/6] POST request_uri (wallet_nonce) -> request object re-signé OK")

    presented = _presented_credential(
        holder_key,
        issuer_key=issuer_key,
        nonce=created["nonce"],
        client_id=created["client_id"],
    )
    verdict = _post_response(http, created["request_id"], _encrypt_response(reissued, presented))
    assert verdict.status_code == 200, verdict.text
    redirect_uri = verdict.json()["redirect_uri"]
    assert redirect_uri.endswith(f"/oid4vp/result/{created['request_id']}"), redirect_uri
    print("  [4/6] POST vp_response (JWE ECDH-ES) -> 200 redirect_uri OK")

    page = http.get(redirect_uri)
    assert page.status_code == 200, page.text
    assert "<h1>Presentation acceptee</h1>" in page.text, page.text
    # Les claims du credential présenté sont listés sur la page (issue #302).
    assert f"<dd>{_VCT}</dd>" in page.text, page.text
    print("  [5/6] GET redirect_uri -> page « Presentation acceptee » + claims OK")


def _rejection(http: httpx.Client, holder_key: ec.EllipticCurvePrivateKey) -> None:
    """Joue l'étape 6 : credential signé hors JWKS de confiance -> 400."""
    created = _create_request(http)
    request_object = _fetch_request_object(http, created["request_id"])
    foreign_key = ec.generate_private_key(ec.SECP256R1())
    presented = _presented_credential(
        holder_key,
        issuer_key=foreign_key,
        nonce=created["nonce"],
        client_id=created["client_id"],
    )
    verdict = _post_response(
        http, created["request_id"], _encrypt_response(request_object, presented)
    )
    assert verdict.status_code == 400, verdict.text
    body = verdict.json()
    assert body["error"] == "invalid_request", body
    assert "signature du credential non appariee" in body["error_description"], body
    print("  [6/6] credential hors JWKS -> 400 « signature non appariee » OK")


def _run_scenario(issuer_key: ec.EllipticCurvePrivateKey) -> None:
    """Joue le round-trip verifier OpenID4VP (6 étapes) de bout en bout.

    Args:
        issuer_key: clé qui signe les credentials (celle du JWKS de confiance
            configuré sur l'OP ; l'étape 6 la contourne volontairement).
    """
    holder_key = ec.generate_private_key(ec.SECP256R1())
    with httpx.Client(timeout=_HTTP_TIMEOUT) as http:
        _happy_flow(http, holder_key, issuer_key)
        _rejection(http, holder_key)
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique) puis le scénario, et tout termine."""
    started_at = time.monotonic()
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    extra_settings = {
        "oid4vp_enabled": True,
        "oid4vp_credential_jwks": json.dumps(_credential_jwks(issuer_key)),
    }
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(),
            extra_settings=extra_settings,
        ),
    ):
        print(
            f"\nScénario OpenID4VP verifier (direct_post.jwt, "
            f"port {SERVER_PORT}, deadline={_DEADLINE}s)..."
        )
        _run_scenario(issuer_key)
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
