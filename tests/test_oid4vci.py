"""Tests minimaux du support OpenID for Verifiable Credential Issuance (slice 0).

Le support est désactivé par défaut : aucune route n'est montée dans ce cas.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse, urlsplit

import jwt as _jwt
import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from puridentityserver.application.oid4vci import credential_vct
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app


def test_flag_off_exposes_no_oid4vci_routes() -> None:
    app = create_app(settings=Settings(oid4vci_enabled=False))
    client = TestClient(app)
    response = client.get("/.well-known/openid-credential-issuer")
    assert response.status_code == 404
    discovery = client.get("/.well-known/openid-configuration").json()
    assert "openid4vci" not in discovery["scopes_supported"]


def test_flag_on_exposes_metadata() -> None:
    settings = Settings(oid4vci_enabled=True)
    # Provide a base_url/issuer default acceptable for TestClient
    client = TestClient(create_app(settings=settings))
    response = client.get("/.well-known/openid-credential-issuer")
    assert response.status_code == 200
    body = response.json()
    assert body["credential_issuer"] == settings.issuer
    assert "credential_endpoint" in body
    configuration = body["credential_configurations_supported"]["puridentityserver-sdjwt-vc"]
    assert configuration["vct"] == credential_vct(settings.issuer)


def test_credential_type_metadata_served_at_vct() -> None:
    # SD-JWT VC §6.3.1 : la Type Metadata est servie à l'URL du ``vct``.
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    vct = credential_vct(settings.issuer)
    response = client.get(urlsplit(vct).path)
    assert response.status_code == 200
    body = response.json()
    assert body["vct"] == vct
    assert body["name"]
    assert body["claims"]


def test_signed_issuer_metadata_served_when_accepted() -> None:
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    response = client.get(
        "/.well-known/openid-credential-issuer",
        headers={"Accept": "application/jwt"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/jwt")
    token = response.text
    header = pyjwt.get_unverified_header(token)
    assert header["typ"] == "openidvci-issuer-metadata+jwt"
    assert "jwk" in header
    import json

    from jwt.algorithms import ECAlgorithm, RSAAlgorithm

    jwk = header["jwk"]
    if jwk["kty"] == "RSA":
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    else:
        public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
    claims = pyjwt.decode(
        token, public_key, algorithms=[str(header["alg"])], options={"verify_aud": False}
    )
    assert claims["sub"] == settings.issuer
    assert claims["credential_issuer"] == settings.issuer
    assert "iat" in claims


def test_signed_issuer_metadata_served_with_long_issuer() -> None:
    """L'issuer public long de l'instance hébergée ne casse pas la PKI mdoc.

    Régression issue #295 : la génération de la PKI mdoc dépassait la
    limite X.509 (64) sur le CN et la route renvoyait un 500.
    """
    settings = Settings(
        oid4vci_enabled=True,
        issuer="https://puridentity-op-cert.duckdns.org",
    )
    client = TestClient(create_app(settings=settings))
    response = client.get(
        "/.well-known/openid-credential-issuer",
        headers={"Accept": "application/jwt"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/jwt")


def test_metadata_served_with_trailing_slash() -> None:
    client = TestClient(create_app(settings=Settings(oid4vci_enabled=True)))
    response = client.get("/.well-known/openid-credential-issuer/")
    assert response.status_code == 200
    assert response.json()["credential_issuer"] == Settings(oid4vci_enabled=True).issuer


def test_oauth_authorization_server_metadata_reuses_discovery() -> None:
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    discovery = client.get("/.well-known/openid-configuration").json()
    metadata = client.get("/.well-known/oauth-authorization-server")
    assert metadata.status_code == 200
    body = metadata.json()
    assert body == discovery
    assert body["pushed_authorization_request_endpoint"]
    assert "openid4vci" in body["scopes_supported"]


def test_nonce_endpoint_returns_c_nonce() -> None:
    client = TestClient(create_app(settings=Settings(oid4vci_enabled=True)))
    response = client.post("/nonce")
    assert response.status_code == 200
    # OID4VCI 1.0 §7 : la réponse nonce ne doit pas être mise en cache.
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    # Le c_nonce est un JWT signé par l'OP (validation sans état).
    header = pyjwt.get_unverified_header(body["c_nonce"])
    assert header["typ"] == "c_nonce+jwt"
    # Note: c_nonce_expires_in n'est plus renvoyé (suite conformance) ;
    # le c_nonce est un JWT dont l'expiration est portée par lui-même.


def test_credential_requires_bearer() -> None:
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    response = client.post("/credential")
    assert response.status_code == 401


def test_credential_rejects_invalid_bearer() -> None:
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    response = client.post("/credential", headers={"Authorization": "Bearer token"})
    assert response.status_code == 401


def test_credential_rejects_duplicate_dpop_headers() -> None:
    # RFC 9449 7.1 : un seul en-tête DPoP par message, sinon invalid_request.
    settings = Settings(oid4vci_enabled=True)
    client = TestClient(create_app(settings=settings))
    response = client.post(
        "/credential",
        json={"credential_configuration_id": "puridentityserver-sdjwt-vc"},
        headers=[("Authorization", "DPoP token"), ("DPoP", "proof-one"), ("DPoP", "proof-two")],
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_deferred_and_notification_http() -> None:
    import json as _json
    import time

    settings = Settings(oid4vci_enabled=True)
    settings.clients_seed = [
        {
            "client_id": "tcc2",
            "client_secret": "secret",
            "scopes": "openid4vci",
            "client_type": "confidential",
        }
    ]
    app = create_app(settings=settings)
    with TestClient(app) as client:
        assert client.post("/deferred_credential", json={"transaction_id": "x"}).status_code == 401
        assert (
            client.post(
                "/notification", json={"notification_id": "x", "event": "credential_accepted"}
            ).status_code
            == 401
        )

        token_response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "tcc2",
                "client_secret": "secret",
                "scope": "openid4vci",
            },
        )
        assert token_response.status_code == 200, token_response.text
        token = token_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        deferred = client.post(
            "/deferred_credential", json={"transaction_id": "tid"}, headers=headers
        )
        assert deferred.status_code == 400
        assert deferred.json()["error"] == "invalid_transaction_id"

        notif = client.post(
            "/notification",
            json={"notification_id": "nope", "event": "credential_accepted"},
            headers=headers,
        )
        assert notif.status_code == 400
        assert notif.json()["error"] == "invalid_notification_id"

        nonce = client.post("/nonce").json()["c_nonce"]
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_jwk = _json.loads(
            _jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=False)
        )
        public_jwk["alg"] = "ES256"
        proof = _jwt.encode(
            {"aud": settings.issuer, "nonce": nonce, "iat": int(time.time())},
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            algorithm="ES256",
            headers={"typ": "openid4vci-proof+jwt", "jwk": public_jwk},
        )
        cred = client.post(
            "/credential",
            json={
                "credential_configuration_id": "puridentityserver-sdjwt-vc",
                "proofs": {"jwt": [proof]},
            },
            headers=headers,
        )
        assert cred.status_code == 200, cred.text
        notification_id = cred.json()["notification_id"]

        accepted = client.post(
            "/notification",
            json={"notification_id": notification_id, "event": "credential_accepted"},
            headers=headers,
        )
        assert accepted.status_code == 204


def test_credential_refuses_access_token_after_code_reuse() -> None:
    """RFC 6749 §4.1.2 : le rejeu du code revoque l AT (401 sur /credential).

    Regression issue #304 (module attempt-reuse-authorization-code) : le
    credential endpoint du plan HAIP est le « resource endpoint » appele
    par la suite apres le replay du code — il doit opposer la denylist.
    """
    settings = Settings(
        oid4vci_enabled=True,
        clients_seed=(
            {
                "client_id": "wallet-replay",
                "client_secret": "secret-replay",
                "redirect_uris": ["https://app.example/callback"],
                "scopes": "openid openid4vci",
                "client_type": "confidential",
            },
        ),
        identity_seed_users={"alice": {"email": "alice@example.com", "password": "password"}},
    )
    with TestClient(create_app(settings=settings)) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302

        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "wallet-replay",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid openid4vci",
                "state": "st-replay",
            },
            follow_redirects=False,
        )
        assert auth.status_code == 302
        code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]

        exchange = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "wallet-replay",
                "client_secret": "secret-replay",
            },
        )
        assert exchange.status_code == 200, exchange.text
        token = exchange.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        body = {"credential_configuration_id": "puridentityserver-sdjwt-vc"}

        # L AT est encore valide : le controle de preuve est le premier refuse.
        before = client.post("/credential", json=body, headers=headers)
        assert before.status_code == 400
        assert before.json()["error"] == "invalid_proof"

        replay = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "wallet-replay",
                "client_secret": "secret-replay",
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

        after = client.post("/credential", json=body, headers=headers)
        assert after.status_code == 401
        assert after.json()["error"] == "invalid_token"
