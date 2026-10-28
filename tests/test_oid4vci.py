"""Tests minimaux du support OpenID for Verifiable Credential Issuance (slice 0).

Le support est désactivé par défaut : aucune route n'est montée dans ce cas.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import jwt as pyjwt
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
