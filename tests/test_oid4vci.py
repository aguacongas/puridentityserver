"""Tests minimaux du support OpenID for Verifiable Credential Issuance (slice 0).

Le support est désactivé par défaut : aucune route n'est montée dans ce cas.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app


def test_flag_off_exposes_no_oid4vci_routes() -> None:
    app = create_app(settings=Settings(oid4vci_enabled=False))
    client = TestClient(app)
    response = client.get("/.well-known/openid-credential-issuer")
    assert response.status_code == 404


def test_flag_on_exposes_metadata() -> None:
    settings = Settings(oid4vci_enabled=True)
    # Provide a base_url/issuer default acceptable for TestClient
    client = TestClient(create_app(settings=settings))
    response = client.get("/.well-known/openid-credential-issuer")
    assert response.status_code == 200
    body = response.json()
    assert body["credential_issuer"] == settings.issuer
    assert "credential_endpoint" in body
    assert "credential_configurations_supported" in body


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
