"""Tests de la liaison mTLS des access tokens (RFC 8705 §3.3).

Couvre l'émission du claim ``cnf.x5t#S256`` pour un client authentifié
par certificat, son opposabilité sur ``/userinfo`` et la ressource
protégée, et l'exposition du lien en introspection (RFC 7662, qui
conserve ``token_type=Bearer`` — seule la liaison DPoP change le scheme).
"""

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.domain.authorization import der_certificate_hash
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"
_CLIENT_SECRET = "super-secret"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _certificate(common_name: str) -> tuple[bytes, bytes]:
    """Certificat auto-signé de test : couple ``(DER, PEM)``."""
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
        .not_valid_after(now + timedelta(hours=48))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER), certificate.public_bytes(Encoding.PEM)


_DER, _PEM = _certificate("tls-client.example")
_OTHER_DER, _OTHER_PEM = _certificate("other-client.example")
_CERT_HASH = der_certificate_hash(_DER)
_PEM_TEXT = _PEM.decode("ascii")
_OTHER_PEM_TEXT = _OTHER_PEM.decode("ascii")

_TLS_CLIENT = {
    "client_id": "tls-app",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid",
    "client_type": "confidential",
    "token_endpoint_auth_method": "tls_client_auth",
    "tls_client_certificate_hash": _CERT_HASH,
}
_SECRET_CLIENT = {
    "client_id": "web-app",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid",
    "client_type": "confidential",
    "client_secret": _CLIENT_SECRET,
}


def _app(**settings: object) -> FastAPI:
    """Assemble une application mémoire avec les deux clients de test."""
    values: dict[str, object] = {
        "issuer": _ISSUER,
        "base_url": _ISSUER,
        "jwks_algorithms": ("RS256",),
        "clients_seed": (_TLS_CLIENT, _SECRET_CLIENT),
        "protected_resource_enabled": True,
    }
    values.update(settings)
    return create_app(Settings(**values))  # type: ignore[arg-type]


def _client_credentials_token(
    client: TestClient, *, certificate_pem: str = "", client_id: str = "tls-app"
) -> str:
    """Émet un access token ``client_credentials`` avec le certificat fourni."""
    headers = {"X-SSL-Client-Cert": certificate_pem} if certificate_pem else {}
    response = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "scope": "openid"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def _claims(token: str) -> dict[str, object]:
    """Décode le payload non signé de l'access token."""
    data = jwt.decode(  # NOSONAR(S5659) - lecture seule du payload émis par le serveur
        token,
        options={"verify_signature": False},
    )
    return dict(data)


class TestCertificateBoundIssuance:
    """Émission de ``cnf.x5t#S256`` au token endpoint (RFC 8705 §3.3)."""

    def test_tls_client_access_token_carries_certificate_binding(self) -> None:
        with TestClient(_app()) as client:
            token = _client_credentials_token(client, certificate_pem=_PEM_TEXT)

        cnf = _claims(token)["cnf"]
        assert isinstance(cnf, dict)
        assert cnf["x5t#S256"] == _CERT_HASH

    def test_tls_client_without_certificate_is_rejected(self) -> None:
        with TestClient(_app()) as client:
            response = client.post(
                "/token",
                data={"grant_type": "client_credentials", "client_id": "tls-app"},
            )

        assert response.status_code in {400, 401}
        assert response.json()["error"] == "invalid_client"

    def test_secret_client_certificate_header_does_not_bind_token(self) -> None:
        with TestClient(_app()) as client:
            response = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "web-app",
                    "client_secret": _CLIENT_SECRET,
                    "scope": "openid",
                },
                headers={"X-SSL-Client-Cert": _PEM_TEXT},
            )
            assert response.status_code == 200, response.text
            token = str(response.json()["access_token"])

        assert "cnf" not in _claims(token)


class TestCertificateBoundResourceServer:
    """Opposition du lien certificat sur ``/protected-resource`` et ``/userinfo``."""

    @staticmethod
    def _bound_token(client: TestClient) -> str:
        return _client_credentials_token(client, certificate_pem=_PEM_TEXT)

    def test_protected_resource_rejects_bound_token_without_certificate(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.get(
                "/protected-resource", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        assert "RFC 8705" in response.json()["error_description"]

    def test_protected_resource_rejects_mismatched_certificate(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.get(
                "/protected-resource",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-SSL-Client-Cert": _OTHER_PEM_TEXT,
                },
            )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"

    def test_protected_resource_accepts_bound_token_with_certificate(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.get(
                "/protected-resource",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-SSL-Client-Cert": _PEM_TEXT,
                },
            )

        assert response.status_code == 200

    def test_userinfo_rejects_bound_token_without_certificate(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"
        assert "RFC 8705" in response.json()["error_description"]

    def test_userinfo_accepts_bound_token_with_certificate(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.get(
                "/userinfo",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-SSL-Client-Cert": _PEM_TEXT,
                },
            )

        assert response.status_code == 200
        assert response.json()["sub"] == "tls-app"

    def test_introspection_exposes_binding_with_bearer_token_type(self) -> None:
        with TestClient(_app()) as client:
            token = self._bound_token(client)
            response = client.post(
                "/introspect",
                data={
                    "token": token,
                    "client_id": "web-app",
                    "client_secret": _CLIENT_SECRET,
                },
            )

        body = response.json()
        assert body["active"] is True
        assert body["token_type"] == "Bearer"
        assert body["cnf"]["x5t#S256"] == _CERT_HASH
