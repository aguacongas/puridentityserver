"""Tests de la liaison mTLS forcée RFC 8705 §3.1 (``tls_client_certificate_bound_access_tokens``).

Couvre le flag ``tls_client_certificate_bound_access_tokens`` (issue #127) :
l'exigence de certificat à chaque appel client (token endpoint et
``/bc-authorize``), l'émission de ``cnf.x5t#S256`` sur les access tokens
quelque soit la ``token_endpoint_auth_method`` (usage ``private_key_jwt`` +
holder-of-key), la liaison des refresh tokens au certificat d'émission
(RFC 8705 §3.3) et le comportement inchangé des clients non flagués.
"""

import asyncio
import base64
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import httpx
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from puridentityserver.application.backchannel_authorize import (
    AuthenticationAck,
    BackchannelAuthenticationConfig,
    BackchannelAuthenticationError,
    BackchannelAuthenticationParams,
    BackchannelAuthenticationUseCase,
)
from puridentityserver.application.token import (
    TokenConfig,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ClientCertificate,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
    der_certificate_hash,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.client_assertions import PyJWTClientAssertionVerifier
from puridentityserver.infrastructure.client_tls import (
    ClientCertificateHeaderNames,
    extract_client_certificate,
)
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.backchannel_authentications import (
    InMemoryBackchannelAuthenticationRepository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.device_authorizations import (
    InMemoryDeviceAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.refresh_tokens import (
    InMemoryRefreshTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_TOKEN_ENDPOINT = f"{_ISSUER}/token"
_REDIRECT_URI = "https://app.example/callback"
_CLIENT_ID = "hok-app"
_PLAIN_CLIENT_ID = "plain-app"
_KID = "hok-kid-1"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_USER_EMAIL = "alice@example.com"


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


_DER, _PEM = _certificate("hok-client.example")
_OTHER_DER, _OTHER_PEM = _certificate("other-client.example")
_CERT_HASH = der_certificate_hash(_DER)
_PEM_TEXT = _PEM.decode("ascii")
_OTHER_PEM_TEXT = _OTHER_PEM.decode("ascii")


def _rsa_material() -> tuple[RSAPrivateKey, tuple[dict[str, object], ...]]:
    """Clé privée RSA de test et JWKS embarqué ``n``/``e`` pour le seed."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()

    def b64(value: int) -> str:
        length = (value.bit_length() + 7) // 8
        raw = value.to_bytes(length, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwk: dict[str, object] = {
        "kty": "RSA",
        "use": "sig",
        "kid": _KID,
        "alg": "RS256",
        "n": b64(numbers.n),
        "e": b64(numbers.e),
    }
    return private, (jwk,)


_PRIVATE_KEY, _JWKS = _rsa_material()

_CERTIFICATE_A = ClientCertificate(der=_DER, subject_dn="", is_self_signed=True)
_CERTIFICATE_B = ClientCertificate(der=_OTHER_DER, subject_dn="", is_self_signed=True)

_HOK_CLIENT = Client(
    client_id=_CLIENT_ID,
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
    client_type=ClientType.CONFIDENTIAL,
    token_endpoint_auth_method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
    jwks=_JWKS,
    tls_client_certificate_bound_access_tokens=True,
    backchannel_token_delivery_mode="poll",
)

_PLAIN_CLIENT = Client(
    client_id=_PLAIN_CLIENT_ID,
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
    client_type=ClientType.CONFIDENTIAL,
    token_endpoint_auth_method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
    jwks=_JWKS,
)


def _assertion(client_id: str = _CLIENT_ID) -> str:
    """Assertion ``private_key_jwt`` fraîche (``iss = sub = client_id``)."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": _TOKEN_ENDPOINT,
        "exp": int(now.timestamp()) + 600,
        "iat": int(now.timestamp()),
    }
    return pyjwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": _KID})


def _claims(token: str) -> dict[str, object]:
    """Décode le payload non signé du jeton émis."""
    data = pyjwt.decode(  # NOSONAR(S5659) - lecture seule du payload émis par le serveur
        token,
        options={"verify_signature": False},
    )
    return dict(data)


def _make_token_usecase(
    client: Client,
) -> tuple[TokenUseCase, InMemoryRefreshTokenRepository, InMemoryAuthorizationCodeRepository]:
    """TokenUseCase mémoire avec le client fourni et le vérificateur d'assertions."""
    clients = InMemoryClientRepository()
    refresh_tokens = InMemoryRefreshTokenRepository()
    codes = InMemoryAuthorizationCodeRepository()
    token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
    run(clients.save(client))
    usecase = TokenUseCase(
        TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        codes,
        token_manager,
        refresh_tokens,
        InMemoryDeviceAuthorizationRepository(),
        client_assertions=PyJWTClientAssertionVerifier(),
    )
    return usecase, refresh_tokens, codes


def _make_ciba_usecase(client: Client) -> BackchannelAuthenticationUseCase:
    """BackchannelAuthenticationUseCase mémoire avec user store et assertions."""
    clients = InMemoryClientRepository()
    users = InMemoryUserRepository()
    run(clients.save(client))
    run(users.save(UserClaims(subject="alice", claims={"email": _USER_EMAIL, "name": "Alice"})))
    return BackchannelAuthenticationUseCase(
        BackchannelAuthenticationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            ttl_seconds=600,
            interval_seconds=5,
        ),
        clients,
        users,
        InMemoryBackchannelAuthenticationRepository(),
        client_assertions=PyJWTClientAssertionVerifier(),
    )


def _future_expiry() -> datetime:
    """Date d'expiration dans le futur pour les codes d'autorisation."""
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _offline_code(client_id: str) -> AuthorizationCode:
    """Code d'autorisation non consommé avec ``offline_access``."""
    return AuthorizationCode(
        code=f"code-{client_id}",
        client_id=client_id,
        redirect_uri=_REDIRECT_URI,
        subject="alice",
        scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
        expires_at=_future_expiry(),
    )


def _exchange_request(
    client_id: str = _CLIENT_ID, certificate: ClientCertificate | None = None
) -> TokenRequest:
    """Requête d'échange de code avec ``private_key_jwt`` et certificat éventuel."""
    return TokenRequest(
        grant_type="authorization_code",
        code=f"code-{client_id}",
        redirect_uri=_REDIRECT_URI,
        client_id=client_id,
        client_assertion=_assertion(client_id),
        client_assertion_type=_ASSERTION_TYPE,
        tls_certificate=certificate,
    )


def _refresh_request(
    refresh_token: str,
    client_id: str = _CLIENT_ID,
    certificate: ClientCertificate | None = None,
) -> TokenRequest:
    """Requête de renouvellement avec ``private_key_jwt`` et certificat éventuel."""
    return TokenRequest(
        grant_type="refresh_token",
        refresh_token=refresh_token,
        client_id=client_id,
        client_assertion=_assertion(client_id),
        client_assertion_type=_ASSERTION_TYPE,
        tls_certificate=certificate,
    )


def _hok_app(
    *,
    client_certificate_header: str = "X-SSL-Client-Cert",
    client_certificate_dn_header: str = "X-SSL-Client-S-DN",
) -> FastAPI:
    """Application mémoire avec le client flagué et un client simple."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            client_certificate_header=client_certificate_header,
            client_certificate_dn_header=client_certificate_dn_header,
            clients_seed=(
                {
                    "client_id": _CLIENT_ID,
                    "redirect_uris": [_REDIRECT_URI],
                    "scopes": "openid offline_access",
                    "client_type": "confidential",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": list(_JWKS),
                    "tls_client_certificate_bound_access_tokens": True,
                    "backchannel_token_delivery_mode": "poll",
                },
                {
                    "client_id": _PLAIN_CLIENT_ID,
                    "redirect_uris": [_REDIRECT_URI],
                    "scopes": "openid offline_access",
                    "client_type": "confidential",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": list(_JWKS),
                },
            ),
            protected_resource_enabled=True,
        )
    )


def _client_credentials(
    client: TestClient,
    *,
    certificate_pem: str | None = _PEM_TEXT,
    client_id: str = _CLIENT_ID,
) -> httpx.Response:
    """POST ``/token`` ``client_credentials`` (``private_key_jwt``) avec certificat éventuel."""
    headers = {"X-SSL-Client-Cert": certificate_pem} if certificate_pem else {}
    return client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "scope": "openid",
            "client_assertion": _assertion(client_id),
            "client_assertion_type": _ASSERTION_TYPE,
        },
        headers=headers,
    )


class TestCertificateRequirement:
    """Exigence de certificat à chaque appel d'un client flagué (RFC 8705 §3.1)."""

    def test_client_credentials_without_certificate_is_rejected(self) -> None:
        with TestClient(_hok_app()) as client:
            response = _client_credentials(client, certificate_pem=None)

        assert response.status_code == 400, response.text
        body = response.json()
        assert body["error"] == "invalid_client"
        assert "mTLS" in body["error_description"]

    def test_client_credentials_with_certificate_is_accepted_and_bound(self) -> None:
        with TestClient(_hok_app()) as client:
            response = _client_credentials(client)

            assert response.status_code == 200, response.text
            token = str(response.json()["access_token"])

        cnf = _claims(token)["cnf"]
        assert isinstance(cnf, dict)
        assert cnf["x5t#S256"] == _CERT_HASH

    def test_plain_client_needs_no_certificate_and_is_not_bound(self) -> None:
        with TestClient(_hok_app()) as client:
            response = _client_credentials(client, certificate_pem=None, client_id=_PLAIN_CLIENT_ID)

            assert response.status_code == 200, response.text
            token = str(response.json()["access_token"])

        assert "cnf" not in _claims(token)

    def test_backchannel_authorize_without_certificate_is_rejected(self) -> None:
        usecase = _make_ciba_usecase(_HOK_CLIENT)

        result = run(
            usecase.execute(
                BackchannelAuthenticationParams(
                    client_id=_CLIENT_ID,
                    login_hint=_USER_EMAIL,
                    scope="openid",
                    client_assertion=_assertion(),
                    client_assertion_type=_ASSERTION_TYPE,
                )
            )
        )

        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_client"
        assert result.status_code == 401
        assert "mTLS" in result.error_description

    def test_backchannel_authorize_with_certificate_issues_auth_req_id(self) -> None:
        usecase = _make_ciba_usecase(_HOK_CLIENT)

        result = run(
            usecase.execute(
                BackchannelAuthenticationParams(
                    client_id=_CLIENT_ID,
                    login_hint=_USER_EMAIL,
                    scope="openid",
                    client_assertion=_assertion(),
                    client_assertion_type=_ASSERTION_TYPE,
                    tls_certificate=_CERTIFICATE_A,
                )
            )
        )

        assert isinstance(result, AuthenticationAck)
        assert result.auth_req_id


class TestRefreshTokenCertificateBinding:
    """Liaison du refresh token au certificat d'émission (RFC 8705 §3.3)."""

    @staticmethod
    def _exchange(
        usecase: TokenUseCase,
        codes: InMemoryAuthorizationCodeRepository,
        certificate: ClientCertificate | None,
    ) -> TokenResponse:
        """Échange le code hors ligne du client flagué avec le certificat fourni."""
        run(codes.save(_offline_code(_CLIENT_ID)))
        result = run(usecase.execute(_exchange_request(certificate=certificate)))
        assert isinstance(result, TokenResponse), getattr(result, "error_description", "")
        return result

    def test_exchange_binds_access_and_refresh_tokens_to_certificate(self) -> None:
        usecase, refresh_tokens, codes = _make_token_usecase(_HOK_CLIENT)

        response = self._exchange(usecase, codes, _CERTIFICATE_A)
        stored = run(refresh_tokens.find_by_token_hash(token_hash(response.refresh_token)))

        cnf = _claims(response.access_token)["cnf"]
        assert isinstance(cnf, dict)
        assert cnf["x5t#S256"] == _CERT_HASH
        assert stored is not None
        assert stored.tls_cert_hash == _CERT_HASH

    def test_refresh_with_same_certificate_succeeds(self) -> None:
        usecase, _, codes = _make_token_usecase(_HOK_CLIENT)
        issued = self._exchange(usecase, codes, _CERTIFICATE_A)

        result = run(
            usecase.execute(_refresh_request(issued.refresh_token, certificate=_CERTIFICATE_A))
        )

        assert isinstance(result, TokenResponse), getattr(result, "error_description", "")

    def test_refresh_with_other_certificate_is_refused(self) -> None:
        usecase, _, codes = _make_token_usecase(_HOK_CLIENT)
        issued = self._exchange(usecase, codes, _CERTIFICATE_A)

        result = run(
            usecase.execute(_refresh_request(issued.refresh_token, certificate=_CERTIFICATE_B))
        )

        assert result.error == "invalid_grant"
        assert "RFC 8705" in result.error_description

    def test_refresh_without_certificate_is_refused(self) -> None:
        usecase, _, codes = _make_token_usecase(_HOK_CLIENT)
        issued = self._exchange(usecase, codes, _CERTIFICATE_A)

        result = run(usecase.execute(_refresh_request(issued.refresh_token)))

        assert result.error == "invalid_client"
        assert "mTLS" in result.error_description

    def test_plain_client_refresh_token_is_not_certificate_bound(self) -> None:
        usecase, refresh_tokens, codes = _make_token_usecase(_PLAIN_CLIENT)
        run(codes.save(_offline_code(_PLAIN_CLIENT_ID)))

        result = run(usecase.execute(_exchange_request(_PLAIN_CLIENT_ID)))
        assert isinstance(result, TokenResponse), getattr(result, "error_description", "")

        stored = run(refresh_tokens.find_by_token_hash(token_hash(result.refresh_token)))
        assert stored is not None
        assert stored.tls_cert_hash == ""

        refreshed = run(usecase.execute(_refresh_request(result.refresh_token, _PLAIN_CLIENT_ID)))
        assert isinstance(refreshed, TokenResponse), getattr(refreshed, "error_description", "")


class TestBoundTokenResourceServer:
    """Opposition du lien certificat sur la ressource protégée (RFC 8705 §3.3)."""

    def test_bound_token_rejects_mismatched_or_missing_certificate(self) -> None:
        with TestClient(_hok_app()) as client:
            issued = _client_credentials(client)
            assert issued.status_code == 200, issued.text
            token = str(issued.json()["access_token"])

            accepted = client.get(
                "/protected-resource",
                headers={"Authorization": f"Bearer {token}", "X-SSL-Client-Cert": _PEM_TEXT},
            )
            refused = client.get(
                "/protected-resource",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-SSL-Client-Cert": _OTHER_PEM_TEXT,
                },
            )
            without = client.get(
                "/protected-resource", headers={"Authorization": f"Bearer {token}"}
            )

        assert accepted.status_code == 200, accepted.text
        assert refused.status_code == 401, refused.text
        assert without.status_code == 401, without.text


def _request_with_headers(headers: dict[str, str]) -> Request:
    """Requête ASGI minimale portant les en-têtes fournis (sans contexte TLS)."""
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": [
                (name.lower().encode("latin-1"), value.encode("latin-1"))
                for name, value in headers.items()
            ],
            "client": ("127.0.0.1", 4242),
            "server": ("127.0.0.1", 8000),
        }
    )


class TestConfigurableCertificateHeaders:
    """Noms d'en-têtes mTLS configurables (Settings, tout proxy TLS)."""

    def test_custom_certificate_header_is_read_on_token_endpoint(self) -> None:
        with TestClient(_hok_app(client_certificate_header="X-Proxy-Client-Cert")) as client:
            response = _client_credentials(client, certificate_pem=None)
            assert response.status_code == 400, response.text

            custom = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": _CLIENT_ID,
                    "scope": "openid",
                    "client_assertion": _assertion(),
                    "client_assertion_type": _ASSERTION_TYPE,
                },
                headers={"X-Proxy-Client-Cert": _PEM_TEXT},
            )

        assert custom.status_code == 200, custom.text
        cnf = _claims(str(custom.json()["access_token"]))["cnf"]
        assert isinstance(cnf, dict)
        assert cnf["x5t#S256"] == _CERT_HASH

    def test_default_certificate_header_is_ignored_when_reconfigured(self) -> None:
        with TestClient(_hok_app(client_certificate_header="X-Proxy-Client-Cert")) as client:
            response = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": _CLIENT_ID,
                    "scope": "openid",
                    "client_assertion": _assertion(),
                    "client_assertion_type": _ASSERTION_TYPE,
                },
                headers={"X-SSL-Client-Cert": _PEM_TEXT},
            )

        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"

    def test_extract_uses_configured_names_and_ignores_defaults(self) -> None:
        headers = ClientCertificateHeaderNames(certificate="x-mtls-cert", subject_dn="x-mtls-dn")
        request = _request_with_headers(
            {"x-mtls-cert": _PEM_TEXT, "X-SSL-Client-Cert": _OTHER_PEM_TEXT}
        )

        extracted = extract_client_certificate(request, headers)

        assert extracted.der == _DER
        assert extracted.is_self_signed

    def test_extract_reads_url_encoded_and_escaped_pem(self) -> None:
        url_encoded = _PEM_TEXT.replace("\n", "%0A")
        escaped = _PEM_TEXT.replace("\n", "\\n")
        headers = ClientCertificateHeaderNames(certificate="x-mtls-cert")

        from_url = extract_client_certificate(
            _request_with_headers({"x-mtls-cert": url_encoded}), headers
        )
        from_escaped = extract_client_certificate(
            _request_with_headers({"x-mtls-cert": escaped}), headers
        )

        assert from_url.der == _DER
        assert from_escaped.der == _DER

    def test_extract_falls_back_to_configured_dn_header(self) -> None:
        headers = ClientCertificateHeaderNames(certificate="x-mtls-cert", subject_dn="x-mtls-dn")

        extracted = extract_client_certificate(
            _request_with_headers({"x-mtls-dn": "CN=alice,O=example"}), headers
        )

        assert extracted.der is None
        assert extracted.subject_dn == "CN=alice,O=example"

    def test_extract_without_any_header_returns_empty_certificate(self) -> None:
        extracted = extract_client_certificate(_request_with_headers({}))

        assert extracted.der is None
        assert extracted.subject_dn == ""
