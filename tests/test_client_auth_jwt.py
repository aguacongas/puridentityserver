"""Tests de l'authentification client JWT (RFC 7523 §2.2) et du grant jwt-bearer (§2.1).

Couvre les briques de l'issue #46 :

- ``PyJWTClientAssertionVerifier`` : assertions HMAC (``client_secret_jwt``)
  et asymétriques (``private_key_jwt``, JWKS embarqué) ;
- le grant ``urn:ietf:params:oauth:grant-type:jwt-bearer`` au token endpoint ;
- le câblage des méthodes d'authentification client selon la
  ``token_endpoint_auth_method`` (secrets, JWT, mTLS RFC 8705) ;
- l'enregistrement dynamique du matériel de clé et TLS (RFC 7591 §2.1).
"""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from puridentityserver.application.registration import (
    ClientRegistration,
    RegisterRequest,
    RegistrationConfig,
    RegistrationError,
    RegistrationUseCase,
    UpdateClientRequest,
    hash_secret,
)
from puridentityserver.application.token import (
    TokenConfig,
    TokenError,
    TokenRequest,
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
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.infrastructure.client_assertions import PyJWTClientAssertionVerifier
from puridentityserver.infrastructure.jwks import DefaultKeyManager
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
from puridentityserver.infrastructure.secrets import AsymmetricSecretCipher
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.domain.client_assertions import (
    CLIENT_ASSERTION_TYPE_URN,
    JWT_BEARER_GRANT_TYPE_URN,
)

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_TOKEN_ENDPOINT = f"{_ISSUER}/token"
_REDIRECT_URI = "https://app.example/callback"
_SECRET = "s3cret-shared-hmac"
_INITIAL_TOKEN = "registrar-token"
_TEST_KID = "test-kid-1"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _cipher() -> AsymmetricSecretCipher:
    """Chiffreur de scellement de test (une clé RSA générée dans le store)."""
    cipher, _manager, _repository = _seal_ring()
    return cipher


def _seal_ring() -> tuple[AsymmetricSecretCipher, DefaultKeyManager, InMemoryKeyPairRepository]:
    """Anneau de scellement de test : chiffreur + gestionnaire + store partagés."""
    repository = InMemoryKeyPairRepository()
    manager = DefaultKeyManager(repository, use=KeyUse.SECRET)
    run(manager.ensure_active_key(2048, JWTAlgorithm.RS256))
    return AsymmetricSecretCipher(manager), manager, repository


def _future() -> datetime:
    """Date d'expiration dans le futur pour les codes d'autorisation."""
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _rsa_key() -> tuple[RSAPrivateKey, dict[str, object]]:
    """Paire de clés RSA de test et son JWKS embarqué ``n``/``e``."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": _TEST_KID,
                "alg": "RS256",
                "n": n.rstrip(b"=").decode("ascii"),
                "e": e.rstrip(b"=").decode("ascii"),
            }
        ]
    }
    return private, jwks


def _self_signed_cert() -> tuple[bytes, str]:
    """Génère un certificat auto-signé (DER + sujet RFC 4514) valide 48h."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls-client.example")])
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
    return certificate.public_bytes(Encoding.DER), certificate.subject.rfc4514_string()


def _assertion(
    *,
    iss: str,
    sub: str,
    aud: str,
    secret: str | None = None,
    private_key: RSAPrivateKey | None = None,
    kid: str | None = None,
) -> str:
    """Asserte une assertion JWT (HMAC ou RSA) avec ``exp``/``iat`` valides."""
    now = datetime.now(timezone.utc)
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": int(now.timestamp()) + 600,
        "iat": int(now.timestamp()),
    }
    if private_key is not None:
        assert kid is not None
        return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    assert secret is not None
    return pyjwt.encode(payload, secret, algorithm="HS256")


def _client(
    *,
    client_id: str,
    method: TokenEndpointAuthMethod,
    secret: str = "",
    ciphertext: str = "",
    jwks: tuple[dict[str, object], ...] = (),
    tls_hash: str = "",
    tls_subject_dn: str = "",
) -> Client:
    """Client confidentiel de test avec sa méthode d'authentification."""
    return Client(
        client_id=client_id,
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID}),
        client_type=ClientType.CONFIDENTIAL,
        client_secret_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest() if secret else "",
        token_endpoint_auth_method=method,
        client_secret_ciphertext=ciphertext,
        jwks=jwks,
        tls_client_certificate_hash=tls_hash,
        tls_client_auth_subject_dn=tls_subject_dn,
    )


def _code(client_id: str) -> AuthorizationCode:
    """Code d'autorisation non consommé au nom d'Alice."""
    return AuthorizationCode(
        code="valid-code",
        client_id=client_id,
        redirect_uri=_REDIRECT_URI,
        scopes=frozenset({Scope.OPENID}),
        subject="alice",
        expires_at=_future(),
    )


def _make_usecase(
    client: Client,
    *,
    cipher: AsymmetricSecretCipher | None = None,
    verifier: PyJWTClientAssertionVerifier | None = None,
    no_verifier: bool = False,
) -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository]:
    """TokenUseCase à repos en mémoire, avec le vérificateur d'assertions injecté."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    refresh_tokens = InMemoryRefreshTokenRepository()
    device_codes = InMemoryDeviceAuthorizationRepository()
    token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
    run(clients.save(client))
    config = TokenConfig(issuer=_ISSUER, token_endpoint=_TOKEN_ENDPOINT)
    assertions = None if no_verifier else (verifier or PyJWTClientAssertionVerifier(cipher))
    usecase = TokenUseCase(
        config,
        clients,
        codes,
        token_manager,
        refresh_tokens,
        device_codes,
        client_assertions=assertions,
    )
    return usecase, codes


class TestClientAssertionVerifier:
    """Couvre PyJWTClientAssertionVerifier (HMAC et JWKS embarqué)."""

    def test_hmac_verifies_client_secret_jwt(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        verifier = PyJWTClientAssertionVerifier(cipher)

        claims = run(
            verifier.verify(
                token=_assertion(iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is not None
        assert claims["sub"] == "jwt-app"
        assert claims["iss"] == "jwt-app"

    def test_hmac_rejects_wrong_secret(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=_assertion(iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret="wrong"),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is None

    def test_hmac_rejects_wrong_audience(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=_assertion(
                    iss="jwt-app", sub="jwt-app", aud="https://evil.example/token", secret=_SECRET
                ),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is None

    def test_hmac_rejects_expired_assertion(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "iss": "jwt-app",
                "sub": "jwt-app",
                "aud": _TOKEN_ENDPOINT,
                "exp": int(now.timestamp()) - 60,
            },
            _SECRET,
            algorithm="HS256",
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=token,
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is None

    def test_hmac_rejects_sub_mismatch_when_required(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=_assertion(iss="jwt-app", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is None

    def test_hmac_allows_delegated_sub_for_jwt_bearer(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="svc",
            method=TokenEndpointAuthMethod.NONE,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=_assertion(iss="svc", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=False,
            )
        )

        assert claims is not None
        assert claims["sub"] == "alice"

    def test_hmac_requires_ciphertext(self) -> None:
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
        )

        claims = run(
            PyJWTClientAssertionVerifier(_cipher()).verify(
                token=_assertion(iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )

        assert claims is None

    def test_non_hmac_algorithm_without_jwks_is_rejected(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        private, _ = _rsa_key()
        token = _assertion(
            iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, private_key=private, kid=_TEST_KID
        )

        claims = run(
            PyJWTClientAssertionVerifier(cipher).verify(
                token=token, client=client, audience=_TOKEN_ENDPOINT, require_iss_eq_sub=True
            )
        )

        assert claims is None

    def test_malformed_token_returns_none(self) -> None:
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
        )

        claims = run(
            PyJWTClientAssertionVerifier(_cipher()).verify(
                token="not-a-jwt", client=client, audience=_TOKEN_ENDPOINT, require_iss_eq_sub=True
            )
        )

        assert claims is None

    def test_jwks_embedded_verifies_private_key_jwt(self) -> None:
        private, jwks = _rsa_key()
        client = _client(
            client_id="rsa-app",
            method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
            jwks=_keys_from(jwks),
        )
        token = _assertion(
            iss="rsa-app", sub="rsa-app", aud=_TOKEN_ENDPOINT, private_key=private, kid=_TEST_KID
        )

        claims = run(
            PyJWTClientAssertionVerifier().verify(
                token=token, client=client, audience=_TOKEN_ENDPOINT, require_iss_eq_sub=True
            )
        )

        assert claims is not None
        assert claims["iss"] == "rsa-app"

    def test_jwks_embedded_rejects_unknown_kid(self) -> None:
        private, jwks = _rsa_key()
        client = _client(
            client_id="rsa-app",
            method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
            jwks=_keys_from(jwks),
        )
        token = _assertion(
            iss="rsa-app", sub="rsa-app", aud=_TOKEN_ENDPOINT, private_key=private, kid="absent"
        )

        claims = run(
            PyJWTClientAssertionVerifier().verify(
                token=token, client=client, audience=_TOKEN_ENDPOINT, require_iss_eq_sub=True
            )
        )

        assert claims is None


class TestJwtBearerGrant:
    """Couvre le grant ``jwt-bearer`` (RFC 7523 §2.1) au token endpoint."""

    def _usecase(self) -> TokenUseCase:
        cipher = _cipher()
        client = Client(
            client_id="svc",
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_ciphertext=run(cipher.encrypt(_SECRET)),
        )
        usecase, codes = _make_usecase(client, cipher=cipher)
        run(codes.save(_code("svc")))
        return usecase

    def test_issues_access_token_for_delegated_subject(self) -> None:
        usecase = self._usecase()
        assertion = _assertion(iss="svc", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN,
                    client_id="svc",
                    scope="openid",
                    assertion=assertion,
                )
            )
        )

        assert hasattr(result, "access_token")
        assert result.id_token == ""
        assert result.refresh_token == ""
        claims = pyjwt.decode(result.access_token, options={"verify_signature": False})
        assert claims["sub"] == "alice"
        assert claims["aud"] == "svc"

    def test_rejects_without_verifier(self) -> None:
        client = Client(
            client_id="svc", scopes=frozenset({Scope.OPENID}), client_type=ClientType.CONFIDENTIAL
        )
        usecase, _ = _make_usecase(client, no_verifier=True)
        assertion = _assertion(iss="svc", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN, client_id="svc", assertion=assertion
                )
            )
        )

        assert result.error == "unsupported_grant_type"

    def test_rejects_missing_assertion(self) -> None:
        usecase = self._usecase()

        result = run(
            usecase.execute(
                TokenRequest(grant_type=JWT_BEARER_GRANT_TYPE_URN, client_id="svc", assertion="")
            )
        )

        assert result.error == "invalid_grant"
        assert "manquant" in result.error_description

    def test_rejects_malformed_assertion(self) -> None:
        usecase = self._usecase()

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN, client_id="svc", assertion="bogus"
                )
            )
        )

        assert result.error == "invalid_grant"

    def test_rejects_unknown_client(self) -> None:
        usecase = self._usecase()
        assertion = _assertion(iss="ghost", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET)

        result = run(
            usecase.execute(TokenRequest(grant_type=JWT_BEARER_GRANT_TYPE_URN, assertion=assertion))
        )

        assert result.error == "invalid_client"

    def test_rejects_wrong_signature(self) -> None:
        usecase = self._usecase()
        assertion = _assertion(iss="svc", sub="alice", aud=_TOKEN_ENDPOINT, secret="evil-secret")

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN, client_id="svc", assertion=assertion
                )
            )
        )

        assert result.error == "invalid_grant"

    def test_rejects_unknown_scope(self) -> None:
        usecase = self._usecase()
        assertion = _assertion(iss="svc", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN,
                    client_id="svc",
                    scope="admin",
                    assertion=assertion,
                )
            )
        )

        assert result.error == "invalid_scope"


class TestClientAuthMethodDispatch:
    """Couvre la méthode ``_authenticate_client`` selon la ``token_endpoint_auth_method``."""

    def test_client_secret_jwt_authenticates(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        usecase, codes = _make_usecase(client, cipher=cipher)
        run(codes.save(_code("jwt-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="jwt-app",
                    client_assertion_type=CLIENT_ASSERTION_TYPE_URN,
                    client_assertion=_assertion(
                        iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET
                    ),
                )
            )
        )

        assert hasattr(result, "access_token")

    def test_client_secret_jwt_rejects_missing_assertion(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        usecase, codes = _make_usecase(client, cipher=cipher)
        run(codes.save(_code("jwt-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="jwt-app",
                )
            )
        )

        assert result.error == "invalid_client"

    def test_client_secret_jwt_rejects_wrong_assertion_type(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        usecase, codes = _make_usecase(client, cipher=cipher)
        run(codes.save(_code("jwt-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="jwt-app",
                    client_assertion_type="urn:not-supported",
                    client_assertion=_assertion(
                        iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET
                    ),
                )
            )
        )

        assert result.error == "invalid_client"

    def test_client_secret_jwt_rejects_bad_signature(self) -> None:
        cipher = _cipher()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        usecase, codes = _make_usecase(client, cipher=cipher)
        run(codes.save(_code("jwt-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="jwt-app",
                    client_assertion_type=CLIENT_ASSERTION_TYPE_URN,
                    client_assertion=_assertion(
                        iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret="wrong"
                    ),
                )
            )
        )

        assert result.error == "invalid_client"

    def test_private_key_jwt_authenticates(self) -> None:
        private, jwks = _rsa_key()
        client = _client(
            client_id="rsa-app",
            method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
            jwks=_keys_from(jwks),
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("rsa-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="rsa-app",
                    client_assertion_type=CLIENT_ASSERTION_TYPE_URN,
                    client_assertion=_assertion(
                        iss="rsa-app",
                        sub="rsa-app",
                        aud=_TOKEN_ENDPOINT,
                        private_key=private,
                        kid=_TEST_KID,
                    ),
                )
            )
        )

        assert hasattr(result, "access_token")

    def test_client_secret_post_authenticates(self) -> None:
        client = _client(
            client_id="post-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_POST,
            secret=_SECRET,
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("post-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="post-app",
                    client_secret=_SECRET,
                )
            )
        )

        assert hasattr(result, "access_token")

    def test_tls_client_auth_matches_certificate_hash(self) -> None:
        der, _ = _self_signed_cert()
        client = _client(
            client_id="tls-app",
            method=TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
            tls_hash=der_certificate_hash(der),
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("tls-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-app",
                    tls_certificate=ClientCertificate(der=der, is_self_signed=True),
                )
            )
        )

        assert hasattr(result, "access_token")

    def test_tls_client_auth_rejects_mismatched_certificate(self) -> None:
        der, _ = _self_signed_cert()
        other_der, _ = _self_signed_cert()
        client = _client(
            client_id="tls-app",
            method=TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
            tls_hash=der_certificate_hash(der),
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("tls-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-app",
                    tls_certificate=ClientCertificate(der=other_der, is_self_signed=True),
                )
            )
        )

        assert result.error == "invalid_client"

    def test_tls_client_auth_rejects_missing_certificate(self) -> None:
        der, _ = _self_signed_cert()
        client = _client(
            client_id="tls-app",
            method=TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
            tls_hash=der_certificate_hash(der),
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("tls-app")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-app",
                )
            )
        )

        assert result.error == "invalid_client"

    def test_tls_client_auth_matches_subject_dn(self) -> None:
        der, subject_dn = _self_signed_cert()
        client = _client(
            client_id="tls-dn",
            method=TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
            tls_subject_dn=subject_dn,
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("tls-dn")))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-dn",
                    tls_certificate=ClientCertificate(der=der, subject_dn=subject_dn),
                )
            )
        )

        assert hasattr(result, "access_token")

    def test_self_signed_tls_requires_self_signed_certificate(self) -> None:
        der, _ = _self_signed_cert()
        client = _client(
            client_id="tls-ss",
            method=TokenEndpointAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
            tls_hash=der_certificate_hash(der),
        )
        usecase, codes = _make_usecase(client)
        run(codes.save(_code("tls-ss")))

        not_self_signed = ClientCertificate(der=der, is_self_signed=False)
        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-ss",
                    tls_certificate=not_self_signed,
                )
            )
        )

        assert result.error == "invalid_client"

        ok_self_signed = ClientCertificate(der=der, is_self_signed=True)
        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="valid-code",
                    redirect_uri=_REDIRECT_URI,
                    client_id="tls-ss",
                    tls_certificate=ok_self_signed,
                )
            )
        )

        assert hasattr(result, "access_token")


class TestClientAuthRegistration:
    """Couvre l'enregistrement du matériel d'authentification JWT/TLS (RFC 7591 §2.1)."""

    _INITIAL_TOKEN = _INITIAL_TOKEN

    def _usecase(self, *, cipher: AsymmetricSecretCipher | None = None) -> RegistrationUseCase:
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=True,
            initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
        )
        return RegistrationUseCase(config, InMemoryClientRepository(), secret_cipher=cipher)

    def _register(
        self, usecase: RegistrationUseCase, metadata: dict[str, object]
    ) -> ClientRegistration | RegistrationError:
        return run(usecase.register(RegisterRequest(metadata, initial_access_token=_INITIAL_TOKEN)))

    def test_accepts_private_key_jwt_with_embedded_jwks(self) -> None:
        usecase = self._usecase()
        _, jwks = _rsa_key()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks,
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, ClientRegistration)
        assert result.token_endpoint_auth_method == "private_key_jwt"
        assert result.jwks  # clés échoées dans la réponse
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert len(stored.jwks) == 1
        assert stored.token_endpoint_auth_method is TokenEndpointAuthMethod.PRIVATE_KEY_JWT

    def test_accepts_private_key_jwt_with_jwks_uri(self) -> None:
        usecase = self._usecase()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://app.example/.well-known/jwks.json",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, ClientRegistration)
        assert result.jwks_uri == "https://app.example/.well-known/jwks.json"
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.jwks_uri == result.jwks_uri

    def test_rejects_private_key_jwt_without_key_material(self) -> None:
        usecase = self._usecase()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "private_key_jwt",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "jwks" in result.error_description

    def test_accepts_tls_client_auth_with_certificate(self) -> None:
        usecase = self._usecase()
        der, _ = _self_signed_cert()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_certificate": base64.b64encode(der).decode("ascii"),
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, ClientRegistration)
        assert result.tls_client_certificate_hash == der_certificate_hash(der)
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.tls_client_certificate_hash == der_certificate_hash(der)

    def test_accepts_self_signed_tls_with_subject_dn(self) -> None:
        usecase = self._usecase()
        _, subject_dn = _self_signed_cert()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "tls_client_auth_subject_dn": subject_dn,
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, ClientRegistration)
        assert result.tls_client_auth_subject_dn == subject_dn

    def test_rejects_tls_method_without_material(self) -> None:
        usecase = self._usecase()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_rejects_invalid_tls_certificate(self) -> None:
        usecase = self._usecase()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_certificate": "not-base64!",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_accepts_client_secret_jwt_with_cipher(self) -> None:
        cipher = _cipher()
        usecase = self._usecase(cipher=cipher)
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "client_secret_jwt",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, ClientRegistration)
        assert result.token_endpoint_auth_method == "client_secret_jwt"
        assert result.client_secret
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.client_secret_ciphertext
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == result.client_secret

    def test_rejects_client_secret_jwt_without_cipher(self) -> None:
        usecase = self._usecase()
        metadata = {
            "redirect_uris": [f"{_REDIRECT_URI}"],
            "token_endpoint_auth_method": "client_secret_jwt",
        }

        result = self._register(usecase, metadata)

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "clé de scellement" in result.error_description

    def test_rotates_client_secret_jwt_secret(self) -> None:
        cipher = _cipher()
        usecase = self._usecase(cipher=cipher)
        registered = self._register(
            usecase,
            {
                "redirect_uris": [f"{_REDIRECT_URI}"],
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert isinstance(registered, ClientRegistration)

        new_secret = "a-brand-new-secret"
        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    {
                        "redirect_uris": [f"{_REDIRECT_URI}"],
                        "token_endpoint_auth_method": "client_secret_jwt",
                        "client_secret": new_secret,
                    },
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_secret == new_secret
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == new_secret

    def test_update_without_new_secret_preserves_ciphertext(self) -> None:
        """Un PUT sans nouveau secret ne doit pas vider le secret technique (#46)."""
        cipher = _cipher()
        usecase = self._usecase(cipher=cipher)
        registered = self._register(
            usecase,
            {
                "redirect_uris": [f"{_REDIRECT_URI}"],
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert isinstance(registered, ClientRegistration)
        stored_before = run(usecase._clients.find_by_id(registered.client_id))
        assert stored_before is not None

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    {
                        "redirect_uris": [f"{_REDIRECT_URI}"],
                        "token_endpoint_auth_method": "client_secret_jwt",
                    },
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_secret == ""  # jamais ré-émis
        stored_after = run(usecase._clients.find_by_id(registered.client_id))
        assert stored_after is not None
        assert stored_after.client_secret_ciphertext == stored_before.client_secret_ciphertext
        assert (
            run(cipher.decrypt(stored_after.client_secret_ciphertext)) == registered.client_secret
        )

    def test_update_rewraps_secret_after_key_rotation(self) -> None:
        """Après rotation de la clé, un PUT re-scellé sous la clé la plus récente.

        Le secret en clair du client reste identique : la rotation de la clé
        de scellement est transparente pour lui.
        """
        cipher, manager, key_store = _seal_ring()
        clients = InMemoryClientRepository()

        def _usecase(cipher: AsymmetricSecretCipher) -> RegistrationUseCase:
            config = RegistrationConfig(
                issuer=_ISSUER,
                base_url=_ISSUER,
                requires_initial_access_token=True,
                initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
            )
            return RegistrationUseCase(config, clients, secret_cipher=cipher)

        registered = run(
            _usecase(cipher).register(
                RegisterRequest(
                    {
                        "redirect_uris": [f"{_REDIRECT_URI}"],
                        "token_endpoint_auth_method": "client_secret_jwt",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )
        assert isinstance(registered, ClientRegistration)
        old_ciphertext = run(clients.find_by_id(registered.client_id)).client_secret_ciphertext

        # rotation : une clé de scellement plus récente est générée (l'ancienne reste)
        run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))

        result = run(
            _usecase(cipher).update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    {
                        "redirect_uris": [f"{_REDIRECT_URI}"],
                        "token_endpoint_auth_method": "client_secret_jwt",
                    },
                )
            )
        )
        assert isinstance(result, ClientRegistration)
        assert result.client_secret == ""  # sans nouveau secret, rien n'est émis

        stored = run(clients.find_by_id(registered.client_id))
        assert stored is not None
        assert stored.client_secret_ciphertext != old_ciphertext
        assert run(cipher.is_current(stored.client_secret_ciphertext))
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == registered.client_secret
        # drain terminé : l'ancienne clé peut être retirée, le re-scellage reste lisible
        run(key_store.delete(old_ciphertext.split(":", 1)[0]))
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == registered.client_secret


class TestSecretRotationGrace:
    """Grâce de la rotation : les clients survivent tant que l'ancienne clé est portée."""

    def test_verification_survives_rotation_until_old_key_removed(self) -> None:
        cipher, manager, key_store = _seal_ring()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        verifier = PyJWTClientAssertionVerifier(cipher)
        claims = run(
            verifier.verify(
                token=_assertion(iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET),
                client=client,
                audience=_TOKEN_ENDPOINT,
                require_iss_eq_sub=True,
            )
        )
        assert claims is not None
        assert claims["sub"] == "jwt-app"
        original_kid = client.client_secret_ciphertext.split(":", 1)[0]

        # rotation : la nouvelle clé est ajoutée, la vérification continue de passer
        run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))
        assert (
            run(
                verifier.verify(
                    token=_assertion(
                        iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET
                    ),
                    client=client,
                    audience=_TOKEN_ENDPOINT,
                    require_iss_eq_sub=True,
                )
            )
            is not None
        )

        # drain terminé : l'ancienne clé est retirée, le secret devient illisible
        run(key_store.delete(original_kid))
        assert (
            run(
                verifier.verify(
                    token=_assertion(
                        iss="jwt-app", sub="jwt-app", aud=_TOKEN_ENDPOINT, secret=_SECRET
                    ),
                    client=client,
                    audience=_TOKEN_ENDPOINT,
                    require_iss_eq_sub=True,
                )
            )
            is None
        )

    def test_token_usecase_authenticates_after_key_rotation(self) -> None:
        """Flux complet : client chiffré sous l'ancienne clé, serveur roté."""
        cipher, manager, _key_store = _seal_ring()
        client = _client(
            client_id="jwt-app",
            method=TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))
        verifier = PyJWTClientAssertionVerifier(cipher)
        usecase, _ = _make_usecase(client, cipher=None, verifier=verifier)
        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type=JWT_BEARER_GRANT_TYPE_URN,
                    scope="openid",
                    client_id="jwt-app",
                    assertion=_assertion(
                        iss="jwt-app", sub="alice", aud=_TOKEN_ENDPOINT, secret=_SECRET
                    ),
                )
            )
        )
        assert not isinstance(result, TokenError)
        assert result.access_token


def _keys_from(jwks: dict[str, object]) -> tuple[dict[str, object], ...]:
    """Normalise un document JWKS en tuple de clés pour le domaine Client."""
    keys = jwks["keys"]
    assert isinstance(keys, list)
    return tuple(dict(key) for key in keys)
