"""Tests du chiffrement JWE des ``id_token`` (OIDC Core 1.0 §3.1.3.6, feature #47).

Couvre ``id_token_encrypted_response_alg`` par ``id_token_encrypted_response_enc`` :
gestion de clé ``RSA-OAEP``/``RSA-OAEP-256`` (clé publique RSA du ``jwks``
embarqué du client), ``A128KW``/``A256KW`` (RFC 3394) et ``dir`` (clé dérivée
par HKDF) ; chiffrement ``A*CBC-HS*`` (RFC 7518 §5.2) et ``A*GCM`` (§5.3).
L'``id_token`` JWS du serveur est imbriqué avec ``cty: JWT`` (RFC 7516 §4.1.12).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.application.id_token_encryption import (
    encrypt_id_token_for_client,
    resolve_id_token_encryption,
)
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
    ClientType,
    Scope,
)
from puridentityserver.domain.jwe import (
    ALL_ENCRYPTION_ALGORITHMS,
    ALL_ENCRYPTION_METHODS,
    ASYMMETRIC_ENCRYPTION_ALGORITHMS,
    CBC_ENCRYPTION_METHODS,
    DEFAULT_ENCRYPTION_METHOD,
    SYMMETRIC_ENCRYPTION_ALGORITHMS,
    JWEEncryptionMethod,
    JWEKeyManagementAlgorithm,
)
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.infrastructure.jwe import (
    JWEIdTokenEncrypter,
    b64u,
    b64u_decode,
    decrypt_compact,
    derive_content_key,
    encrypt_compact,
    rsa_public_key_from_jwks,
)
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
from puridentityserver.interfaces.domain.tokens import JWEUnavailableError

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_SECRET = "s3cret-client"

_INITIAL_TOKEN = "registrar-token"

_KW_KEK_SIZE = {
    JWEKeyManagementAlgorithm.A128KW: 16,
    JWEKeyManagementAlgorithm.A256KW: 32,
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _rsa_key() -> tuple[RSAPrivateKey, RSAPublicKey, tuple[dict[str, object], ...]]:
    """Génère une paire RSA 2048 bits et son ``(n, e)`` JWKS (RFC 7517 §4.3)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    numbers = public.public_numbers()
    size = (numbers.n.bit_length() + 7) // 8
    key = {
        "kty": "RSA",
        "use": "enc",
        "kid": "enc-1",
        "n": b64u(numbers.n.to_bytes(size, "big")),
        "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    return private, public, (key,)


def _kek(algorithm: JWEKeyManagementAlgorithm, method: JWEEncryptionMethod) -> bytes:
    """Clé dérivée depuis le secret client pour les familles symétriques."""
    size = (
        method.cek_size
        if algorithm is JWEKeyManagementAlgorithm.DIRECT
        else _KW_KEK_SIZE[algorithm]
    )
    return derive_content_key(_SECRET, size)


def _seal_ring() -> tuple[AsymmetricSecretCipher, DefaultKeyManager]:
    """Chiffreur de scellement chiffrant sous une clé ``KeyUse.SECRET`` fraîche."""
    manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.SECRET)
    run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))
    return AsymmetricSecretCipher(manager), manager


class TestEncryptDecryptCompact:
    """Aller-retour du format JWE compact pour toutes les combinaisons (RFC 7516)."""

    @pytest.mark.parametrize("algorithm", ALL_ENCRYPTION_ALGORITHMS)
    @pytest.mark.parametrize("method", ALL_ENCRYPTION_METHODS)
    def test_round_trip(
        self,
        algorithm: JWEKeyManagementAlgorithm,
        method: JWEEncryptionMethod,
    ) -> None:
        private, public, _ = _rsa_key()
        plaintext = b"contenu secret de l'id_token"

        if algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
            token = encrypt_compact(
                algorithm=algorithm, method=method, plaintext=plaintext, rsa_public_key=public
            )
            decrypted = decrypt_compact(
                token,
                algorithm=algorithm,
                method=method,
                rsa_private_key=private,
            )
        else:
            kek = _kek(algorithm, method)
            encryptor = {
                "kek": kek,
                "rsa_public_key": None,
            }
            token = encrypt_compact(
                algorithm=algorithm,
                method=method,
                plaintext=plaintext,
                shared_kek=encryptor["kek"],
            )
            decrypted = decrypt_compact(
                token,
                algorithm=algorithm,
                method=method,
                shared_kek=kek,
            )

        assert decrypted == plaintext
        header, _encrypted_key, iv, ciphertext, tag = token.split(".")
        header_json = json.loads(b64u_decode(header).decode("utf-8"))
        assert header_json["alg"] == algorithm.value
        assert header_json["enc"] == method.value
        assert b64u_decode(iv) and b64u_decode(ciphertext) and b64u_decode(tag)

    @pytest.mark.parametrize("method", CBC_ENCRYPTION_METHODS)
    def test_tampered_ciphertext_rejected(self, method: JWEEncryptionMethod) -> None:
        algorithm = JWEKeyManagementAlgorithm.A128KW
        kek = _kek(algorithm, method)
        token = encrypt_compact(
            algorithm=algorithm,
            method=method,
            plaintext=b"contenu authentifi",
            shared_kek=kek,
        )
        tag = token.rsplit(".", 1)[1]
        flipped = chr(ord(tag[0]) ^ 0x20)
        tampered = token[: -len(tag)] + flipped + tag[1:]

        with pytest.raises(ValueError):
            decrypt_compact(
                tampered,
                algorithm=algorithm,
                method=method,
                shared_kek=kek,
            )

    def test_dir_rejects_undersized_content_key(self) -> None:
        with pytest.raises(ValueError, match="exige une clé de contenu"):
            encrypt_compact(
                algorithm=JWEKeyManagementAlgorithm.DIRECT,
                method=JWEEncryptionMethod.A256GCM,
                plaintext=b"x",
                shared_kek=b"too-short",
            )

    def test_rsa_public_key_from_jwks_resolves_n_and_e(self) -> None:
        _, public, keys = _rsa_key()
        resolved = rsa_public_key_from_jwks(keys)
        assert isinstance(resolved, RSAPublicKey)
        assert resolved.public_numbers().n == public.public_numbers().n


class TestJWEIdTokenEncrypter:
    """L'encapsuleur imbrique le JWS serveur avec ``cty: JWT`` (RFC 7516 §4.1.12)."""

    def _client(self, *, algorithm: str, enc: str, keys: tuple[dict[str, object], ...]) -> Client:
        return Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            jwks=keys,
            id_token_encrypted_response_alg=algorithm,
            id_token_encrypted_response_enc=enc,
        )

    def test_nests_jws_with_cty_jwt_and_default_enc(self) -> None:
        encrypter = JWEIdTokenEncrypter()
        client = self._client(
            algorithm="dir",
            enc="",
            keys=(),
        )
        jws = "eyJhbGciOiJSUzI1NiJ9.example.payload"

        sealed = run(
            encrypter.encrypt_id_token(
                id_token=jws,
                client=client,
                shared_secret=_SECRET,
            )
        )

        header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
        assert header["alg"] == "dir"
        assert header["enc"] == DEFAULT_ENCRYPTION_METHOD.value
        assert header["cty"] == "JWT"
        assert (
            decrypt_compact(
                sealed,
                algorithm=JWEKeyManagementAlgorithm.DIRECT,
                method=DEFAULT_ENCRYPTION_METHOD,
                shared_kek=derive_content_key(_SECRET, DEFAULT_ENCRYPTION_METHOD.cek_size),
            ).decode("utf-8")
            == jws
        )

    def test_unknown_algorithm_raises(self) -> None:
        encrypter = JWEIdTokenEncrypter()
        client = self._client(algorithm="BOGUS", enc="", keys=())
        with pytest.raises(JWEUnavailableError):
            run(
                encrypter.encrypt_id_token(
                    id_token="jws",
                    client=client,
                    shared_secret=_SECRET,
                )
            )


class TestResolveIdTokenEncryption:
    """Résolution du matériel de chiffrement d'``id_token`` par client."""

    def _client(self, *, algorithm: str, enc: str = "", ciphertext: str = "") -> Client:
        return Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            client_secret_ciphertext=ciphertext,
            id_token_encrypted_response_alg=algorithm,
            id_token_encrypted_response_enc=enc,
        )

    def test_absent_configuration_returns_none(self) -> None:
        client = self._client(algorithm="")
        assert run(resolve_id_token_encryption(client, None)) is None

    def test_unknown_algorithm_returns_none(self) -> None:
        client = self._client(algorithm="RSA-KEM")
        assert run(resolve_id_token_encryption(client, None)) is None

    def test_unknown_method_returns_none(self) -> None:
        client = self._client(algorithm="dir", enc="A128CCM")
        assert run(resolve_id_token_encryption(client, None)) is None

    @pytest.mark.parametrize("algorithm", ASYMMETRIC_ENCRYPTION_ALGORITHMS)
    def test_asymmetric_uses_default_method(self, algorithm: JWEKeyManagementAlgorithm) -> None:
        client = self._client(algorithm=algorithm.value)
        assert run(resolve_id_token_encryption(client, None)) == (
            algorithm,
            DEFAULT_ENCRYPTION_METHOD,
            "",
        )

    def test_asymmetric_preserves_explicit_method(self) -> None:
        client = self._client(algorithm="RSA-OAEP-256", enc="A192GCM")
        assert run(resolve_id_token_encryption(client, None)) == (
            JWEKeyManagementAlgorithm.RSA_OAEP_256,
            JWEEncryptionMethod.A192GCM,
            "",
        )

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ENCRYPTION_ALGORITHMS)
    def test_symmetric_without_cipher_returns_none(
        self, algorithm: JWEKeyManagementAlgorithm
    ) -> None:
        client = self._client(algorithm=algorithm.value, ciphertext="chiffré")
        assert run(resolve_id_token_encryption(client, None)) is None

    def test_symmetric_without_ciphertext_returns_none(self) -> None:
        cipher, _ = _seal_ring()
        client = self._client(algorithm="A128KW")
        assert run(resolve_id_token_encryption(client, cipher)) is None

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ENCRYPTION_ALGORITHMS)
    def test_symmetric_decrypts_shared_secret(self, algorithm: JWEKeyManagementAlgorithm) -> None:
        cipher, _ = _seal_ring()
        client = self._client(
            algorithm=algorithm.value,
            enc="A256GCM",
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        assert run(resolve_id_token_encryption(client, cipher)) == (
            algorithm,
            JWEEncryptionMethod.A256GCM,
            _SECRET,
        )

    def test_should_encrypt_only_when_algorithm_configured(self) -> None:
        assert (
            run(
                encrypt_id_token_for_client(
                    id_token="jws",
                    client=self._client(algorithm=""),
                    secret_cipher=None,
                    encrypter=JWEIdTokenEncrypter(),
                )
            )
            == "jws"
        )

    def test_missing_encrypter_raises(self) -> None:
        with pytest.raises(JWEUnavailableError, match="aucun chiffreur"):
            run(
                encrypt_id_token_for_client(
                    id_token="jws",
                    client=self._client(algorithm="dir"),
                    secret_cipher=None,
                    encrypter=None,
                )
            )


class TestTokenEndpointEncryptedIdToken:
    """L'échange de code émet un ``id_token`` JWE (sans jamais exposer le JWS)."""

    def _usecase(
        self,
        client: Client,
        cipher: AsymmetricSecretCipher | None,
    ) -> TokenUseCase:
        clients = InMemoryClientRepository()
        run(clients.save(client))
        km = DefaultKeyManager(InMemoryKeyPairRepository())
        return TokenUseCase(
            TokenConfig(
                issuer=_ISSUER,
                signing_algorithm=JWTAlgorithm.RS256,
                secret_cipher=cipher,
                id_token_encrypter=JWEIdTokenEncrypter(),
            ),
            clients,
            InMemoryAuthorizationCodeRepository(),
            PyJWTTokenManager(km),
            InMemoryRefreshTokenRepository(),
            InMemoryDeviceAuthorizationRepository(),
        )

    def _save_code(self, usecase: TokenUseCase) -> str:
        code = AuthorizationCode(
            code="jwe-code",
            client_id="jwe-client",
            redirect_uri="https://app.example/callback",
            subject="user-123",
            scopes=frozenset({Scope.OPENID}),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        run(usecase._codes.save(code))
        return code.code

    def _exchange(self, usecase: TokenUseCase, *, client_secret: str = _SECRET) -> str:
        response = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code=self._save_code(usecase),
                    redirect_uri="https://app.example/callback",
                    client_id="jwe-client",
                    client_secret=client_secret,
                )
            )
        )
        assert not isinstance(response, TokenError)
        assert response.id_token
        return response.id_token

    def _rsa_client(self) -> tuple[RSAPrivateKey, Client]:
        private, public, keys = _rsa_key()
        client = Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            jwks=keys,
            id_token_encrypted_response_alg="RSA-OAEP",
            id_token_encrypted_response_enc="A128GCM",
        )
        assert public is not None
        return private, client

    def test_rsa_oaep_encrypts_and_inner_jws_signed_by_server(self) -> None:
        private, client = self._rsa_client()
        usecase = self._usecase(client, None)

        sealed = self._exchange(usecase)

        header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
        assert header["alg"] == "RSA-OAEP"
        assert header["enc"] == "A128GCM"
        inner = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm.RSA_OAEP,
            method=JWEEncryptionMethod.A128GCM,
            rsa_private_key=private,
        ).decode("utf-8")
        inner_header = pyjwt.get_unverified_header(inner)
        assert inner_header["alg"] == "RS256"
        assert inner_header["kid"]
        claims = pyjwt.decode(
            inner,
            options={"verify_signature": False},
            issuer=_ISSUER,
            audience="jwe-client",
        )
        assert claims["sub"] == "user-123"

    def test_symmetric_dir_with_default_enc(self) -> None:
        cipher, _ = _seal_ring()
        client = Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            client_secret_ciphertext=run(cipher.encrypt(_SECRET)),
            id_token_signed_response_alg="HS256",
            id_token_encrypted_response_alg="dir",
        )
        usecase = self._usecase(client, cipher)

        sealed = self._exchange(usecase)

        header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
        assert header["alg"] == "dir"
        assert header["enc"] == DEFAULT_ENCRYPTION_METHOD.value
        inner = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm.DIRECT,
            method=DEFAULT_ENCRYPTION_METHOD,
            shared_kek=derive_content_key(_SECRET, DEFAULT_ENCRYPTION_METHOD.cek_size),
        ).decode("utf-8")
        claims = pyjwt.decode(
            inner,
            _SECRET.encode("utf-8"),
            algorithms=["HS256"],
            issuer=_ISSUER,
            audience="jwe-client",
        )
        assert claims["sub"] == "user-123"

    def test_symmetric_aes_kw(self) -> None:
        cipher, _ = _seal_ring()
        client = Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            client_secret_ciphertext=run(cipher.encrypt(_SECRET)),
            id_token_signed_response_alg="HS256",
            id_token_encrypted_response_alg="A128KW",
            id_token_encrypted_response_enc="A192CBC-HS384",
        )
        usecase = self._usecase(client, cipher)

        sealed = self._exchange(usecase)

        header = json.loads(b64u_decode(sealed.split(".")[0]).decode("utf-8"))
        assert header["alg"] == "A128KW"
        assert header["enc"] == "A192CBC-HS384"
        inner = decrypt_compact(
            sealed,
            algorithm=JWEKeyManagementAlgorithm.A128KW,
            method=JWEEncryptionMethod.A192CBC_HS384,
            shared_kek=derive_content_key(_SECRET, 16),
        ).decode("utf-8")
        assert (
            pyjwt.decode(
                inner,
                _SECRET.encode("utf-8"),
                algorithms=["HS256"],
                issuer=_ISSUER,
                audience="jwe-client",
            )["sub"]
            == "user-123"
        )

    def test_missing_symmetric_material_rejects_exchange(self) -> None:
        cipher, _ = _seal_ring()
        client = Client(
            client_id="jwe-client",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hash_secret(_SECRET),
            id_token_encrypted_response_alg="dir",
        )
        usecase = self._usecase(client, cipher)

        response = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code=self._save_code(usecase),
                    redirect_uri="https://app.example/callback",
                    client_id="jwe-client",
                    client_secret=_SECRET,
                )
            )
        )
        assert isinstance(response, TokenError)
        assert response.error == "invalid_client"
        assert "indisponible" in response.error_description


class TestRegistrationEncryption:
    """L'enregistrement valide le couple ``alg``/``enc`` et son matériel (§3.1.3.6)."""

    def _usecase(self, *, secret_cipher: AsymmetricSecretCipher | None) -> RegistrationUseCase:
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=True,
            initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
        )
        return RegistrationUseCase(config, InMemoryClientRepository(), secret_cipher=secret_cipher)

    def test_registers_rsa_client_with_embedded_jwks(self) -> None:
        _, _, keys = _rsa_key()
        usecase = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "jwks": {"keys": list(keys)},
                        "id_token_encrypted_response_alg": "RSA-OAEP",
                        "id_token_encrypted_response_enc": "A256GCM",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.id_token_encrypted_response_alg == "RSA-OAEP"
        assert result.id_token_encrypted_response_enc == "A256GCM"
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.jwks and stored.jwks[0]["kty"] == "RSA"

    def test_rejects_rsa_without_public_key(self) -> None:
        usecase = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "id_token_encrypted_response_alg": "RSA-OAEP-256",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "RSA" in result.error_description

    def test_rejects_enc_without_alg(self) -> None:
        usecase = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_encrypted_response_enc": "A128GCM",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "id_token_encrypted_response_enc exige" in result.error_description

    @pytest.mark.parametrize("algorithm", ("A128KW", "A256KW", "dir"))
    def test_registers_symmetric_client_with_sealed_secret(self, algorithm: str) -> None:
        cipher, _ = _seal_ring()
        usecase = self._usecase(secret_cipher=cipher)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "id_token_encrypted_response_alg": algorithm,
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.id_token_encrypted_response_alg == algorithm
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.client_secret_ciphertext

    def test_rejects_symmetric_with_keyless_auth_method(self) -> None:
        cipher, _ = _seal_ring()
        usecase = self._usecase(secret_cipher=cipher)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "none",
                        "id_token_encrypted_response_alg": "A128KW",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "secret partagé" in result.error_description

    def test_rejects_symmetric_without_seal_cipher(self) -> None:
        usecase = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_encrypted_response_alg": "dir",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "chiffreur" in result.error_description

    def test_update_to_symmetric_without_new_secret_rejected(self) -> None:
        cipher, _ = _seal_ring()
        usecase = self._usecase(secret_cipher=cipher)
        registered = self._plain_client(usecase)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    client_id=registered.client_id,
                    registration_access_token=registered.registration_access_token,
                    metadata={
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_encrypted_response_alg": "A256KW",
                    },
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "nouveau client_secret" in result.error_description

    def test_update_to_symmetric_with_new_secret_seals_it(self) -> None:
        cipher, _ = _seal_ring()
        usecase = self._usecase(secret_cipher=cipher)
        registered = self._plain_client(usecase)
        new_secret = "nouveau-secret-jwe"

        result = run(
            usecase.update(
                UpdateClientRequest(
                    client_id=registered.client_id,
                    registration_access_token=registered.registration_access_token,
                    metadata={
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "client_secret": new_secret,
                        "id_token_encrypted_response_alg": "dir",
                    },
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.id_token_encrypted_response_alg == "dir"
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == new_secret

    def test_rejects_unknown_algorithm(self) -> None:
        usecase = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_encrypted_response_alg": "ECDH-ES+A128KW",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "non supporté" in result.error_description

    def _plain_client(self, usecase: RegistrationUseCase) -> ClientRegistration:
        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "client_secret_basic",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )
        assert isinstance(result, ClientRegistration)
        assert result.client_secret
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert not stored.client_secret_ciphertext
        return result


class TestDiscoveryEncryptionValues:
    """Le discovery annonce les familles JWE supportées (OIDC Discovery 1.0 §3)."""

    def test_document_exposes_encryption_values(self) -> None:
        metadata = run(DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER)).execute())
        assert metadata["id_token_encryption_alg_values_supported"] == [
            algorithm.value for algorithm in ALL_ENCRYPTION_ALGORITHMS
        ]
        assert metadata["id_token_encryption_enc_values_supported"] == [
            method.value for method in ALL_ENCRYPTION_METHODS
        ]

    def test_configuration_subset_is_respected(self) -> None:
        config = DiscoveryConfig(
            issuer=_ISSUER,
            encryption_algorithms=("dir", "RSA-OAEP-256"),
            encryption_methods=("A128CBC-HS256", "A256GCM"),
        )
        metadata = run(DiscoveryUseCase(config).execute())
        assert metadata["id_token_encryption_alg_values_supported"] == [
            "dir",
            "RSA-OAEP-256",
        ]
        assert metadata["id_token_encryption_enc_values_supported"] == [
            "A128CBC-HS256",
            "A256GCM",
        ]
