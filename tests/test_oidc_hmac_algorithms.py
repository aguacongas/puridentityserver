"""Tests des algorithmes symétriques HS* pour la signature d'``id_token`` (#47).

Couvre OIDC Core 1.0 §3.1.3.7 : ``id_token_signed_response_alg`` HS* signe
l'``id_token`` avec le secret partagé du client (JWS HMAC, sans ``kid``),
le secret étant conservé chiffré (clé de scellement ``KeyUse.SECRET``) et
uniquement récupérable par le serveur à l'émission. Sans chiffreur ou sans
secret récupérable, l'émission échoue — les clés HS* n'existent jamais au
JWKS serveur.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt as pyjwt
import pytest

from puridentityserver.application.id_token_material import resolve_id_token_material
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
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm, KeyUse
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

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_SECRET = "s3cret-client"

_INITIAL_TOKEN = "registrar-token"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _seal_ring() -> tuple[AsymmetricSecretCipher, DefaultKeyManager]:
    """Chiffreur de scellement chiffrant sous une clé ``KeyUse.SECRET`` fraîche."""
    manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.SECRET)
    run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))
    return AsymmetricSecretCipher(manager), manager


def _hs_client(*, algorithm: JWTAlgorithm, ciphertext: str, secret_hash: str = "") -> Client:
    """Client confidentiel signant son ``id_token`` en HS* avec ``secret`` scellé."""
    return Client(
        client_id="hmac-client",
        redirect_uris=frozenset({"https://app.example/callback"}),
        scopes=frozenset({Scope.OPENID}),
        client_type=ClientType.CONFIDENTIAL,
        client_secret_hash=secret_hash or hash_secret(_SECRET),
        client_secret_ciphertext=ciphertext,
        id_token_signed_response_alg=algorithm.value,
    )


def _token_usecase(client: Client, cipher: AsymmetricSecretCipher | None) -> TokenUseCase:
    """Construit un ``TokenUseCase`` avec le client donné et le chiffreur injecté."""
    clients = InMemoryClientRepository()
    run(clients.save(client))
    km = DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    return TokenUseCase(
        TokenConfig(
            issuer=_ISSUER,
            signing_algorithm=JWTAlgorithm.RS256,
            secret_cipher=cipher,
        ),
        clients,
        InMemoryAuthorizationCodeRepository(),
        token_manager,
        InMemoryRefreshTokenRepository(),
        InMemoryDeviceAuthorizationRepository(),
    )


def _save_code(usecase: TokenUseCase) -> str:
    """Conserve un code d'autorisation non expiré adressé au client HMAC."""
    code = AuthorizationCode(
        code="hmac-code",
        client_id="hmac-client",
        redirect_uri="https://app.example/callback",
        subject="user-123",
        scopes=frozenset({Scope.OPENID}),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    run(usecase._codes.save(code))
    return code.code


def _exchange_id_token(
    usecase: TokenUseCase, *, client_secret: str = _SECRET
) -> tuple[str, dict[str, object]]:
    """Échange le code et retourne ``(id_token, header déchiffré)`` du client HMAC."""
    request = TokenRequest(
        grant_type="authorization_code",
        code=_save_code(usecase),
        redirect_uri="https://app.example/callback",
        client_id="hmac-client",
        client_secret=client_secret,
    )
    response = run(usecase.execute(request))
    assert not isinstance(response, TokenError)
    assert response.id_token
    header = pyjwt.get_unverified_header(response.id_token)
    return response.id_token, header


class TestResolveIdTokenMaterial:
    """Résolution du matériel de signature d'``id_token`` par client."""

    def test_absent_configuration_uses_server_default(self) -> None:
        client = replace(
            _hs_client(algorithm=JWTAlgorithm.ES512, ciphertext="x"),
            id_token_signed_response_alg="",
        )
        default = JWTAlgorithm.RS512
        material = run(resolve_id_token_material(client, default, None))
        assert material == (default, "")

    def test_unknown_value_falls_back_to_default(self) -> None:
        client = replace(
            _hs_client(algorithm=JWTAlgorithm.RS256, ciphertext="x"),
            id_token_signed_response_alg="HS999",
        )
        default = JWTAlgorithm.RS256
        assert run(resolve_id_token_material(client, default, None)) == (default, "")

    def test_asymmetric_uses_algorithm_without_shared_secret(self) -> None:
        client = _hs_client(algorithm=JWTAlgorithm.ES384, ciphertext="")
        assert run(resolve_id_token_material(client, JWTAlgorithm.RS256, None)) == (
            JWTAlgorithm.ES384,
            "",
        )

    def test_hs_without_cipher_returns_none(self) -> None:
        client = replace(
            _hs_client(algorithm=JWTAlgorithm.HS256, ciphertext="chiffré"),
            client_secret_ciphertext="chiffré",
        )
        assert run(resolve_id_token_material(client, JWTAlgorithm.RS256, None)) is None

    def test_hs_without_ciphertext_returns_none(self) -> None:
        cipher, _ = _seal_ring()
        client = _hs_client(algorithm=JWTAlgorithm.HS256, ciphertext="")
        assert run(resolve_id_token_material(client, JWTAlgorithm.RS256, cipher)) is None

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ALGORITHMS)
    def test_hs_decrypts_shared_secret(self, algorithm: JWTAlgorithm) -> None:
        cipher, _ = _seal_ring()
        client = _hs_client(
            algorithm=algorithm,
            ciphertext=run(cipher.encrypt(_SECRET)),
        )
        assert run(resolve_id_token_material(client, JWTAlgorithm.RS256, cipher)) == (
            algorithm,
            _SECRET,
        )


class TestSigningKeysFilterHmac:
    """Les algorithmes HS* ne produisent jamais de clés de serveur (JWKS)."""

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ALGORITHMS)
    def test_generating_key_pair_rejected(self, algorithm: JWTAlgorithm) -> None:
        manager = DefaultKeyManager(InMemoryKeyPairRepository())
        awaitable = manager.generate_key_pair(2048, algorithm)
        with pytest.raises(ValueError, match="aucune clé à générer"):
            asyncio.run(awaitable)

    def test_ensure_active_key_raises_for_hmac(self) -> None:
        manager = DefaultKeyManager(InMemoryKeyPairRepository())
        awaitable = manager.ensure_active_key(2048, JWTAlgorithm.HS512)
        with pytest.raises(ValueError, match="aucune clé à générer"):
            asyncio.run(awaitable)


class TestTokenEndpointHmacSigning:
    """L'échange de code émet un ``id_token`` signé HS* avec le secret du client."""

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ALGORITHMS)
    def test_id_token_signed_with_client_shared_secret(self, algorithm: JWTAlgorithm) -> None:
        cipher, _ = _seal_ring()
        client = _hs_client(algorithm=algorithm, ciphertext=run(cipher.encrypt(_SECRET)))
        usecase = _token_usecase(client, cipher)

        id_token, header = _exchange_id_token(usecase)

        assert header["alg"] == algorithm.value
        assert "kid" not in header
        decoded = pyjwt.decode(
            id_token,
            _SECRET.encode("utf-8"),
            algorithms=[algorithm.value],
            issuer=_ISSUER,
            options={"verify_aud": False},
        )
        assert decoded["sub"] == "user-123"
        assert decoded["aud"] == "hmac-client"

    def test_hmac_signature_rejects_wrong_secret(self) -> None:
        cipher, _ = _seal_ring()
        client = _hs_client(algorithm=JWTAlgorithm.HS256, ciphertext=run(cipher.encrypt(_SECRET)))
        usecase = _token_usecase(client, cipher)

        id_token, _ = _exchange_id_token(usecase)

        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(
                id_token,
                b"wrong-secret",
                algorithms=["HS256"],
                issuer=_ISSUER,
                options={"verify_aud": False},
            )

    def test_access_token_still_signed_with_server_key(self) -> None:
        cipher, _ = _seal_ring()
        client = _hs_client(algorithm=JWTAlgorithm.HS384, ciphertext=run(cipher.encrypt(_SECRET)))
        usecase = _token_usecase(client, cipher)
        response = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code=_save_code(usecase),
                    redirect_uri="https://app.example/callback",
                    client_id="hmac-client",
                    client_secret=_SECRET,
                )
            )
        )
        assert response.access_token
        header = pyjwt.get_unverified_header(response.access_token)
        assert header["alg"] == "RS256"
        assert header["kid"]

    def test_hs_without_recoverable_secret_rejects_exchange(self) -> None:
        cipher, _ = _seal_ring()
        client = replace(
            _hs_client(algorithm=JWTAlgorithm.HS256, ciphertext=run(cipher.encrypt(_SECRET))),
            id_token_signed_response_alg="HS256",
            client_secret_ciphertext="",
        )
        usecase = _token_usecase(client, cipher)

        request = TokenRequest(
            grant_type="authorization_code",
            code=_save_code(usecase),
            redirect_uri="https://app.example/callback",
            client_id="hmac-client",
            client_secret=_SECRET,
        )
        response = run(usecase.execute(request))
        assert isinstance(response, TokenError)
        assert response.error == "invalid_client"
        assert "indisponible" in response.error_description

    def test_hmac_without_shared_secret_raises(self) -> None:
        manager = DefaultKeyManager(InMemoryKeyPairRepository())
        token_manager = PyJWTTokenManager(manager)
        awaitable = token_manager.create_id_token(
            algorithm=JWTAlgorithm.HS256,
            issuer=_ISSUER,
            subject="user-123",
            audience="hmac-client",
            nonce="",
            expires_at=9999999999,
            issued_at=9999990000,
        )
        with pytest.raises(ValueError, match="secret partagé"):
            asyncio.run(awaitable)


class TestRegistrationHmacSigning:
    """L'enregistrement d'un client HS* scelle le secret ; les transitions refusent l'impossible."""

    def _usecase(
        self, *, secret_cipher: AsymmetricSecretCipher | None
    ) -> tuple[RegistrationUseCase, AsymmetricSecretCipher | None]:
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=True,
            initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
        )
        return RegistrationUseCase(
            config, InMemoryClientRepository(), secret_cipher=secret_cipher
        ), secret_cipher

    @pytest.mark.parametrize("algorithm", SYMMETRIC_ALGORITHMS)
    def test_registers_hs_client_with_sealed_secret(self, algorithm: JWTAlgorithm) -> None:
        cipher, _ = _seal_ring()
        usecase, _ = self._usecase(secret_cipher=cipher)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "client_secret_basic",
                        "id_token_signed_response_alg": algorithm.value,
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.id_token_signed_response_alg == algorithm.value
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.client_secret_hash == hash_secret(result.client_secret)
        assert stored.client_secret_ciphertext
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == result.client_secret

    def test_rejects_hmac_with_keyless_auth_method(self) -> None:
        cipher, _ = _seal_ring()
        usecase, _ = self._usecase(secret_cipher=cipher)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "token_endpoint_auth_method": "none",
                        "id_token_signed_response_alg": "HS256",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "secret partagé" in result.error_description

    def test_rejects_hmac_without_seal_cipher(self) -> None:
        usecase, _ = self._usecase(secret_cipher=None)

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_signed_response_alg": "HS256",
                    },
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "chiffreur" in result.error_description

    def test_update_to_hmac_without_secret_rejected(self) -> None:
        cipher, _ = _seal_ring()
        usecase, _ = self._usecase(secret_cipher=cipher)
        registered = self._plain_client(usecase)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    client_id=registered.client_id,
                    registration_access_token=registered.registration_access_token,
                    metadata={
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "id_token_signed_response_alg": "HS256",
                    },
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "nouveau client_secret" in result.error_description

    def test_update_to_hmac_with_new_secret_seals_and_issues_it(self) -> None:
        cipher, _ = _seal_ring()
        usecase, _ = self._usecase(secret_cipher=cipher)
        registered = self._plain_client(usecase)
        new_secret = "nouveau-secret-client"

        result = run(
            usecase.update(
                UpdateClientRequest(
                    client_id=registered.client_id,
                    registration_access_token=registered.registration_access_token,
                    metadata={
                        "redirect_uris": ["https://app.example/callback"],
                        "scope": "openid",
                        "client_secret": new_secret,
                        "id_token_signed_response_alg": "HS512",
                    },
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.id_token_signed_response_alg == "HS512"
        assert result.client_secret == new_secret
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert stored.client_secret_hash == hash_secret(new_secret)
        assert run(cipher.decrypt(stored.client_secret_ciphertext)) == new_secret

    def _plain_client(self, usecase: RegistrationUseCase) -> ClientRegistration:
        """Enregistre un client confidentiel classique (secret non scellé, sans HS*)."""
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
