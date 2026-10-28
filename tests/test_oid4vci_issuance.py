"""Tests pour le slice d'issuance OpenID4VCI (subset #222)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from puridentityserver.application.oid4vci import OID4VCIIssuerUseCase
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.tokens import PyJWTTokenManager


def _token_manager() -> PyJWTTokenManager:
    return PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))


def test_issuer_issues_sdjwt_credential_for_valid_access_token() -> None:
    issuer = "https://id.example"
    token_manager = _token_manager()
    now = int(datetime.now(timezone.utc).timestamp())

    async def _task() -> None:
        await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        token = await token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=issuer,
            subject="alice",
            audience="wallet-client",
            expires_at=now + 600,
            issued_at=now,
            scopes=frozenset(),
        )
        usecase = OID4VCIIssuerUseCase(
            issuer=issuer,
            key_manager=token_manager._key_manager,
            algorithm=JWTAlgorithm.RS256,
            token_manager=token_manager,
        )
        result = await usecase.issue_credential(token, "vc+sd-jwt")
        assert result is not None
        assert result["credentials"]
        credential = result["credentials"][0]["credential"]
        assert isinstance(credential, str)
        assert credential.count(".") == 2
        assert "c_nonce" in result

    asyncio.run(_task())


def test_issuer_rejects_invalid_access_token() -> None:
    issuer = "https://id.example"
    token_manager = _token_manager()
    usecase = OID4VCIIssuerUseCase(
        issuer=issuer,
        key_manager=token_manager._key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=token_manager,
    )

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        result = await usecase.issue_credential("not-a-valid-jwt", "vc+sd-jwt")
        assert result is None

    asyncio.run(_task())


def test_issuer_rejects_invalid_proof() -> None:
    issuer = "https://id.example"
    token_manager = _token_manager()
    now = int(datetime.now(timezone.utc).timestamp())

    async def _task() -> None:
        await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        token = await token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=issuer,
            subject="alice",
            audience="wallet-client",
            expires_at=now + 600,
            issued_at=now,
            scopes=frozenset(),
        )
        usecase = OID4VCIIssuerUseCase(
            issuer=issuer,
            key_manager=token_manager._key_manager,
            algorithm=JWTAlgorithm.RS256,
            token_manager=token_manager,
        )
        result = await usecase.issue_credential(token, "vc+sd-jwt", "not-a-jwt")
        assert result is None

    asyncio.run(_task())


def test_issuer_issues_credential_with_proof_binding() -> None:
    issuer = "https://id.example"
    token_manager = _token_manager()
    now = int(datetime.now(timezone.utc).timestamp())

    async def _task() -> None:
        await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        token = await token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=issuer,
            subject="alice",
            audience="wallet-client",
            expires_at=now + 600,
            issued_at=now,
            scopes=frozenset(),
        )
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
        jwk["alg"] = "RS256"
        proof = pyjwt.encode(
            {"aud": issuer, "iat": now, "exp": now + 300, "nonce": "n"},
            private_key,
            algorithm="RS256",
            headers={"typ": "openid4vci-proof+jwt", "jwk": jwk},
        )
        usecase = OID4VCIIssuerUseCase(
            issuer=issuer,
            key_manager=token_manager._key_manager,
            algorithm=JWTAlgorithm.RS256,
            token_manager=token_manager,
        )
        result = await usecase.issue_credential(token, "vc+sd-jwt", proof)
        assert result is not None
        credential = result["credentials"][0]["credential"]
        assert isinstance(credential, str)
        assert credential.count(".") == 2
        assert "c_nonce" in result

    asyncio.run(_task())
