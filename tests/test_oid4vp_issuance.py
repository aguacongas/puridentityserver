"""Tests du slice d'issuance OpenID4VP (sous-issue #223)."""

from __future__ import annotations

import asyncio

from puridentityserver.application.oid4vp import OID4VPVerifierUseCase
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository


def test_presentation_request_signed() -> None:
    async def _task() -> None:
        key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
        await key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        usecase = OID4VPVerifierUseCase(
            issuer="https://id.example",
            key_manager=key_manager,
            algorithm=JWTAlgorithm.RS256,
        )
        result = await usecase.create_presentation_request(None, "direct_post")
        assert "request" in result
        assert "nonce" in result
        assert result["response_mode"] == "direct_post"

    asyncio.run(_task())


def _signed_vp_token(issuer: str, nonce: str) -> str:
    """Construit un vp_token signe a la cle RSA avec JWK embarque."""
    import time

    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    jwk["alg"] = "RS256"
    now = int(time.time())
    token = pyjwt.encode(
        {"iss": "did:example:holder", "aud": issuer, "nonce": nonce, "iat": now, "exp": now + 300},
        private_key,
        algorithm="RS256",
        headers={"typ": "JWT", "alg": "RS256", "jwk": jwk},
    )
    return token


def test_validate_presentation_response() -> None:
    async def _task() -> None:
        key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
        await key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        usecase = OID4VPVerifierUseCase(
            issuer="https://id.example",
            key_manager=key_manager,
            algorithm=JWTAlgorithm.RS256,
        )
        created = await usecase.create_presentation_request(None, "direct_post")
        nonce = created["nonce"]

        vp_token = _signed_vp_token("https://id.example", nonce)
        assert usecase.validate_presentation_response(vp_token) == {"status": "received"}
        # nonce consomme.
        assert usecase.validate_presentation_response(vp_token) == "invalid_presentation"

        bad_token = _signed_vp_token("https://id.example", "nope")
        assert usecase.validate_presentation_response(bad_token) == "invalid_presentation"

        assert usecase.validate_presentation_response(None) == "invalid_request"
        assert usecase.validate_presentation_response(["", "x"]) == "invalid_request"
        # Signature invalide : token forge, jwk ne correspond pas.
        forged = _signed_vp_token("https://id.example", nonce)
        tampered = forged[:-4] + "AAAA"
        assert usecase.validate_presentation_response(tampered) == "invalid_presentation"

    asyncio.run(_task())


def test_presentation_request_with_definition() -> None:
    async def _task() -> None:
        key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
        await key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        usecase = OID4VPVerifierUseCase(
            issuer="https://id.example",
            key_manager=key_manager,
            algorithm=JWTAlgorithm.RS256,
        )
        result = await usecase.create_presentation_request({"id": "x"}, "direct_post")
        assert "request" in result
        assert usecase.validate_presentation_response("not-a-jwt") == "invalid_presentation"

    asyncio.run(_task())
