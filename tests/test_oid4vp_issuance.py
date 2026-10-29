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


def test_validate_presentation_response() -> None:
    import jwt as pyjwt

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

        vp_token = pyjwt.encode({"nonce": nonce}, "secret", algorithm="HS256")
        assert usecase.validate_presentation_response(vp_token) == {"status": "received"}
        # nonce consomme.
        assert usecase.validate_presentation_response(vp_token) == "invalid_presentation"

        bad_token = pyjwt.encode({"nonce": "nope"}, "secret", algorithm="HS256")
        assert usecase.validate_presentation_response(bad_token) == "invalid_presentation"

        assert usecase.validate_presentation_response(None) == "invalid_request"
        assert usecase.validate_presentation_response(["", "x"]) == "invalid_request"

    asyncio.run(_task())
