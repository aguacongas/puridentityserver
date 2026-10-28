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
