"""Tests de l'offre de credential OpenID4VCI (OID4VCI 1.0 §4.1.1, §4.1.2)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi.testclient import TestClient

from puridentityserver.application.oid4vci import (
    CREDENTIAL_CONFIGURATION_ID,
    CredentialError,
    CredentialOfferUseCase,
)
from puridentityserver.domain.authorization import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    AuthorizationCode,
    Scope,
)
from puridentityserver.domain.credential_offer import CredentialOffer
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_credential_offer_repository,
)
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.credential_offers import (
    InMemoryCredentialOfferRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.sql.credential_offers import (
    SQLCredentialOfferRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_ISSUER = "https://op.example"
_CLIENT_ID = "wallet-client"
_USER_SUBJECT = "user-1"

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


class _Harness:
    """Use case d'offre cable sur des repositories en mémoire."""

    def __init__(self) -> None:
        self.offers = InMemoryCredentialOfferRepository()
        self.codes = InMemoryAuthorizationCodeRepository()
        self.tokens = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        self.usecase = CredentialOfferUseCase(
            issuer=_ISSUER,
            offer_repository=self.offers,
            code_repository=self.codes,
            token_manager=self.tokens,
        )

    def token(
        self,
        *,
        subject: str = _USER_SUBJECT,
        client_id: str = _CLIENT_ID,
        scopes: frozenset[Scope] = frozenset({Scope.OID4VCI}),
    ) -> str:
        """Émet un access token pour le porteur voulu."""
        now = int(time.time())
        return run(
            self.tokens.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject=subject,
                audience=client_id,
                expires_at=now + 300,
                issued_at=now,
                scopes=scopes,
                additional_claims={"client_id": client_id},
            )
        )

    def machine_token(self, *, client_id: str = _CLIENT_ID) -> str:
        """Émet un jeton ``client_credentials`` (``sub`` égal au client)."""
        return self.token(subject=client_id, client_id=client_id)


def test_create_offer_for_user_token() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.token()))

    assert not isinstance(result, CredentialError)
    offer = result["credential_offer"]
    assert offer["credential_issuer"] == _ISSUER
    assert offer["credential_configuration_ids"] == [CREDENTIAL_CONFIGURATION_ID]
    grant = offer["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]
    assert grant["pre-authorized_code"]
    assert grant["authorization_server"] == _ISSUER
    assert "tx_code" not in grant
    assert "tx_code" not in result
    assert result["credential_offer_uri"].startswith(f"{_ISSUER}/credential-offer/")


def test_create_offer_with_transaction_code() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.token(), tx_code=True))

    assert not isinstance(result, CredentialError)
    tx_code = result["tx_code"]
    assert isinstance(tx_code, str)
    assert len(tx_code) == 6
    assert tx_code.isdigit()
    grant = result["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]
    assert grant["tx_code"]["input_mode"] == "numeric"
    assert grant["tx_code"]["length"] == 6
    code = run(harness.codes.find_by_code(grant["pre-authorized_code"]))
    assert code is not None
    assert code.tx_code_hash
    assert code.pre_authorized


def test_offer_is_redeemable_by_pre_authorized_grant() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.token()))
    assert not isinstance(result, CredentialError)
    grant = result["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]

    code = run(harness.codes.find_by_code(grant["pre-authorized_code"]))

    assert code is not None
    assert code.subject == _USER_SUBJECT
    assert code.scopes == frozenset({Scope.OID4VCI})
    assert code.client_id == ""


def test_machine_token_requires_subject() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.machine_token()))

    assert isinstance(result, CredentialError)
    assert result.error == "invalid_request"
    assert result.status_code == 400


def test_machine_token_may_designate_another_subject() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.machine_token(), subject="alice"))

    assert not isinstance(result, CredentialError)
    code = run(
        harness.codes.find_by_code(
            result["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE][
                "pre-authorized_code"
            ]
        )
    )
    assert code is not None
    assert code.subject == "alice"


def test_user_token_cannot_designate_another_subject() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.token(), subject="alice"))

    assert isinstance(result, CredentialError)
    assert result.error == "invalid_request"
    assert result.status_code == 403


def test_missing_scope_is_refused() -> None:
    harness = _Harness()

    result = run(harness.usecase.create(harness.token(scopes=frozenset({Scope.OPENID}))))

    assert isinstance(result, CredentialError)
    assert result.error == "insufficient_scope"
    assert result.status_code == 403


def test_invalid_token_is_refused() -> None:
    harness = _Harness()

    result = run(harness.usecase.create("not-a-token"))

    assert isinstance(result, CredentialError)
    assert result.error == "invalid_token"
    assert result.status_code == 401


def test_unknown_configuration_is_refused() -> None:
    harness = _Harness()

    result = run(
        harness.usecase.create(
            harness.token(), credential_configuration_ids=["other-configuration"]
        )
    )

    assert isinstance(result, CredentialError)
    assert result.error == "unknown_credential_configuration"


def test_resolve_returns_offer() -> None:
    harness = _Harness()

    created = run(harness.usecase.create(harness.token()))
    assert not isinstance(created, CredentialError)
    offer_id = created["credential_offer_uri"].rsplit("/", 1)[-1]

    resolved = run(harness.usecase.resolve(offer_id))

    assert resolved == created["credential_offer"]


def test_resolve_unknown_offer() -> None:
    harness = _Harness()

    result = run(harness.usecase.resolve("absent"))

    assert isinstance(result, CredentialError)
    assert result.status_code == 404


def test_resolve_consumed_offer_is_gone() -> None:
    harness = _Harness()
    created = run(harness.usecase.create(harness.token()))
    assert not isinstance(created, CredentialError)
    grant = created["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]
    run(harness.codes.consume(grant["pre-authorized_code"]))

    result = run(harness.usecase.resolve(created["credential_offer_uri"].rsplit("/", 1)[-1]))

    assert isinstance(result, CredentialError)
    assert result.status_code == 404


def test_resolve_expired_offer_is_gone() -> None:
    harness = _Harness()
    now = datetime.now(timezone.utc)
    offer = CredentialOffer(
        offer_id="expired",
        credential_configuration_ids=(CREDENTIAL_CONFIGURATION_ID,),
        subject=_USER_SUBJECT,
        pre_authorized_code="code",
        created_at=now - timedelta(hours=1),
        expires_at=now - timedelta(minutes=1),
    )
    run(harness.offers.save(offer))

    result = run(harness.usecase.resolve("expired"))

    assert isinstance(result, CredentialError)
    assert result.status_code == 404


def test_resolve_offer_without_code_is_gone() -> None:
    harness = _Harness()
    now = datetime.now(timezone.utc)
    offer = CredentialOffer(
        offer_id="orphan",
        credential_configuration_ids=(CREDENTIAL_CONFIGURATION_ID,),
        subject=_USER_SUBJECT,
        pre_authorized_code="missing",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    run(harness.offers.save(offer))

    result = run(harness.usecase.resolve("orphan"))

    assert isinstance(result, CredentialError)
    assert result.status_code == 404


def test_offer_route_requires_token() -> None:
    client = TestClient(create_app(settings=Settings(oid4vci_enabled=True)))

    response = client.post("/credential-offer", json={})

    assert response.status_code == 401


def test_offer_route_serves_unknown_offer_with_no_store() -> None:
    client = TestClient(create_app(settings=Settings(oid4vci_enabled=True)))

    response = client.get("/credential-offer/absent")

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_memory_repository_delete_is_idempotent() -> None:
    repo = InMemoryCredentialOfferRepository()

    run(repo.delete("absent"))

    assert run(repo.find_by_id("absent")) is None


def test_memory_repository_round_trip() -> None:
    repo = InMemoryCredentialOfferRepository()
    now = datetime.now(timezone.utc)
    offer = CredentialOffer(
        offer_id="offer-1",
        credential_configuration_ids=(CREDENTIAL_CONFIGURATION_ID,),
        subject=_USER_SUBJECT,
        pre_authorized_code="code-1",
        tx_code_required=True,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    run(repo.save(offer))

    assert run(repo.find_by_id("offer-1")) == offer


async def _sql_repo(tmp_path: Path) -> SQLCredentialOfferRepository:
    repo = SQLCredentialOfferRepository(f"sqlite+aiosqlite:///{tmp_path / 'offers.db'}")
    await repo.initialise()
    return repo


def test_sql_repository_round_trip(tmp_path: Path) -> None:
    repo = run(_sql_repo(tmp_path))
    now = datetime.now(timezone.utc)
    offer = CredentialOffer(
        offer_id="offer-sql",
        credential_configuration_ids=(CREDENTIAL_CONFIGURATION_ID,),
        subject=_USER_SUBJECT,
        pre_authorized_code="code-sql",
        client_id=_CLIENT_ID,
        tx_code_required=True,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    run(repo.save(offer))
    stored = run(repo.find_by_id("offer-sql"))
    run(repo.delete("offer-sql"))
    deleted = run(repo.find_by_id("offer-sql"))
    run(repo.close())

    assert stored is not None
    assert stored.subject == _USER_SUBJECT
    assert stored.credential_configuration_ids == (CREDENTIAL_CONFIGURATION_ID,)
    assert stored.pre_authorized_code == "code-sql"
    assert stored.tx_code_required is True
    assert deleted is None


def test_sql_repository_delete_absent_is_noop(tmp_path: Path) -> None:
    repo = run(_sql_repo(tmp_path))

    run(repo.delete("absent"))
    existing = run(repo.find_by_id("absent"))
    run(repo.close())

    assert existing is None


def test_factory_builds_memory_repository() -> None:
    repository = build_credential_offer_repository(Settings(storage_type="memory"))

    assert isinstance(repository, InMemoryCredentialOfferRepository)


def test_factory_builds_sql_repository() -> None:
    repository = build_credential_offer_repository(
        Settings(storage_type="sql", storage_dsn="sqlite:///memory")
    )

    assert isinstance(repository, SQLCredentialOfferRepository)


def test_factory_rejects_unknown_store_type() -> None:
    settings = Settings.model_construct(storage_type="cassandra")

    with pytest.raises(ValueError, match="non supporté"):
        build_credential_offer_repository(settings)


def test_sql_code_row_carries_pre_authorized_columns() -> None:
    from puridentityserver.infrastructure.persistence.sql.codes import (
        AuthorizationCodeRow,
        _from_row,
        _to_row,
    )

    code = AuthorizationCode(
        code="code",
        client_id="",
        subject=_USER_SUBJECT,
        pre_authorized=True,
        tx_code_hash="hash",
    )
    row = _to_row(code)

    assert isinstance(row, AuthorizationCodeRow)
    assert row.pre_authorized is True
    assert row.tx_code_hash == "hash"
    assert _from_row(row).pre_authorized is True
    assert _from_row(row).tx_code_hash == "hash"
