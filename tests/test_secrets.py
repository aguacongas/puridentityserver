"""Tests du chiffrement au repos des secrets clients (clé de scellement rotative, #46).

Couvre ``AsymmetricSecretCipher`` (RSA-OAEP sur le store ``key_pair``) :
scellement sous la clé la plus récente, déchiffrement par ``kid`` avec
repli sur les clés encore présentes (rotation automatique de
``KeyUse.SECRET``), taux ``is_current`` / ``reencrypt`` pour le drain, et
seed d'une clé privée pour les serveurs en mémoire.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import pytest

from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.secrets import AsymmetricSecretCipher, load_seal_key_pair

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _ring() -> tuple[DefaultKeyManager, InMemoryKeyPairRepository]:
    """Gestionnaire de la famille ``KeyUse.SECRET`` sur un store en mémoire."""
    repository = InMemoryKeyPairRepository()
    return DefaultKeyManager(repository, use=KeyUse.SECRET), repository


def _cipher(manager: DefaultKeyManager) -> AsymmetricSecretCipher:
    """Chiffreur de scellement scopé sur ``manager``."""
    return AsymmetricSecretCipher(manager)


def _new_seal_pair(manager: DefaultKeyManager) -> None:
    """Génère une clé de scellement active."""
    run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))


def test_encrypt_uses_newest_key_and_decrypts() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    cipher = _cipher(manager)
    token = run(cipher.encrypt("s3cret"))
    assert run(cipher.decrypt(token)) == "s3cret"
    assert run(cipher.is_current(token))


def test_decrypt_resolves_kid_across_rotated_keys() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    cipher = _cipher(manager)
    token = run(cipher.encrypt("pour-le-drain"))
    # rotation : une clé plus récente est ajoutée, l'ancienne reste portée
    _new_seal_pair(manager)
    rotated = _cipher(manager)
    assert run(rotated.decrypt(token)) == "pour-le-drain"
    assert not run(rotated.is_current(token))


def test_decrypt_fails_after_key_removed() -> None:
    manager, repository = _ring()
    _new_seal_pair(manager)
    cipher = _cipher(manager)
    token = run(cipher.encrypt("orphelin"))
    run(manager.generate_key_pair(2048, JWTAlgorithm.RS256))
    # drain terminé : la clé du jeton est retirée du store, une autre reste
    run(repository.delete(token.split(":", 1)[0]))
    awaitable = cipher.decrypt(token)
    with pytest.raises(ValueError, match="secret client indéchiffrable"):
        asyncio.run(awaitable)


def test_legacy_token_without_prefix_still_decrypts() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    token = run(_cipher(manager).encrypt("ancien-format"))
    # un token sans préfixe (sinon format) reste déchiffrable par repli
    bare = token.split(":", 1)[1]
    assert run(_cipher(manager).decrypt(bare)) == "ancien-format"


def test_reencrypt_drains_to_newest_key() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    token = run(_cipher(manager).encrypt("legacy"))
    _new_seal_pair(manager)
    cipher = _cipher(manager)
    rewrapped = run(cipher.reencrypt(token))
    assert run(cipher.is_current(rewrapped))
    assert run(cipher.decrypt(rewrapped)) == "legacy"


def test_reencrypt_is_identity_when_already_current() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    cipher = _cipher(manager)
    token = run(cipher.encrypt("stable"))
    assert run(cipher.reencrypt(token)) == token


def test_missing_seal_key_raises() -> None:
    manager, _ = _ring()
    cipher = _cipher(manager)
    awaitable = cipher.encrypt("valeur")
    with pytest.raises(ValueError, match="aucune clé de scellement"):
        asyncio.run(awaitable)


def test_rotate_if_stale_generates_when_old() -> None:
    manager, repository = _ring()
    _new_seal_pair(manager)
    key = run(manager.get_active_keys())[0]
    old = replace(key, created_at=datetime.now(timezone.utc) - timedelta(days=400))
    run(repository.save(old))
    cipher = _cipher(manager)
    assert run(cipher.rotate_if_stale(rotation_days=90)) is True
    assert len(run(manager.get_active_keys())) == 2
    # la nouvelle clé est la plus récente : elle scelle les nouveaux secrets
    assert run(cipher.is_current(run(cipher.encrypt("neuf"))))


def test_rotate_if_stale_is_noop_when_fresh() -> None:
    manager, _repository = _ring()
    _new_seal_pair(manager)
    assert run(_cipher(manager).rotate_if_stale(rotation_days=90)) is False


def test_rotate_if_stale_generates_on_empty_store() -> None:
    manager, _repository = _ring()
    assert run(_cipher(manager).rotate_if_stale()) is True


def test_seed_key_pair_roundtrip_and_stable_kid() -> None:
    manager, repository = _ring()
    run(manager.ensure_active_key(2048, JWTAlgorithm.RS256))
    seed_key = run(manager.get_active_keys())[0]
    seeded = load_seal_key_pair(seed_key.private_key_pem)
    assert seeded.kid == load_seal_key_pair(seed_key.private_key_pem).kid
    assert seeded.use is KeyUse.SECRET
    run(repository.save(seeded))
    cipher = _cipher(manager)
    assert run(cipher.decrypt(run(cipher.encrypt("via-seed")))) == "via-seed"
