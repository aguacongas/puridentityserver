"""Tests du stockage persistant de la PKI mdoc."""

from __future__ import annotations

from pathlib import Path

from puridentityserver.infrastructure.mdoc import generate_mdoc_pki
from puridentityserver.infrastructure.mdoc_storage import (
    FileMdocPKIRepository,
    InMemoryMdocPKIRepository,
)


def test_in_memory_load_save_round_trip() -> None:
    repo = InMemoryMdocPKIRepository()
    assert repo.load() is None
    pki = generate_mdoc_pki("https://id.example")
    repo.save(pki)
    loaded = repo.load()
    assert loaded is not None
    assert loaded.issuer_certificate.subject == pki.issuer_certificate.subject
    assert loaded.signer_certificate.subject == pki.signer_certificate.subject


def test_file_absent_means_none(tmp_path: Path) -> None:
    repo = FileMdocPKIRepository(tmp_path / "pki.pem.json")  # json name arbitrary internally
    assert repo.load() is None


def test_file_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "mdoc_pki.json"
    repo = FileMdocPKIRepository(path)
    pki = generate_mdoc_pki("https://id.example")
    repo.save(pki)
    assert path.is_file()
    loaded = repo.load()
    assert loaded is not None
    assert (
        loaded.issuer_private_key.private_numbers().private_value
        == pki.issuer_private_key.private_numbers().private_value
    )
    assert (
        loaded.signer_private_key.private_numbers().private_value
        == pki.signer_private_key.private_numbers().private_value
    )


def test_file_malformed_falls_back_none(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    repo = FileMdocPKIRepository(path)
    assert repo.load() is None


def test_file_invalid_pem_falls_back_none(tmp_path: Path) -> None:
    path = tmp_path / "pki.json"
    import json

    path.write_text(json.dumps({"issuer_key_pem": "bad"}), encoding="utf-8")
    repo = FileMdocPKIRepository(path)
    assert repo.load() is None
