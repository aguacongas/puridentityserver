"""Tests du stockage persistant de l'IACA mdoc."""

from __future__ import annotations

import json
from pathlib import Path

from puridentityserver.infrastructure.mdoc import generate_mdoc_iaca, generate_mdoc_pki
from puridentityserver.infrastructure.mdoc_storage import (
    FileMdocPKIRepository,
    InMemoryMdocPKIRepository,
)


def test_in_memory_load_save_round_trip() -> None:
    repo = InMemoryMdocPKIRepository()
    assert repo.load() is None
    iaca = generate_mdoc_iaca("https://id.example")
    repo.save(iaca)
    loaded = repo.load()
    assert loaded is not None
    assert loaded.certificate.subject == iaca.certificate.subject
    assert (
        loaded.private_key.private_numbers().private_value
        == iaca.private_key.private_numbers().private_value
    )


def test_file_absent_means_none(tmp_path: Path) -> None:
    repo = FileMdocPKIRepository(tmp_path / "pki.pem.json")  # json name arbitrary internally
    assert repo.load() is None


def test_file_round_trip_persists_iaca_only(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "mdoc_pki.json"
    repo = FileMdocPKIRepository(path)
    iaca = generate_mdoc_iaca("https://id.example")
    repo.save(iaca)
    assert path.is_file()
    # Le dépôt ne conserve que l'IACA : le document signer est minté au boot.
    assert set(json.loads(path.read_text(encoding="utf-8"))) == {
        "issuer_key_pem",
        "issuer_cert_pem",
    }
    loaded = repo.load()
    assert loaded is not None
    assert (
        loaded.private_key.private_numbers().private_value
        == iaca.private_key.private_numbers().private_value
    )
    assert loaded.certificate == iaca.certificate


def test_file_loads_legacy_four_field_depot(tmp_path: Path) -> None:
    """Un ancien dépôt 4 champs (IACA + document signer) reste chargeable.

    Seuls les deux champs d'IACA sont lus ; le document signer y est
    ignoré et reminté au démarrage avec le contact de l'émetteur courant.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding

    def _pem_private(key: object) -> str:
        raw = key.private_bytes(  # type: ignore[attr-defined]
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return bytes(raw).decode("ascii")

    def _pem_cert(certificate: object) -> str:
        return bytes(certificate.public_bytes(Encoding.PEM)).decode("ascii")  # type: ignore[attr-defined]

    path = tmp_path / "legacy.json"
    pki = generate_mdoc_pki("https://op.example.com")
    path.write_text(
        json.dumps(
            {
                "issuer_key_pem": _pem_private(pki.issuer_private_key),
                "issuer_cert_pem": _pem_cert(pki.issuer_certificate),
                "signer_key_pem": _pem_private(pki.signer_private_key),
                "signer_cert_pem": _pem_cert(pki.signer_certificate),
            }
        ),
        encoding="utf-8",
    )
    repo = FileMdocPKIRepository(path)
    loaded = repo.load()
    assert loaded is not None
    assert loaded.certificate == pki.issuer_certificate
    assert (
        loaded.private_key.private_numbers().private_value
        == pki.issuer_private_key.private_numbers().private_value
    )


def test_file_malformed_falls_back_none(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    repo = FileMdocPKIRepository(path)
    assert repo.load() is None


def test_file_invalid_pem_falls_back_none(tmp_path: Path) -> None:
    path = tmp_path / "pki.json"
    path.write_text(json.dumps({"issuer_key_pem": "bad"}), encoding="utf-8")
    repo = FileMdocPKIRepository(path)
    assert repo.load() is None
