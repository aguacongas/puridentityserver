"""Tests de la PKI du verifier OpenID4VP : generation, empreintes, persistance."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from puridentityserver.application.oid4vp import OID4VPVerifierUseCase
from puridentityserver.infrastructure.jwe import b64u
from puridentityserver.infrastructure.oid4vp_pki import (
    VERIFIER_CA_LIFETIME_DAYS,
    X509_HASH_CLIENT_ID_PREFIX,
    FileVerifierPKIRepository,
    InMemoryVerifierPKIRepository,
    generate_verifier_pki,
)

ISSUER = "https://id.example"


def test_generated_pki_shapes_client_id_and_chain() -> None:
    """client_id x509_hash, x5c leaf unique et ancre PEM hors chaine."""
    pki = generate_verifier_pki()

    assert pki.client_id.startswith(X509_HASH_CLIENT_ID_PREFIX)
    assert pki.client_id == f"{X509_HASH_CLIENT_ID_PREFIX}{pki.leaf_thumbprint}"
    assert len(pki.leaf_thumbprint) == 43

    der = pki.leaf_certificate.public_bytes(serialization.Encoding.DER)
    expected_thumbprint = b64u(hashlib.sha256(der).digest())
    assert pki.leaf_thumbprint == expected_thumbprint

    assert len(pki.x5c) == 1
    assert base64.b64decode(pki.x5c[0]) == der

    assert pki.trust_anchor_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert pki.trust_anchor_pem.endswith("-----END CERTIFICATE-----\n")
    assert pki.ca_certificate.subject == pki.leaf_certificate.issuer


def test_leaf_certificate_is_issued_by_ca() -> None:
    """Le leaf est signe par la CA et n'est pas une racine."""
    pki = generate_verifier_pki()
    ca_public = pki.ca_certificate.public_key()
    ca_public.verify(  # type: ignore[attr-defined]
        pki.leaf_certificate.signature,
        pki.leaf_certificate.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    leaf_constraints = pki.leaf_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    assert leaf_constraints.ca is False
    ca_constraints = pki.ca_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    assert ca_constraints.ca is True


def test_ca_is_self_signed_and_long_lived() -> None:
    """La CA est auto-signee sur duree de vie de harness."""
    now = datetime.now(timezone.utc)
    pki = generate_verifier_pki(now=now)
    ca_public = pki.ca_certificate.public_key()
    ca_public.verify(  # type: ignore[attr-defined]
        pki.ca_certificate.signature,
        pki.ca_certificate.tbs_certificate_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    assert pki.ca_certificate.subject == pki.ca_certificate.issuer
    lifetime = pki.ca_certificate.not_valid_after_utc - pki.ca_certificate.not_valid_before_utc
    assert lifetime.days >= VERIFIER_CA_LIFETIME_DAYS - 1


def test_common_name_is_truncated_to_x509_limit() -> None:
    """Le commonName du leaf est borne a 64 caracteres (RFC 5280)."""
    pki = generate_verifier_pki(common_name="N" * 120)
    attributes = pki.leaf_certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    assert len(str(attributes[0].value)) == 64


def test_in_memory_repository_roundtrip() -> None:
    """Le depot en memoire rend la PKI sauvegardee."""
    repository = InMemoryVerifierPKIRepository()
    assert repository.load() is None
    pki = generate_verifier_pki()
    repository.save(pki)
    loaded = repository.load()
    assert loaded is not None
    assert loaded.client_id == pki.client_id


def test_file_repository_missing_file_returns_none(tmp_path: Path) -> None:
    """Un fichier absent rend None (le use case regenere alors la PKI)."""
    repository = FileVerifierPKIRepository(tmp_path / "absent.json")
    assert repository.load() is None


def test_file_repository_roundtrip(tmp_path: Path) -> None:
    """Save puis load restitue la meme PKI (client_id stable)."""
    path = tmp_path / "nested" / "oid4vp-pki.json"
    repository = FileVerifierPKIRepository(path)
    pki = generate_verifier_pki()
    repository.save(pki)
    assert path.is_file()

    loaded = FileVerifierPKIRepository(path).load()
    assert loaded is not None
    assert loaded.client_id == pki.client_id
    assert loaded.x5c == pki.x5c
    assert loaded.trust_anchor_pem == pki.trust_anchor_pem


def test_file_repository_rejects_invalid_json(tmp_path: Path) -> None:
    """Un fichier illisible ou non objet rend None sans lever d'exception."""
    path = tmp_path / "oid4vp-pki.json"
    path.write_text("not json at all", encoding="utf-8")
    assert FileVerifierPKIRepository(path).load() is None

    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert FileVerifierPKIRepository(path).load() is None


def test_file_repository_rejects_missing_field(tmp_path: Path) -> None:
    """Un champ absent ou non textuel rend None (regeneration)."""
    path = tmp_path / "oid4vp-pki.json"
    pki = generate_verifier_pki()
    data = {
        "ca_key_pem": _pem_private(pki.ca_private_key),
        "ca_cert_pem": _pem_cert(pki.ca_certificate),
        "leaf_key_pem": _pem_private(pki.leaf_private_key),
        "leaf_cert_pem": 42,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    assert FileVerifierPKIRepository(path).load() is None

    data.pop("leaf_cert_pem")
    path.write_text(json.dumps(data), encoding="utf-8")
    assert FileVerifierPKIRepository(path).load() is None


def test_file_repository_rejects_non_ec_private_key(tmp_path: Path) -> None:
    """Une cle privee non EC dans le fichier rend None."""
    path = tmp_path / "oid4vp-pki.json"
    pki = generate_verifier_pki()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = {
        "ca_key_pem": _pem_private(pki.ca_private_key),
        "ca_cert_pem": _pem_cert(pki.ca_certificate),
        "leaf_key_pem": _pem_private(rsa_key),  # type: ignore[arg-type]
        "leaf_cert_pem": _pem_cert(pki.leaf_certificate),
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    assert FileVerifierPKIRepository(path).load() is None


def test_usecase_persists_pki_through_file_repository(tmp_path: Path) -> None:
    """Le use case genere la PKI une fois puis la recharge du fichier."""
    path = tmp_path / "oid4vp-pki.json"
    first = OID4VPVerifierUseCase(issuer=ISSUER, pki_repository=FileVerifierPKIRepository(path))
    created_one = first.create_presentation_request()
    assert path.is_file()

    second = OID4VPVerifierUseCase(issuer=ISSUER, pki_repository=FileVerifierPKIRepository(path))
    created_two = second.create_presentation_request()
    assert created_two.client_id == created_one.client_id


def _pem_private(key: object) -> str:
    """Serialise une cle privee en PEM PKCS#8 non chiffre."""
    raw = key.private_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.decode("ascii")


def _pem_cert(certificate: x509.Certificate) -> str:
    """Serialise un certificat au format PEM."""
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
