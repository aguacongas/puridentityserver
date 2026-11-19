"""Tests de la PKI d'emission des credentials SD-JWT (issue #304)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from puridentityserver.infrastructure.credential_pki import (
    FileCredentialPKIRepository,
    InMemoryCredentialPKIRepository,
    generate_credential_pki,
)


def test_generate_credential_pki_builds_root_and_leaf() -> None:
    pki = generate_credential_pki()
    root_constraints = pki.root_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    leaf_constraints = pki.leaf_certificate.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    assert root_constraints.ca is True
    assert leaf_constraints.ca is False
    # Le leaf n'est jamais auto-signe (exigence PKIX de la suite) : il est
    # emis par la racine, qui reste hors chaine x5c.
    assert pki.leaf_certificate.issuer == pki.root_certificate.subject
    assert pki.leaf_certificate.subject != pki.leaf_certificate.issuer
    assert pki.leaf_certificate.subject != pki.root_certificate.subject


def test_x5c_is_leaf_only_in_standard_base64() -> None:
    """Chaîne ``x5c`` : base64 standard avec padding (RFC 7515 §4.1.6)."""
    pki = generate_credential_pki()
    assert len(pki.x5c) == 1
    encoded = pki.x5c[0]
    assert encoded.endswith("=")
    certificate = x509.load_der_x509_certificate(base64.b64decode(encoded))
    assert certificate == pki.leaf_certificate
    assert certificate != pki.root_certificate


def test_kid_derives_from_leaf_subject_key_identifier() -> None:
    pki = generate_credential_pki()
    ski = pki.leaf_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert pki.kid == base64.urlsafe_b64encode(ski.digest).rstrip(b"=").decode("ascii")


def test_trust_anchor_pem_is_the_root() -> None:
    pki = generate_credential_pki()
    anchor = x509.load_pem_x509_certificate(pki.trust_anchor_pem.encode("ascii"))
    assert anchor == pki.root_certificate


def test_credential_signature_verifies_with_leaf() -> None:
    """La leaf RSA signe le credential ; la publique leaf le vérifie (RS256)."""
    pki = generate_credential_pki()
    signed = pyjwt.encode(
        {"sub": "alice"}, pki.leaf_private_key, algorithm="RS256", headers={"x5c": pki.x5c}
    )
    claims = pyjwt.decode(signed, key=pki.leaf_certificate.public_key(), algorithms=["RS256"])
    assert claims["sub"] == "alice"


def test_in_memory_repository_round_trip() -> None:
    repository = InMemoryCredentialPKIRepository()
    assert repository.load() is None
    pki = generate_credential_pki()
    repository.save(pki)
    loaded = repository.load()
    assert loaded is not None
    assert loaded.root_certificate == pki.root_certificate
    assert loaded.kid == pki.kid


def test_file_repository_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "credential-pki.json"
    repository = FileCredentialPKIRepository(path)
    assert repository.load() is None
    pki = generate_credential_pki()
    repository.save(pki)
    assert path.is_file()
    assert set(json.loads(path.read_text(encoding="utf-8"))) == {
        "root_key_pem",
        "root_cert_pem",
        "leaf_key_pem",
        "leaf_cert_pem",
    }
    loaded = repository.load()
    assert loaded is not None
    assert loaded.root_certificate == pki.root_certificate
    assert loaded.leaf_certificate == pki.leaf_certificate
    assert loaded.kid == pki.kid
    assert loaded.leaf_private_key.private_numbers().d == pki.leaf_private_key.private_numbers().d


def test_file_repository_malformed_falls_back_none(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert FileCredentialPKIRepository(path).load() is None


def test_file_repository_rejects_non_rsa_key(tmp_path: Path) -> None:
    path = tmp_path / "pki.json"
    pki = generate_credential_pki()
    repository = FileCredentialPKIRepository(path)
    repository.save(pki)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    data["leaf_key_pem"] = ec_pem.decode("ascii")
    path.write_text(json.dumps(data), encoding="utf-8")
    assert repository.load() is None
