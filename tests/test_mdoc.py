"""Tests du module mdoc ISO 18013-5 (format ``mso_mdoc``)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cose.messages import Sign1Message
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from puridentityserver.infrastructure.mdoc import (
    PERSONAL_NAME_NAMESPACE,
    MdocBindingError,
    _capped_common_name,
    _issuer_common_name,
    _private_cose_key,
    generate_mdoc_pki,
)


def _device_jwk() -> dict[str, str]:
    """Génère un JWK EC P-256 public de test."""
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()

    def _b64(value: int) -> str:
        raw = value.to_bytes(32, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {"kty": "EC", "crv": "P-256", "x": _b64(numbers.x), "y": _b64(numbers.y)}


def test_generate_mdoc_pki_builds_iaca_and_signer() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    # L'IACA est une autorité ; le document signer non.
    issuer_ext = pki.issuer_certificate.extensions
    signer_ext = pki.signer_certificate.extensions
    assert any(isinstance(ext.value, x509.BasicConstraints) and ext.value.ca for ext in issuer_ext)
    assert any(
        isinstance(ext.value, x509.BasicConstraints) and not ext.value.ca for ext in signer_ext
    )
    # Le signer est émis par l'IACA (issuer = sujet de l'IACA).
    assert pki.signer_certificate.issuer == pki.issuer_certificate.subject


def test_generate_mdoc_pki_caps_common_names_at_x509_limit() -> None:
    """Les CN restent sous la limite X.509 (64) pour un issuer long.

    Régression issue #295 : l'URL publique de l'instance hébergée
    dépassait la limite et la metadata signée OID4VCI renvoyait un 500.
    """
    issuer = "https://puridentity-op-cert.duckdns.org"
    pki = generate_mdoc_pki(issuer)

    iaca_names = pki.issuer_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    signer_names = pki.signer_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert len(iaca_names) == 1
    assert len(signer_names) == 1
    iaca_common_name = iaca_names[0].value
    signer_common_name = signer_names[0].value
    assert iaca_common_name == f"{issuer} IACA"
    assert signer_common_name.endswith(" document signer")
    assert len(iaca_common_name) <= 64
    assert len(signer_common_name) <= 64

    # Issuer si long que le CN de l'IACA atteint la limite : la troncature
    # conserve le suffixe du document signer.
    long_issuer = "https://example.com/tenant/" + "a" * 120
    long_pki = generate_mdoc_pki(long_issuer)
    long_iaca_names = long_pki.issuer_certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )
    long_signer_names = long_pki.signer_certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )
    assert len(long_iaca_names) == 1
    assert len(long_signer_names) == 1
    assert long_iaca_names[0].value.endswith(" IACA")
    assert long_signer_names[0].value.endswith(" document signer")
    assert len(long_iaca_names[0].value) <= 64
    assert len(long_signer_names[0].value) <= 64


def test_capped_common_name_keeps_suffix_under_x509_limit() -> None:
    """La base est tronquée pour conserver le suffixe sous la limite (64)."""
    common_name = _capped_common_name("a" * 100, " IACA")
    assert common_name == "a" * 59 + " IACA"
    assert len(common_name) == 64
    # Suffixe lui-même au-delà de la limite : on ne garde que le suffixe tronqué.
    assert _capped_common_name("base", "s" * 70) == "s" * 64


def test_issuer_common_name_falls_back_to_rfc4514_subject() -> None:
    """Sans ``commonName`` dans le sujet, on retombe sur le sujet RFC 4514."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    assert _issuer_common_name(certificate) == name.rfc4514_string()


def test_issue_produces_verifiable_issuer_signed() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(device_jwk=_device_jwk(), claims={"given_name": "Alice"})

    outer = cbor2.loads(blob)
    assert set(outer) == {"issuerAuth", "nameSpaces"}
    items = outer["nameSpaces"][PERSONAL_NAME_NAMESPACE]
    assert len(items) == 1
    item = cbor2.loads(items[0].value)
    assert item[2] == "given_name"
    assert item[3] == "Alice"

    # issuerAuth : COSE Sign1 (tag 18), signature vérifiable, x5chain de deux.
    auth = outer["issuerAuth"]
    assert auth.tag == 18
    message = Sign1Message.from_cose_obj(list(auth.value), True)
    message.key = _private_cose_key(pki.signer_private_key)
    assert message.verify_signature() is True
    protected = cbor2.loads(message.phdr_encoded)
    assert protected[1] == -7
    assert len(protected[33]) == 2


def test_issue_embeds_device_key_and_validity() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(device_jwk=_device_jwk(), claims={"given_name": "Alice"})
    outer = cbor2.loads(blob)
    message = Sign1Message.from_cose_obj(list(outer["issuerAuth"].value), True)
    message.key = _private_cose_key(pki.signer_private_key)
    mso = cbor2.loads(message.payload)

    device_key = mso["deviceKeyInfo"]["deviceKey"]
    assert device_key[1] == 2  # kty: EC2
    assert device_key[3] == -7  # alg: ES256
    assert device_key[-1] == 1  # crv: P-256
    assert mso["digestAlgorithm"] == "-7"
    assert mso["version"] == "1.0"
    assert "signed" in mso["validityInfo"]
    assert "validUntil" in mso["validityInfo"]


def test_issue_covers_each_claim_with_digest() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(device_jwk=_device_jwk(), claims={"given_name": "Alice", "age": 42})
    outer = cbor2.loads(blob)
    digests = {
        k: list(v)
        for k, v in cbor2.loads(
            Sign1Message.from_cose_obj(list(outer["issuerAuth"].value), True).payload
        )["valueDigests"].items()
    }
    assert digests == {PERSONAL_NAME_NAMESPACE: ["given_name", "age"]}


def test_issue_rejects_non_ec_binding_key() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    with pytest.raises(MdocBindingError, match="non EC"):
        pki.issue(device_jwk={"kty": "RSA"}, claims={"given_name": "Alice"})


def test_issue_rejects_non_p256_curve() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    jwk = _device_jwk()
    jwk["crv"] = "P-384"
    with pytest.raises(MdocBindingError, match="P-256"):
        pki.issue(device_jwk=jwk, claims={"given_name": "Alice"})


def test_issue_rejects_missing_coordinates() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    with pytest.raises(MdocBindingError, match="coordonnees"):
        pki.issue(device_jwk={"kty": "EC", "crv": "P-256"}, claims={"given_name": "Alice"})


def test_signer_certificate_der_round_trip() -> None:
    """La chaîne x5chain doit être rechargeable en DER par un verifier."""
    pki = generate_mdoc_pki("https://op.example.com")
    signer_der = pki.signer_certificate.public_bytes(Encoding.DER)
    loaded = x509.load_der_x509_certificate(signer_der)
    assert loaded.subject == pki.signer_certificate.subject
