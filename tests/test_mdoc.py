"""Tests du module mdoc ISO 18013-5 (format ``mso_mdoc``)."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cose.headers import X5chain
from cose.messages import Sign1Message
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID

from puridentityserver.application.oid4vci import MDOC_DOCTYPE
from puridentityserver.infrastructure.mdoc import (
    MDOC_ISSUING_COUNTRY,
    MDOC_SIGNER_LIFETIME_DAYS,
    PERSONAL_NAME_NAMESPACE,
    MDoc_LIFETIME_DAYS,
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


def test_document_signer_certificate_obeys_iso_18013_table_b3() -> None:
    """Profil ISO 18013-5 Table B.3 du certificat document signer.

    Régression issue #255 : la suite de conformance OIDF classe ces
    écarts en WARNING inattendu, ce qui fait échouer le plan
    ``oid4vci-mdoc`` même sans aucun module FAILED.
    """
    issuer = "https://op.example.com"
    generated = datetime(2026, 1, 1, tzinfo=timezone.utc)
    pki = generate_mdoc_pki(issuer, generated)
    ds = pki.signer_certificate
    iaca = pki.issuer_certificate
    critical = {ext.oid for ext in ds.extensions if ext.critical}

    # countryName obligatoire (PrintableString, [A-Z]{2}) et aligné sur
    # l'élément issuing_country émis.
    countries = ds.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    assert [attribute.value for attribute in countries] == [MDOC_ISSUING_COUNTRY]
    # Seuls keyUsage et extendedKeyUsage peuvent être critiques.
    assert critical == {ExtensionOID.KEY_USAGE, ExtensionOID.EXTENDED_KEY_USAGE}

    key_usage = ds.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature
    assert not any(
        (
            key_usage.content_commitment,
            key_usage.key_encipherment,
            key_usage.data_encipherment,
            key_usage.key_agreement,
            key_usage.key_cert_sign,
            key_usage.crl_sign,
        )
    )
    eku = ds.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert [oid.dotted_string for oid in eku] == ["1.0.18013.5.1.2"]

    # SKI présent, AKI identique au SKI de l'IACA émettrice.
    iaca_ski = iaca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = ds.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == iaca_ski.digest

    # Contact de l'émetteur et CRL en URI (la suite exige la présence d'une
    # distribution point URI sans raison ni cRLIssuer, sans la télécharger).
    ian = ds.extensions.get_extension_for_class(x509.IssuerAlternativeName).value
    assert [name.value for name in ian] == [issuer]
    points = ds.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert len(points) == 1
    point = points[0]
    assert point.full_name is not None
    assert [name.value for name in point.full_name] == [f"{issuer}/crl/mdoc.crl"]
    assert point.reasons is None and point.crl_issuer is None

    # basicConstraints ca=False, non critique (Table B.3 n'autorise que
    # keyUsage et extendedKeyUsage en extension critique).
    constraints = ds.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is False
    assert ExtensionOID.BASIC_CONSTRAINTS not in critical

    # Validité : plafond Table B.3 (457 j) respectée, et couverture du
    # validUntil du MSO émis à MDoc_LIFETIME_DAYS (ISO 18013-5 §9.3.1).
    validity = ds.not_valid_after_utc - ds.not_valid_before_utc
    assert validity <= timedelta(days=457)
    assert MDOC_SIGNER_LIFETIME_DAYS < 457
    assert generated + timedelta(days=MDoc_LIFETIME_DAYS) < ds.not_valid_after_utc

    # Le SKI est le SHA-1 du BIT STRING de la clé publique (RFC 5280 §4.2.1.2).
    ski = ds.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    spki = ds.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert ski.digest == hashlib.sha1(spki[-65:]).digest()


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
    blob = pki.issue(
        device_jwk=_device_jwk(), claims={"given_name": "Alice"}, doc_type=MDOC_DOCTYPE
    )

    outer = cbor2.loads(blob)
    assert set(outer) == {"issuerAuth", "nameSpaces"}
    items = outer["nameSpaces"][PERSONAL_NAME_NAMESPACE]
    assert len(items) == 1
    item = cbor2.loads(items[0].value)
    assert item["elementIdentifier"] == "given_name"
    assert item["elementValue"] == "Alice"
    assert isinstance(item["digestID"], int)
    assert isinstance(item["random"], bytes)

    # issuerAuth : COSE Sign1 en tableau nu (sans tag CBOR 18, exigence des
    # parseurs mdoc dont CoseSign1.fromDataItem), signature vérifiable,
    # x5chain de deux en unprotected.
    auth = outer["issuerAuth"]
    assert isinstance(auth, list)
    assert len(auth) == 4
    message = Sign1Message.from_cose_obj(list(auth), True)
    message.key = _private_cose_key(pki.signer_private_key)
    assert message.verify_signature() is True
    protected = cbor2.loads(message.phdr_encoded)
    assert protected[1] == -7
    assert len(message.uhdr_encoded[X5chain]) == 2


def test_issue_embeds_device_key_and_validity() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(
        device_jwk=_device_jwk(), claims={"given_name": "Alice"}, doc_type=MDOC_DOCTYPE
    )
    outer = cbor2.loads(blob)
    message = Sign1Message.from_cose_obj(list(outer["issuerAuth"]), True)
    message.key = _private_cose_key(pki.signer_private_key)
    loaded = cbor2.loads(message.payload)
    mso = cbor2.loads(loaded.value) if isinstance(loaded, cbor2.CBORTag) else loaded

    device_key = mso["deviceKeyInfo"]["deviceKey"]
    assert device_key[1] == 2  # kty: EC2
    assert device_key[3] == -7  # alg: ES256
    assert device_key[-1] == 1  # crv: P-256
    assert mso["docType"] == MDOC_DOCTYPE
    assert mso["digestAlgorithm"] == "SHA-256"
    assert mso["version"] == "1.0"
    # validityInfo : tag CBOR 0 (décodé en datetime par cbor2) à la seconde
    # entière, UTC — les parseurs mdoc refusent les fractions de seconde.
    for key in ("signed", "validFrom", "validUntil"):
        stamp = mso["validityInfo"][key]
        assert isinstance(stamp, datetime)
        assert stamp.microsecond == 0
        assert stamp.utcoffset() == timedelta(0)


def test_issue_mso_matches_mdoc_parser_requirements() -> None:
    """Régression encodage : chaque exigence des parseurs mdoc (suite OIDF).

    Les cinq points vérifiés ici ont causé l'échec ``ParseMdocCredentialFromVCIIssuance
    : Failed requirement.`` (issue #255) : tableau COSE nu, digests indexés par
    ``digestId`` entier, ``docType`` présent, ``digestAlgorithm`` en texte,
    dates en tag CBOR 0 sans fraction de seconde.
    """
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(
        device_jwk=_device_jwk(),
        claims={"given_name": "Alice", "family_name": "Martin"},
        doc_type=MDOC_DOCTYPE,
    )
    outer = cbor2.loads(blob)

    # 1. issuerAuth = tableau COSE [protected, unprotected, payload, signature].
    auth = outer["issuerAuth"]
    assert isinstance(auth, list) and len(auth) == 4

    # Le payload est un tag CBOR 24 portant l'octet CBOR de la MSO.
    payload = cbor2.loads(auth[2])
    assert isinstance(payload, cbor2.CBORTag) and payload.tag == 24
    mso = cbor2.loads(payload.value)
    assert not isinstance(mso, cbor2.CBORTag)

    # 2. valueDigests indexé par digestId (uint), pas par identifiant d'élément.
    digests = mso["valueDigests"][PERSONAL_NAME_NAMESPACE]
    assert sorted(digests) == [0, 1]

    # 3-4. docType requis et digestAlgorithm en texte admis.
    assert mso["docType"] == MDOC_DOCTYPE
    assert mso["digestAlgorithm"] in {"SHA-256", "SHA-384", "SHA-512"}

    # 5. validityInfo : tstr RFC 3339 tagué 0 (cbor2 le rend en datetime),
    # sans microsecondes, en UTC.
    validity = mso["validityInfo"]
    for key in ("signed", "validFrom", "validUntil"):
        stamp = validity[key]
        assert isinstance(stamp, datetime)
        assert stamp.microsecond == 0
        assert stamp.utcoffset() == timedelta(0)


def test_issue_covers_each_claim_with_digest() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    blob = pki.issue(
        device_jwk=_device_jwk(),
        claims={"given_name": "Alice", "age": 42},
        doc_type=MDOC_DOCTYPE,
    )
    outer = cbor2.loads(blob)
    payload = cbor2.loads(Sign1Message.from_cose_obj(list(outer["issuerAuth"]), True).payload)
    if isinstance(payload, cbor2.CBORTag):
        payload = cbor2.loads(payload.value)
    digests = payload["valueDigests"][PERSONAL_NAME_NAMESPACE]
    # Clés = digestId uint, alignées sur le champ digestId des IssuerSignedItem.
    assert sorted(digests) == [0, 1]
    items = outer["nameSpaces"][PERSONAL_NAME_NAMESPACE]
    assert [cbor2.loads(item.value)["digestID"] for item in items] == [0, 1]


def test_issue_rejects_non_ec_binding_key() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    with pytest.raises(MdocBindingError, match="non EC"):
        pki.issue(
            device_jwk={"kty": "RSA"},
            claims={"given_name": "Alice"},
            doc_type=MDOC_DOCTYPE,
        )


def test_issue_rejects_non_p256_curve() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    jwk = _device_jwk()
    jwk["crv"] = "P-384"
    with pytest.raises(MdocBindingError, match="P-256"):
        pki.issue(device_jwk=jwk, claims={"given_name": "Alice"}, doc_type=MDOC_DOCTYPE)


def test_issue_rejects_missing_coordinates() -> None:
    pki = generate_mdoc_pki("https://op.example.com")
    with pytest.raises(MdocBindingError, match="coordonnees"):
        pki.issue(
            device_jwk={"kty": "EC", "crv": "P-256"},
            claims={"given_name": "Alice"},
            doc_type=MDOC_DOCTYPE,
        )


def test_signer_certificate_der_round_trip() -> None:
    """La chaîne x5chain doit être rechargeable en DER par un verifier."""
    pki = generate_mdoc_pki("https://op.example.com")
    signer_der = pki.signer_certificate.public_bytes(Encoding.DER)
    loaded = x509.load_der_x509_certificate(signer_der)
    assert loaded.subject == pki.signer_certificate.subject
