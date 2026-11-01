"""Credential mdoc ISO 18013-5 (format ``mso_mdoc``) pour l'émission OID4VCI.

Ce module construit la structure ``IssuerSigned`` d'un mobile mdoc conforme
ISO/IEC 18013-5 : une ``MobileSecurityObject`` (MSO) signée en COSE ``Sign1``
(tag CBOR 18), portant les digests des éléments émis, l'intervalle de validité
et la clé device du wallet, avec la chaîne de certificats du document signer
dans l'en-tête ``x5chain`` (RFC 9360).

La PKI mdoc se compose d'une IACA (autorité racine auto-signée) et d'un
document signer émis par cette IACA ; les deux sont générés à la volée et
vivent en mémoire pour la durée du processus.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import cbor2
from cose.keys import CoseKey  # type: ignore[import-untyped]
from cose.messages import Sign1Message  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

#: Algorithme de digest et de signature MSO (ES256 / SHA-256), encodé ``-7``.
DIGEST_ALGORITHM = -16

#: Namespace du nom personnel (ISO 18013-5.1 §4.1).
PERSONAL_NAME_NAMESPACE = "org.iso.18013.5.1"

#: Durée de validité d'un mdoc émis, en jours.
MDoc_LIFETIME_DAYS = 365

#: Tag CBOR d'un ``IssuerSignedItem`` encodé (ISO 18013-5 §9.1.2.1).
_ISSUER_SIGNED_ITEM_TAG = 24

#: Label COSE de l'en-tête ``x5chain`` (RFC 9360 §2).
_X5CHAIN_LABEL = 33

#: Label COSE de l'en-tête ``alg`` (RFC 9052 §3.1).
_HEADER_ALG = 1

#: Label COSE de l'attribut ``kty`` d'une clé (RFC 9052 §2).
_KEY_KTY = 1

#: Label COSE de l'attribut ``alg`` d'une clé (RFC 9052 §2).
_KEY_ALG = 3

#: Valeur ``kty`` d'une clé EC2 (RFC 9052 §2).
_KTY_EC2 = 2

#: Valeur ``alg`` ES256 (RFC 9052 §2).
_ALG_ES256 = -7

#: Valeur ``crv`` P-256 (RFC 9052 §2).
_CRV_P256 = 1

#: Algorithmes de preuve JWT admis pour une liaison ``cose_key`` mdoc.
MDOC_BINDING_JWK_TYPES = frozenset({"EC"})


class MdocBindingError(ValueError):
    """Clé de liaison du proof JWT inutilisable pour un device key mdoc."""


@dataclass(frozen=True)
class MdocIssuerPKI:
    """PKI mdoc d'un émetteur : IACA auto-signée et document signer émis.

    La structure conserve les clés privées nécessaires à la signature des
    ``issuerAuth`` et les deux certificats à embarquer dans ``x5chain``.
    """

    issuer_private_key: ec.EllipticCurvePrivateKey
    issuer_certificate: x509.Certificate
    signer_private_key: ec.EllipticCurvePrivateKey
    signer_certificate: x509.Certificate

    def issue(
        self,
        *,
        device_jwk: Mapping[str, Any],
        claims: Mapping[str, Any],
        now: datetime | None = None,
    ) -> bytes:
        """Émet un ``IssuerSigned`` CBOR lié à la clé device du wallet.

        Args:
            device_jwk: clé publique du wallet (``kty: EC``, ``crv: P-256``).
            claims: éléments à émettre, par identifiant d'élément.
            now: instant de signature, défaut : UTC courant.

        Returns:
            Le ``IssuerSigned`` encodé en CBOR (à transmettre en base64url).
        """
        signed_at = now or datetime.now(timezone.utc)
        digest_algorithm = hashes.SHA256()
        name_spaces, value_digests = _signed_name_spaces(claims, digest_algorithm)
        mso = _mobile_security_object(
            device_cose_key=_device_cose_key(device_jwk),
            value_digests=value_digests,
            signed_at=signed_at,
        )
        issuer_auth = _sign_mso(mso, self)
        return cbor2.dumps(
            {
                "issuerAuth": issuer_auth,
                "nameSpaces": name_spaces,
            }
        )


def generate_mdoc_pki(issuer: str, now: datetime | None = None) -> MdocIssuerPKI:
    """Génère une PKI mdoc (IACA auto-signée + document signer).

    Args:
        issuer: URL de l'émetteur, utilisée comme commune des certificats.
        now: instant de génération, défaut : UTC courant.

    Returns:
        La paire IACA / document signer prête à signer des MSO.
    """
    generated_at = now or datetime.now(timezone.utc)
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_certificate = _self_signed_issuer_certificate(issuer_key, issuer, generated_at)
    signer_key = ec.generate_private_key(ec.SECP256R1())
    signer_certificate = _document_signer_certificate(
        signer_key, issuer_certificate, issuer_key, generated_at
    )
    return MdocIssuerPKI(
        issuer_private_key=issuer_key,
        issuer_certificate=issuer_certificate,
        signer_private_key=signer_key,
        signer_certificate=signer_certificate,
    )


def _self_signed_issuer_certificate(
    private_key: ec.EllipticCurvePrivateKey, issuer: str, generated_at: datetime
) -> x509.Certificate:
    """Construit le certificat auto-signé de l'IACA (``ca=True``)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer} IACA")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=MDoc_LIFETIME_DAYS * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )


def _document_signer_certificate(
    private_key: ec.EllipticCurvePrivateKey,
    issuer_certificate: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    generated_at: datetime,
) -> x509.Certificate:
    """Construit le certificat du document signer émis par l'IACA."""
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_certificate.subject} document signer")]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=MDoc_LIFETIME_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _device_cose_key(device_jwk: Mapping[str, Any]) -> dict[int, Any]:
    """Convertit un JWK EC P-256 public en clé COSE publique (RFC 9052)."""
    if device_jwk.get("kty") not in MDOC_BINDING_JWK_TYPES:
        raise MdocBindingError("cle de liaison non EC, incompatible avec un device key mdoc")
    if device_jwk.get("crv") != "P-256":
        raise MdocBindingError("seule la courbe P-256 est supportee pour un device key mdoc")
    x_value = device_jwk.get("x")
    y_value = device_jwk.get("y")
    if not isinstance(x_value, str) or not isinstance(y_value, str):
        raise MdocBindingError("coordonnees x/y absentes de la cle de liaison")
    return {
        _KEY_KTY: _KTY_EC2,
        _KEY_ALG: _ALG_ES256,
        -1: _CRV_P256,
        -2: _b64url_decode(x_value),
        -3: _b64url_decode(y_value),
    }


def _b64url_decode(value: str) -> bytes:
    """Décode une valeur base64url sans padding (RFC 4648 §5)."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _private_cose_key(private_key: ec.EllipticCurvePrivateKey) -> CoseKey:
    """Convertit une clé privée EC P-256 en clé COSE privée."""
    public_numbers = private_key.public_key().public_numbers()
    return CoseKey.from_dict(
        {
            _KEY_KTY: _KTY_EC2,
            _KEY_ALG: _ALG_ES256,
            -1: _CRV_P256,
            -2: public_numbers.x.to_bytes(32, "big"),
            -3: public_numbers.y.to_bytes(32, "big"),
            -4: private_key.private_numbers().private_value.to_bytes(32, "big"),  # type: ignore[attr-defined]  # méthode abstraite réelle, absente des stubs cryptography
        }
    )


def _issuer_signed_item(
    element_identifier: str, element_value: object, digest_id: int
) -> cbor2.CBORTag:
    """Construit un ``IssuerSignedItem`` encodé (tag CBOR 24)."""
    random_bytes = secrets.token_bytes(16)
    item = {
        0: digest_id,
        1: random_bytes,
        2: element_identifier,
        3: element_value,
    }
    return cbor2.CBORTag(_ISSUER_SIGNED_ITEM_TAG, cbor2.dumps(item))


def _item_digest(encoded_item: cbor2.CBORTag, digest_algorithm: hashes.HashAlgorithm) -> bytes:
    """Digest SHA-256 de l'``IssuerSignedItem`` encodé (ISO 18013-5 §9.1.2.1)."""
    digest = hashes.Hash(digest_algorithm)
    digest.update(cbor2.dumps(encoded_item))
    return digest.finalize()


def _signed_name_spaces(
    claims: Mapping[str, Any], digest_algorithm: hashes.HashAlgorithm
) -> tuple[dict[str, list[cbor2.CBORTag]], dict[str, dict[str, bytes]]]:
    """Encode les éléments émis et calcule leurs digests par namespace."""
    items: list[cbor2.CBORTag] = []
    digests: dict[str, bytes] = {}
    for digest_id, (element_identifier, element_value) in enumerate(claims.items()):
        encoded_item = _issuer_signed_item(element_identifier, element_value, digest_id)
        items.append(encoded_item)
        digests[element_identifier] = _item_digest(encoded_item, digest_algorithm)
    return {PERSONAL_NAME_NAMESPACE: items}, {PERSONAL_NAME_NAMESPACE: digests}


def _mobile_security_object(
    *,
    device_cose_key: dict[int, Any],
    value_digests: dict[str, dict[str, bytes]],
    signed_at: datetime,
) -> dict[str, Any]:
    """Construit la MSO (ISO 18013-5 §9.1.2.1) hors signature."""
    valid_until = signed_at + timedelta(days=MDoc_LIFETIME_DAYS)
    return {
        "version": "1.0",
        "digestAlgorithm": DIGEST_ALGORITHM,
        "valueDigests": value_digests,
        "validityInfo": {
            "signed": signed_at.isoformat(),
            "validFrom": signed_at.isoformat(),
            "validUntil": valid_until.isoformat(),
        },
        "deviceKeyInfo": {"deviceKey": device_cose_key},
    }


def _sign_mso(mso: dict[str, Any], pki: MdocIssuerPKI) -> cbor2.CBORTag:
    """Signe la MSO en COSE ``Sign1`` avec la chaîne ``x5chain`` du signer."""
    message = Sign1Message(
        phdr={_HEADER_ALG: _ALG_ES256},
        payload=cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso))),
    )
    message.uhdr_update(
        {
            _X5CHAIN_LABEL: [
                pki.signer_certificate.public_bytes(cast(Encoding, Encoding.DER)),
                pki.issuer_certificate.public_bytes(cast(Encoding, Encoding.DER)),
            ]
        }
    )
    message.key = _private_cose_key(pki.signer_private_key)
    encoded = message.encode(sign=True, tag=True)
    tagged = cbor2.loads(encoded)
    return cbor2.CBORTag(tagged.tag, tagged.value)
