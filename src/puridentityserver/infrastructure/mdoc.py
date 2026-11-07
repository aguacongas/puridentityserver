"""Credential mdoc ISO 18013-5 (format ``mso_mdoc``) pour l'émission OID4VCI.

Ce module construit la structure ``IssuerSigned`` d'un mobile mdoc conforme
ISO/IEC 18013-5 : une ``MobileSecurityObject`` (MSO) signée en COSE ``Sign1``
(portée par un ``issuerAuth`` en tableau COSE de 4 éléments, sans tag CBOR 18),
portant les digests des éléments émis, l'intervalle de validité
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
from datetime import date, datetime, timedelta, timezone
from typing import Any, cast

import cbor2
from cose.keys import CoseKey  # type: ignore[import-untyped]
from cose.messages import Sign1Message  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.oid import NameOID

#: Algorithme de digest de la MSO, en texte (ISO 18013-5 §9.1.2.1 ; valeurs
#: admises par les parseurs mdoc : ``SHA-256``, ``SHA-384``, ``SHA-512``).
DIGEST_ALGORITHM = "SHA-256"

#: Namespace du nom personnel (ISO 18013-5.1 §4.1).
PERSONAL_NAME_NAMESPACE = "org.iso.18013.5.1"

#: Durée de validité d'un mdoc émis, en jours.
MDoc_LIFETIME_DAYS = 365

#: Durée de validité du certificat document signer, en jours. ISO 18013-5
#: Table B.3 plafonne cette validité à 457 jours ; 456 laisse une marge sur
#: le ``validUntil`` du MSO émis à J+365 depuis la génération de la PKI,
#: exigence de ISO 18013-5 §9.3.1 (un lecteur peut rejeter un MSO qui
#: survit à son certificat).
MDOC_SIGNER_LIFETIME_DAYS = 456

#: Pays ISO 3166-1 alpha-2 porté par les sujets des certificats mdoc et par
#: l'élément ``issuing_country`` émis : ISO 18013-5 Table B.3 impose que le
#: ``countryName`` du document signer soit identique à cette valeur.
MDOC_ISSUING_COUNTRY = "FR"

#: OID de la clé de signature de document mdoc (``mdlDS``), exigée par
#: ISO 18013-5 Table B.3 dans l'``extendedKeyUsage`` d'un document signer
#: de doctype mDL.
_OID_MDL_DS_EKU = ObjectIdentifier("1.0.18013.5.1.2")

#: Éléments obligatoires d'un mdoc mDL (ISO 18013-5 §13.4.2, table 20,
#: présence « M »), avec les valeurs de démonstration de l'instance : le
#: doctype ``org.iso.18013.5.1.mDL`` impose ces 11 éléments dans le
#: namespace ``org.iso.18013.5.1``. Les dates sont des ``datetime.date``
#: pour que cbor2 les encode en CBOR tag 1004 (full-date) et le portrait
#: en ``bytes`` pour un bstr, formats exigés par les contraintes de la
#: table 20 (tstr latin-1 ≤ 150 pour les textes, alpha-2 pour le pays).
#: L'ensemble est en lecture seule : il est copié à chaque émission.
MDL_MANDATORY_ELEMENTS: dict[str, object] = {
    "family_name": "Martin",
    "given_name": "Alice",
    "birth_date": date(1985, 6, 15),
    "issue_date": date(2025, 6, 1),
    "expiry_date": date(2030, 6, 1),
    "issuing_country": MDOC_ISSUING_COUNTRY,
    "issuing_authority": "Ministere de l'Interieur",
    "document_number": "12AB34567",
    "portrait": base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
        "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    ),
    "driving_privileges": [
        {
            "vehicle_category_code": "B",
            "issue_date": date(2025, 6, 1),
            "expiry_date": date(2030, 6, 1),
            "codes": [{"code": "01"}],
        }
    ],
    "un_distinguishing_sign": "SIGN-DEMO-0001",
}

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
        doc_type: str,
        now: datetime | None = None,
    ) -> bytes:
        """Émet un ``IssuerSigned`` CBOR lié à la clé device du wallet.

        Args:
            device_jwk: clé publique du wallet (``kty: EC``, ``crv: P-256``).
            claims: éléments à émettre, par identifiant d'élément.
            doc_type: type de document ISO 18013-5 (doctype de la
                configuration d'émetteur publiée en metadata).
            now: instant de signature, défaut : UTC courant. S'il est
                antérieur à la validité du certificat du document signer
                (cas d'un MSO arrondi à l'heure émis peu après la
                génération de la PKI), il est relevé à cette borne :
                ISO 18013-5 §9.3.1 interdit un ``signed`` hors de la
                validité du signer.

        Returns:
            Le ``IssuerSigned`` encodé en CBOR (à transmettre en base64url).
        """
        signed_at = (now or datetime.now(timezone.utc)).replace(microsecond=0)
        # ``not_valid_before`` est naïf (UTC), convention de ``cryptography``.
        not_before = self.signer_certificate.not_valid_before.replace(
            tzinfo=timezone.utc, microsecond=0
        )
        if signed_at < not_before:
            signed_at = not_before
        digest_algorithm = hashes.SHA256()
        name_spaces, value_digests = _signed_name_spaces(claims, digest_algorithm)
        mso = _mobile_security_object(
            doc_type=doc_type,
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
        signer_key, issuer_certificate, issuer_key, generated_at, issuer
    )
    return MdocIssuerPKI(
        issuer_private_key=issuer_key,
        issuer_certificate=issuer_certificate,
        signer_private_key=signer_key,
        signer_certificate=signer_certificate,
    )


def generate_mdoc_crl(pki: MdocIssuerPKI, crl_counter: int | None = None) -> bytes:
    """Génère un CRL DER signé par l'IACA conforme au profil ISO 18013-5 Table B.10.

    Profil CRL B.10 :
      - version 2 (obligatoire pour indiquer la présence d'extensions et nextUpdate)
      - issuer = subject du certificat IACA (même DN binaire)
      - ECDSA avec SHA-256, même algorithme dans le TBS et signature externe
      - authority key identifier en keyIdentifier form, égal au SKI de l'IACA (non critique)
      - CRL number ≥ 0 ≤ 20 octets (RFC 5280), ici compteur incrémenté à chaque génération
      - nextUpdate présent et ≤ 90j après thisUpdate (B.2 impose une nouvelle CRL toutes les 90j)
      - revokedCertificates absent si rien n'est révoqué (Table B.10)
      - aucune autre extension

    Args:
        pki: objet ``MdocIssuerPKI`` contenant la clé privée de l'IACA et le SKI de cette dernière.
        crl_counter: compteur incrémenté pour le CRLNumber (optionnel, défaut : valeur persistante).

    Returns:
        Le CRL encodé en DER (pour être servi tel quel à ``/crl/mdoc.crl``).
    """
    from cryptography import x509 as x509_mod
    from cryptography.hazmat.primitives.serialization import Encoding as SerializationEncoding

    # thisUpdate : UTC, encodage UTCTime ou GeneralizedTime selon la date (<2050 ou ≥2050)
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    this_update = now_utc.replace(minute=0, second=0)  # arrondi à l'heure (RFC 9901)

    # nextUpdate : ≤ 90j après thisUpdate (exigence de la suite 5.3.4)
    next_update = this_update + timedelta(days=7)  # 7 jours, largement sous les 90j B.2

    # SKI de l'IACA (keyIdentifier pour AKI, Table B.10)
    ski = x509.SubjectKeyIdentifier.from_public_key(pki.issuer_certificate.public_key())

    builder = x509_mod.CertificateRevocationListBuilder()
    # Issuer = subject du certificat IACA (même DN binaire)
    issuer_name_str = pki.issuer_certificate.subject
    builder = builder.issuer_name(issuer_name_str)
    builder = builder.last_update(this_update)
    builder = builder.next_update(next_update)

    # AKI en keyIdentifier form (Table B.10), non critique, authority_cert_issuer/serial_number=None
    aki_extension = x509.AuthorityKeyIdentifier(
        key_identifier=ski.digest, authority_cert_issuer=None, authority_cert_serial_number=None
    )
    builder = builder.add_extension(aki_extension, critical=False)

    # CRLNumber (RFC 5280 : entier non-négatif, ici ≤ 20 octets), non critique
    crl_number_value = crl_counter if crl_counter is not None else 1
    crl_number_ext = x509_mod.CRLNumber(crl_number_value)
    builder = builder.add_extension(crl_number_ext, critical=False)

    # Signature IACA SHA-256
    signer_key = pki.issuer_private_key
    crl = builder.sign(private_key=signer_key, algorithm=hashes.SHA256())

    from typing import cast

    return crl.public_bytes(encoding=cast(SerializationEncoding, SerializationEncoding.DER))


#: Limite de longueur d'un ``Common Name`` X.509 (RFC 5280 §4.2.1.6).
_COMMON_NAME_MAX_LENGTH = 64


def _capped_common_name(base: str, suffix: str) -> str:
    """Compose un CN en conservant le suffixe sous la limite X.509 (64).

    Un issuer long (URL publique de l'instance de certification) ferait
    dépasser la limite si le CN était concaténé sans troncature :
    ``cryptography`` lèverait alors ``ValueError`` et la metadata signée
    de l'émetteur OID4VCI renverrait un 500.

    Args:
        base: partie variable du CN (URL de l'émetteur, CN de l'IACA).
        suffix: suffixe sémantique (``" IACA"``, ``" document signer"``).

    Returns:
        Le CN composé, tronqué si nécessaire pour tenir sous 64 caractères.
    """
    available = _COMMON_NAME_MAX_LENGTH - len(suffix)
    if available <= 0:
        return suffix[:_COMMON_NAME_MAX_LENGTH]
    return f"{base[:available]}{suffix}"


def _issuer_common_name(issuer_certificate: x509.Certificate) -> str:
    """CN porté par le sujet de l'IACA, ou le sujet RFC 4514 à défaut.

    Args:
        issuer_certificate: certificat IACA dont on lit le ``commonName``.

    Returns:
        La valeur du ``commonName``, ou le sujet RFC 4514 si absent.
    """
    attributes = issuer_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attributes) == 1:
        return str(attributes[0].value)
    return issuer_certificate.subject.rfc4514_string()


def _self_signed_issuer_certificate(
    private_key: ec.EllipticCurvePrivateKey, issuer: str, generated_at: datetime
) -> x509.Certificate:
    """Construit le certificat auto-signé de l'IACA (``ca=True``)."""
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, MDOC_ISSUING_COUNTRY),
            x509.NameAttribute(NameOID.COMMON_NAME, _capped_common_name(issuer, " IACA")),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=MDoc_LIFETIME_DAYS * 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )


def _document_signer_certificate(
    private_key: ec.EllipticCurvePrivateKey,
    issuer_certificate: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    generated_at: datetime,
    issuer: str,
) -> x509.Certificate:
    """Construit le certificat du document signer émis par l'IACA.

    Le certificat suit le profil ISO 18013-5 Table B.3 exigé par les
    lecteurs stricts et par la suite de conformance : ``countryName``
    identique à l'élément ``issuing_country``, ``keyUsage`` critique
    limité à ``digitalSignature``, ``extendedKeyUsage`` critique portant
    l'OID ``mdlDS``, identifiants de clé (SKI/AKI), nom alternatif de
    l'émetteur et point de distribution de CRL, ``basicConstraints``
    non critique (seuls ``keyUsage`` et ``EKU`` peuvent l'être).

    Args:
        private_key: clé privée EC du document signer.
        issuer_certificate: certificat IACA émetteur.
        issuer_key: clé privée de l'IACA qui signe ce certificat.
        generated_at: instant de génération (validité bornée à -1 h 05 pour
            couvrir le MSO arrondi à l'heure).
        issuer: URL de l'émetteur, contact du nom alternatif et base de
            l'URI du point de distribution de CRL.

    Returns:
        Le certificat document signer signé par l'IACA.
    """
    contact = issuer.rstrip("/")
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, MDOC_ISSUING_COUNTRY),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                _capped_common_name(_issuer_common_name(issuer_certificate), " document signer"),
            ),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        # marge d'une heure : le ``signed`` du MSO est arrondi à l'heure
        # (RFC 9901 §10.1, anti-linkabilité) et doit rester dans la
        # validité du signer (ISO 18013-5 §9.3.1)
        .not_valid_before(generated_at - timedelta(hours=1, minutes=5))
        .not_valid_after(generated_at + timedelta(days=MDOC_SIGNER_LIFETIME_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([_OID_MDL_DS_EKU]), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_certificate.public_key()),
            critical=False,
        )
        .add_extension(
            x509.IssuerAlternativeName([x509.UniformResourceIdentifier(contact)]),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(f"{contact}/crl/mdoc.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
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
    """Construit un ``IssuerSignedItem`` encodé (tag CBOR 24).

    La carte est à clés texte (``digestID``, ``random``, ``elementIdentifier``,
    ``elementValue``) : c'est l'encodage qu'émet la librairie multipaz, de
    référence dans l'écosystème mdoc, et celui que lit la suite de
    conformance OIDF.
    """
    random_bytes = secrets.token_bytes(16)
    item = {
        "digestID": digest_id,
        "random": random_bytes,
        "elementIdentifier": element_identifier,
        "elementValue": element_value,
    }
    return cbor2.CBORTag(_ISSUER_SIGNED_ITEM_TAG, cbor2.dumps(item))


def _item_digest(encoded_item: cbor2.CBORTag, digest_algorithm: hashes.HashAlgorithm) -> bytes:
    """Digest SHA-256 de l'``IssuerSignedItem`` encodé (ISO 18013-5 §9.1.2.1)."""
    digest = hashes.Hash(digest_algorithm)
    digest.update(cbor2.dumps(encoded_item))
    return digest.finalize()


def _signed_name_spaces(
    claims: Mapping[str, Any], digest_algorithm: hashes.HashAlgorithm
) -> tuple[dict[str, list[cbor2.CBORTag]], dict[str, dict[int, bytes]]]:
    """Encode les éléments émis et calcule leurs digests par namespace.

    Les digests sont indexés par ``digestId`` (entier non signé), la clé
    attendue par les parseurs mdoc pour ``valueDigests`` (ISO 18013-5 §9.1.2.1).
    """
    items: list[cbor2.CBORTag] = []
    digests: dict[int, bytes] = {}
    for digest_id, (element_identifier, element_value) in enumerate(claims.items()):
        encoded_item = _issuer_signed_item(element_identifier, element_value, digest_id)
        items.append(encoded_item)
        digests[digest_id] = _item_digest(encoded_item, digest_algorithm)
    return {PERSONAL_NAME_NAMESPACE: items}, {PERSONAL_NAME_NAMESPACE: digests}


def _rfc3339_instant(value: datetime) -> cbor2.CBORTag:
    """Encode un instant en tag CBOR 0 sur texte RFC 3339 à la seconde entière.

    Les parseurs mdoc exigent un tag 0 (date/time string) et refusent les
    fractions de seconde dans ``validityInfo`` (ISO 18013-5 §9.1.2.1).
    """
    whole = value.astimezone(timezone.utc).replace(microsecond=0)
    return cbor2.CBORTag(0, whole.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _mobile_security_object(
    *,
    doc_type: str,
    device_cose_key: dict[int, Any],
    value_digests: dict[str, dict[int, bytes]],
    signed_at: datetime,
) -> dict[str, Any]:
    """Construit la MSO (ISO 18013-5 §9.1.2.1) hors signature."""
    valid_until = signed_at + timedelta(days=MDoc_LIFETIME_DAYS)
    return {
        "version": "1.0",
        "docType": doc_type,
        "digestAlgorithm": DIGEST_ALGORITHM,
        "valueDigests": value_digests,
        "validityInfo": {
            "signed": _rfc3339_instant(signed_at),
            "validFrom": _rfc3339_instant(signed_at),
            "validUntil": _rfc3339_instant(valid_until),
        },
        "deviceKeyInfo": {"deviceKey": device_cose_key},
    }


def _sign_mso(mso: dict[str, Any], pki: MdocIssuerPKI) -> list[Any]:
    """Signe la MSO en COSE ``Sign1`` avec la chaîne ``x5chain`` du signer.

    Le tableau COSE est encodé **sans tag CBOR 18** : les parseurs mdoc
    (dont ``CoseSign1.fromDataItem`` de la suite OIDF) exigent un tableau
    de 4 éléments nu et rejettent un élément tagué.
    """
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
    return cast(list[Any], cbor2.loads(message.encode(sign=True, tag=False)))
