"""PKI du verifier OpenID4VP (CA auto-signée + leaf de signature du request object).

Le profil HAIP impose un ``client_id`` de forme ``x509_hash:<empreinte>``
(OID4VP 1.0 Final §5.9.3-3.6.1) : l'empreinte SHA-256 (base64url, RFC 7638)
du certificat leaf embarqué dans l'en-tête ``x5c`` du request object signé.
La suite valide ensuite la chaîne ``[leaf]`` en PKIX complet contre l'ancre de
confiance injectée dans la configuration du test
(``client.request_object_trust_anchor_pem``) : la CA reste donc hors chaîne et
le leaf n'est jamais auto-signé.

Les certificats sont générés à la première demande et persistés (PEM en JSON)
pour que le ``client_id`` reste stable d'un run à l'autre.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from puridentityserver.infrastructure.jwe import b64u

_LOGGER = logging.getLogger(__name__)

#: Durée de validité de la CA racine du verifier, en jours (harness de
#: certification : aucune contrainte de profil public sur la racine).
VERIFIER_CA_LIFETIME_DAYS = 3650

#: Durée de validité du leaf de signature, en jours. La suite contrôle la
#: validité du leaf à chaque module ; cinq ans couvrent la durée de vie du
#: harness local persistant sans imposer une rotation prématurée.
VERIFIER_LEAF_LIFETIME_DAYS = 1825

#: Préfixe du ``client_id`` x509_hash (OID4VP 1.0 Final §5.9.3-3.6.1).
X509_HASH_CLIENT_ID_PREFIX = "x509_hash:"

#: Limite X.509 du ``commonName`` (RFC 5280).
_COMMON_NAME_MAX_LENGTH = 64


class VerifierPKIRepository(Protocol):
    """Contrat de persistance minimal pour la PKI du verifier."""

    def load(self) -> VerifierPKI | None:
        """Charge la PKI persistée, ou ``None`` si absente/invalide."""

    def save(self, pki: VerifierPKI) -> None:
        """Persiste la PKI."""


@dataclass(frozen=True)
class VerifierPKI:
    """PKI du verifier : CA racine auto-signée et leaf émis par cette CA.

    Le leaf signe les request objects (en-tête ``x5c``, ``alg = ES256``) et
    sert de source au ``client_id`` ``x509_hash:`` ; la CA fournit l'ancre de
    confiance que la suite injecte dans sa configuration de test.
    """

    ca_private_key: ec.EllipticCurvePrivateKey
    ca_certificate: x509.Certificate
    leaf_private_key: ec.EllipticCurvePrivateKey
    leaf_certificate: x509.Certificate

    @property
    def leaf_thumbprint(self) -> str:
        """Empreinte SHA-256 (base64url) du certificat leaf, en ``x5t#S256``."""
        der = self.leaf_certificate.public_bytes(
            cast(serialization.Encoding, serialization.Encoding.DER)
        )
        return b64u(hashlib.sha256(der).digest())

    @property
    def client_id(self) -> str:
        """``client_id`` du verifier : ``x509_hash:`` + empreinte SHA-256 du leaf.

        L'empreinte est le base64url (sans padding) du SHA-256 du DER du
        certificat, identique au thumbprint calculé par la suite
        (``X509CertUtils.computeSHA256Thumbprint``).
        """
        return f"{X509_HASH_CLIENT_ID_PREFIX}{self.leaf_thumbprint}"

    @property
    def x5c(self) -> list[str]:
        """Chaîne ``x5c`` du request object : le seul certificat leaf.

        Encodage base64 **standard** avec padding (RFC 7515 §4.1.6 — pas du
        base64url) ; la CA reste hors chaîne, exigence PKIX de la suite.
        """
        der = self.leaf_certificate.public_bytes(
            cast(serialization.Encoding, serialization.Encoding.DER)
        )
        return [base64.b64encode(der).decode("ascii")]

    @property
    def trust_anchor_pem(self) -> str:
        """Certificat CA au format PEM (ancre de confiance à injecter dans le plan)."""
        pem = self.ca_certificate.public_bytes(
            cast(serialization.Encoding, serialization.Encoding.PEM)
        )
        return pem.decode("ascii")


def generate_verifier_pki(
    common_name: str = "PurIdentityServer OID4VP verifier",
    now: datetime | None = None,
) -> VerifierPKI:
    """Génère la PKI du verifier (CA auto-signée + leaf de signature).

    Args:
        common_name: sujet du leaf, tronqué à la limite X.509 de 64 caractères.
        now: instant de génération, défaut : UTC courant.

    Returns:
        La paire CA / leaf prête à signer les request objects.
    """
    generated_at = now or datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_certificate = _ca_certificate(ca_key, generated_at)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_certificate = _leaf_certificate(
        leaf_key, ca_certificate, ca_key, common_name[:_COMMON_NAME_MAX_LENGTH], generated_at
    )
    return VerifierPKI(
        ca_private_key=ca_key,
        ca_certificate=ca_certificate,
        leaf_private_key=leaf_key,
        leaf_certificate=leaf_certificate,
    )


class InMemoryVerifierPKIRepository:
    """Dépôt en mémoire (tests / défaut éphémère)."""

    def __init__(self) -> None:
        """Initialise le dépôt vide."""
        self._pki: VerifierPKI | None = None

    def load(self) -> VerifierPKI | None:
        """Rend la PKI en mémoire, si elle a été sauvegardée."""
        return self._pki

    def save(self, pki: VerifierPKI) -> None:
        """Mémorise la PKI en mémoire."""
        self._pki = pki


class FileVerifierPKIRepository:
    """Dépôt fichier (JSON de PEM), sur le modèle du dépôt de la PKI mdoc."""

    def __init__(self, path: str | Path) -> None:
        """Stocke le chemin du fichier persistant."""
        self._path = Path(path)

    def load(self) -> VerifierPKI | None:
        """Charge la PKI depuis le fichier ; ``None`` si absente/invalide."""
        if not self._path.is_file():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _LOGGER.warning("PKI oid4vp illisible sur %s, régénération", self._path)
            return None
        if not isinstance(data, dict):
            return None
        try:
            ca_key = _load_ec_private(_require_str(data, "ca_key_pem"))
            leaf_key = _load_ec_private(_require_str(data, "leaf_key_pem"))
            ca_certificate = x509.load_pem_x509_certificate(
                _require_str(data, "ca_cert_pem").encode("ascii")
            )
            leaf_certificate = x509.load_pem_x509_certificate(
                _require_str(data, "leaf_cert_pem").encode("ascii")
            )
        except (ValueError, TypeError):
            _LOGGER.warning("PKI oid4vp invalide sur %s, régénération", self._path)
            return None
        return VerifierPKI(
            ca_private_key=ca_key,
            ca_certificate=ca_certificate,
            leaf_private_key=leaf_key,
            leaf_certificate=leaf_certificate,
        )

    def save(self, pki: VerifierPKI) -> None:
        """Persiste la PKI en JSON (PEM) dans le fichier."""
        data: dict[str, Any] = {
            "ca_key_pem": _pem_private(pki.ca_private_key),
            "ca_cert_pem": _pem_cert(pki.ca_certificate),
            "leaf_key_pem": _pem_private(pki.leaf_private_key),
            "leaf_cert_pem": _pem_cert(pki.leaf_certificate),
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            _LOGGER.warning("Impossible de persister la PKI oid4vp sur %s", self._path)


def _ca_certificate(
    private_key: ec.EllipticCurvePrivateKey, generated_at: datetime
) -> x509.Certificate:
    """Construit le certificat auto-signé de la CA racine (``ca=True``)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PurIdentityServer OID4VP CA")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=VERIFIER_CA_LIFETIME_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )


def _leaf_certificate(
    private_key: ec.EllipticCurvePrivateKey,
    ca_certificate: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    generated_at: datetime,
) -> x509.Certificate:
    """Construit le certificat leaf émis par la CA (signature ``ES256`` du RO)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=VERIFIER_LEAF_LIFETIME_DAYS))
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_certificate.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _load_ec_private(pem: str) -> ec.EllipticCurvePrivateKey:
    """Charge une clé privée EC depuis son PEM ; ``ValueError`` sinon."""
    key = load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("clé privée oid4vp non EC")
    return key


def _require_str(data: dict[str, Any], key: str) -> str:
    """Exige un champ textuel dans les données persistées."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"champ {key} manquant ou non textuel")
    return value


def _pem_private(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Serialise une clé privée EC en PEM PKCS#8."""
    raw = private_key.private_bytes(  # type: ignore[attr-defined]  # méthode abstraite réelle, absente des stubs cryptography
        encoding=cast(serialization.Encoding, serialization.Encoding.PEM),
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cast(bytes, raw).decode("ascii")


def _pem_cert(certificate: x509.Certificate) -> str:
    """Serialise un certificat X.509 en PEM."""
    pem = certificate.public_bytes(cast(serialization.Encoding, serialization.Encoding.PEM))
    return pem.decode("ascii")
