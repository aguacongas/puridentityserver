"""PKI d'emission des credentials SD-JWT (racine RSA + leaf de signature).

HAIP section 4.5.1 impose l'en-tete ``x5c`` (RFC 7515 section 4.1.6) sur le
credential SD-JWT emis : la suite de conformance OIDF valide la chaine
``[leaf]`` en PKIX complet contre l'ancre de confiance injectee dans sa
configuration de test (``credential.trust_anchor_pem``) - la racine reste
hors chaine et le leaf n'est jamais auto-signe - puis verifie la signature
du JWT avec la cle publique du leaf.

Les certificats sont generes une fois et persistes (PEM en JSON, setting
``credential_pki_path``) : l'ancre commitee dans les plans de certification
doit correspondre exactement a la racine utilisee a l'emission. Sans depot
configure (developpement), aucun ``x5c`` n'est emis et le credential reste
signe par la cle active de l'OP.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from puridentityserver.infrastructure.jwe import b64u

_LOGGER = logging.getLogger(__name__)

#: Duree de validite de la racine, en jours.
CREDENTIAL_CA_LIFETIME_DAYS = 3650

#: Duree de validite du leaf de signature, en jours. La suite controle la
#: validite du leaf a chaque module ; cinq ans couvrent la duree de vie du
#: depot commité sans imposer une rotation prematuree.
CREDENTIAL_LEAF_LIFETIME_DAYS = 1825

#: Exposant des clefs RSA de la PKI.
_RSA_PUBLIC_EXPONENT = 65537

#: Taille des clefs RSA de la PKI (profil FAPI : RSA >= 2048).
_RSA_KEY_SIZE = 2048


class CredentialPKIRepository(Protocol):
    """Contrat de persistance minimal pour la PKI d'emission."""

    def load(self) -> CredentialPKI | None:
        """Charge la PKI persistee, ou ``None`` si absente/invalide."""

    def save(self, pki: CredentialPKI) -> None:
        """Persiste la PKI."""


@dataclass(frozen=True)
class CredentialPKI:
    """PKI d'emission : racine auto-signee et leaf emis par cette racine.

    Le leaf signe les credentials SD-JWT (en-tete ``x5c``, ``alg = RS256``) ;
    la racine fournit l'ancre de confiance que la suite injecte dans sa
    configuration de test (``credential.trust_anchor_pem``).
    """

    root_private_key: rsa.RSAPrivateKey
    root_certificate: x509.Certificate
    leaf_private_key: rsa.RSAPrivateKey
    leaf_certificate: x509.Certificate

    @property
    def x5c(self) -> list[str]:
        """Chaine ``x5c`` du credential : le seul certificat leaf.

        Encodage base64 **standard** avec padding (RFC 7515 section 4.1.6,
        pas du base64url) ; la racine reste hors chaine, exigence PKIX de
        la suite.
        """
        der = self.leaf_certificate.public_bytes(serialization.Encoding.DER)
        return [base64.b64encode(der).decode("ascii")]

    @property
    def kid(self) -> str:
        """``kid`` du credential : base64url du SKI de la leaf (RFC 5280)."""
        ski = self.leaf_certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        return b64u(ski.digest)

    @property
    def trust_anchor_pem(self) -> str:
        """Certificat racine au format PEM (ancre a injecter dans le plan)."""
        pem = self.root_certificate.public_bytes(serialization.Encoding.PEM)
        return pem.decode("ascii")


def generate_credential_pki(now: datetime | None = None) -> CredentialPKI:
    """Genere la PKI d'emission (racine auto-signee + leaf de signature).

    Args:
        now: instant de generation, defaut : UTC courant.

    Returns:
        La paire racine / leaf prete a signer des credentials SD-JWT.
    """
    generated_at = now or datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_SIZE
    )
    root_certificate = _root_certificate(root_key, generated_at)
    leaf_key = rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_SIZE
    )
    leaf_certificate = _leaf_certificate(leaf_key, root_certificate, root_key, generated_at)
    return CredentialPKI(
        root_private_key=root_key,
        root_certificate=root_certificate,
        leaf_private_key=leaf_key,
        leaf_certificate=leaf_certificate,
    )


class InMemoryCredentialPKIRepository:
    """Depot en memoire (tests)."""

    def __init__(self) -> None:
        """Initialise le depot vide."""
        self._pki: CredentialPKI | None = None

    def load(self) -> CredentialPKI | None:
        """Rend la PKI en memoire, si elle a ete sauvegardee."""
        return self._pki

    def save(self, pki: CredentialPKI) -> None:
        """Memorise la PKI en memoire."""
        self._pki = pki


class FileCredentialPKIRepository:
    """Depot fichier (JSON de PEM), sur le modele du depot de la PKI oid4vp."""

    def __init__(self, path: str | Path) -> None:
        """Stocke le chemin du fichier persistant."""
        self._path = Path(path)

    def load(self) -> CredentialPKI | None:
        """Charge la PKI depuis le fichier ; ``None`` si absente/invalide."""
        if not self._path.is_file():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _LOGGER.warning("PKI credential illisible sur %s, regeneration", self._path)
            return None
        if not isinstance(data, dict):
            return None
        try:
            root_key = _load_rsa_private(_require_str(data, "root_key_pem"))
            leaf_key = _load_rsa_private(_require_str(data, "leaf_key_pem"))
            root_certificate = x509.load_pem_x509_certificate(
                _require_str(data, "root_cert_pem").encode("ascii")
            )
            leaf_certificate = x509.load_pem_x509_certificate(
                _require_str(data, "leaf_cert_pem").encode("ascii")
            )
        except (ValueError, TypeError):
            _LOGGER.warning("PKI credential invalide sur %s, regeneration", self._path)
            return None
        return CredentialPKI(
            root_private_key=root_key,
            root_certificate=root_certificate,
            leaf_private_key=leaf_key,
            leaf_certificate=leaf_certificate,
        )

    def save(self, pki: CredentialPKI) -> None:
        """Persiste la PKI en JSON (PEM) dans le fichier."""
        data: dict[str, Any] = {
            "root_key_pem": _pem_private(pki.root_private_key),
            "root_cert_pem": _pem_cert(pki.root_certificate),
            "leaf_key_pem": _pem_private(pki.leaf_private_key),
            "leaf_cert_pem": _pem_cert(pki.leaf_certificate),
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            _LOGGER.warning("Impossible de persister la PKI credential sur %s", self._path)


def _root_certificate(private_key: rsa.RSAPrivateKey, generated_at: datetime) -> x509.Certificate:
    """Construit le certificat auto-signe de la racine (``ca=True``)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PurIdentityServer credential CA")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=CREDENTIAL_CA_LIFETIME_DAYS))
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
    private_key: rsa.RSAPrivateKey,
    root_certificate: x509.Certificate,
    root_key: rsa.RSAPrivateKey,
    generated_at: datetime,
) -> x509.Certificate:
    """Construit le certificat leaf emis par la racine (signature ``RS256``)."""
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "PurIdentityServer credential signer")]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(root_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(generated_at - timedelta(minutes=5))
        .not_valid_after(generated_at + timedelta(days=CREDENTIAL_LEAF_LIFETIME_DAYS))
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
            # certificat : la cle est toujours signable (sous-ensemble
            # CertificateIssuerPublicKeyTypes, cf. mdoc.py)
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cast(CertificateIssuerPublicKeyTypes, root_certificate.public_key())
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )


def _load_rsa_private(pem: str) -> rsa.RSAPrivateKey:
    """Charge une cle privee RSA depuis son PEM ; ``ValueError`` sinon."""
    key = load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("cle privee credential non RSA")
    return key


def _require_str(data: dict[str, Any], key: str) -> str:
    """Exige un champ textuel dans les donnees persistees."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"champ {key} manquant ou non textuel")
    return value


def _pem_private(private_key: rsa.RSAPrivateKey) -> str:
    """Serialise une cle privee RSA en PEM PKCS#8."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.decode("ascii")


def _pem_cert(certificate: x509.Certificate) -> str:
    """Serialise un certificat X.509 en PEM."""
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    return pem.decode("ascii")
