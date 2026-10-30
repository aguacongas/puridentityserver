"""Stockage persistant de la PKI mdoc (IACA + document signer)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from puridentityserver.infrastructure.mdoc import MdocIssuerPKI

_LOGGER = logging.getLogger(__name__)


class MdocPKIRepository(Protocol):
    """Contrat de persistance minimal pour la PKI mdoc."""

    def load(self) -> MdocIssuerPKI | None:
        """Charge la PKI persistee, ou ``None`` si rien/donnee invalide."""

    def save(self, pki: MdocIssuerPKI) -> None:
        """Persiste la PKI."""


class InMemoryMdocPKIRepository:
    """Depot en memoire (tests / defaut ephemere)."""

    def __init__(self) -> None:
        """Initialise le depot vide."""
        self._pki: MdocIssuerPKI | None = None

    def load(self) -> MdocIssuerPKI | None:
        """Rend la PKI en memoire, si elle a ete sauvegardee."""
        return self._pki

    def save(self, pki: MdocIssuerPKI) -> None:
        """Memorise la PKI en memoire."""
        self._pki = pki


class FileMdocPKIRepository:
    """Depot fichier (JSON de PEM)."""

    def __init__(self, path: str | Path) -> None:
        """Stocke le chemin du fichier persistant."""
        self._path = Path(path)

    def load(self) -> MdocIssuerPKI | None:
        """Charge la PKI depuis le fichier ; ``None`` si absent/invalide."""
        if not self._path.is_file():
            return None
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError, ValueError):
            _LOGGER.warning("PKI mdoc illisible sur %s, regeneration", self._path)
            return None
        if not isinstance(data, dict):
            return None
        try:
            issuer_key = load_pem_private_key(
                _require_str(data, "issuer_key_pem").encode("ascii"),
                password=None,
            )
            signer_key = load_pem_private_key(
                _require_str(data, "signer_key_pem").encode("ascii"),
                password=None,
            )
            if not isinstance(issuer_key, ec.EllipticCurvePrivateKey) or not isinstance(
                signer_key, ec.EllipticCurvePrivateKey
            ):
                _LOGGER.warning("PKI mdoc : cles non EC sur %s, regeneration", self._path)
                return None
            issuer_cert = x509.load_pem_x509_certificate(
                _require_str(data, "issuer_cert_pem").encode("ascii")
            )
            signer_cert = x509.load_pem_x509_certificate(
                _require_str(data, "signer_cert_pem").encode("ascii")
            )
        except (ValueError, TypeError):
            _LOGGER.warning("PKI mdoc invalide sur %s, regeneration", self._path)
            return None
        return MdocIssuerPKI(
            issuer_private_key=issuer_key,
            issuer_certificate=issuer_cert,
            signer_private_key=signer_key,
            signer_certificate=signer_cert,
        )

    def save(self, pki: MdocIssuerPKI) -> None:
        """Persiste la PKI en JSON (PEM) dans le fichier."""
        data: dict[str, Any] = {
            "issuer_key_pem": _pem_private(pki.issuer_private_key),
            "issuer_cert_pem": _pem_cert(pki.issuer_certificate),
            "signer_key_pem": _pem_private(pki.signer_private_key),
            "signer_cert_pem": _pem_cert(pki.signer_certificate),
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            _LOGGER.warning("Impossible de persister la PKI mdoc sur %s", self._path)


def _require_str(data: dict[str, Any], key: str) -> str:
    """Exige un champ textuel dans les donnees persistees."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"champ {key} manquant ou non textuel")
    return value


def _pem_private(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Serialise une cle privee EC en PEM PKCS#8."""
    raw = cast(
        bytes,
        private_key.private_bytes(  # type: ignore[attr-defined]
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    return raw.decode("ascii")


def _pem_cert(certificate: x509.Certificate) -> str:
    """Serialise un certificat X509 en PEM."""
    return certificate.public_bytes(
        cast(serialization.Encoding, serialization.Encoding.PEM)
    ).decode("ascii")
