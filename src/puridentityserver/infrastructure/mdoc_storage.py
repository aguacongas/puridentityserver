"""Stockage persistant de la PKI mdoc (IACA seule, document signer minté au boot)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from puridentityserver.infrastructure.mdoc import MdocIaca

_LOGGER = logging.getLogger(__name__)


class MdocPKIRepository(Protocol):
    """Contrat de persistance minimal pour l'IACA mdoc."""

    def load(self) -> MdocIaca | None:
        """Charge l'IACA persistee, ou ``None`` si rien/donnee invalide."""

    def save(self, iaca: MdocIaca) -> None:
        """Persiste l'IACA."""


class InMemoryMdocPKIRepository:
    """Depot en memoire (tests / defaut ephemere)."""

    def __init__(self) -> None:
        """Initialise le depot vide."""
        self._iaca: MdocIaca | None = None

    def load(self) -> MdocIaca | None:
        """Rend l'IACA en memoire, si elle a ete sauvegardee."""
        return self._iaca

    def save(self, iaca: MdocIaca) -> None:
        """Memorise l'IACA en memoire."""
        self._iaca = iaca


class FileMdocPKIRepository:
    """Depot fichier (JSON de PEM) : les seuls champs IACA sont lus et ecrits.

    Un depot ancien au format 4 champs (IACA + document signer) reste
    chargeable : ses deux champs d'IACA sont les seuls consultes, le
    document signer etant reminté a chaque demarrage.
    """

    def __init__(self, path: str | Path) -> None:
        """Stocke le chemin du fichier persistant."""
        self._path = Path(path)

    def load(self) -> MdocIaca | None:
        """Charge l'IACA depuis le fichier ; ``None`` si absente/invalide."""
        if not self._path.is_file():
            return None
        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError):
            _LOGGER.warning("IACA mdoc illisible sur %s, regeneration", self._path)
            return None
        if not isinstance(data, dict):
            return None
        try:
            issuer_key = load_pem_private_key(
                _require_str(data, "issuer_key_pem").encode("ascii"),
                password=None,
            )
            if not isinstance(issuer_key, ec.EllipticCurvePrivateKey):
                _LOGGER.warning("IACA mdoc : cle non EC sur %s, regeneration", self._path)
                return None
            issuer_cert = x509.load_pem_x509_certificate(
                _require_str(data, "issuer_cert_pem").encode("ascii")
            )
        except (ValueError, TypeError):
            _LOGGER.warning("IACA mdoc invalide sur %s, regeneration", self._path)
            return None
        return MdocIaca(private_key=issuer_key, certificate=issuer_cert)

    def save(self, iaca: MdocIaca) -> None:
        """Persiste l'IACA en JSON (PEM) dans le fichier."""
        data: dict[str, Any] = {
            "issuer_key_pem": _pem_private(iaca.private_key),
            "issuer_cert_pem": _pem_cert(iaca.certificate),
        }
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            _LOGGER.warning("Impossible de persister l'IACA mdoc sur %s", self._path)


def _require_str(data: dict[str, Any], key: str) -> str:
    """Exige un champ textuel dans les donnees persistees."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"champ {key} manquant ou non textuel")
    return value


def _pem_private(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Serialise une cle privee EC en PEM PKCS#8."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw.decode("ascii")


def _pem_cert(certificate: x509.Certificate) -> str:
    """Serialise un certificat X509 en PEM."""
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
