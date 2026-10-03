"""Entités du périmètre DPoP (RFC 9449 — Proof-of-Possession de jeton).

Le domaine ne contient que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Le port de validation vit dans
``interfaces/domain/dpop.py``, le port anti-replay dans
``interfaces/repositories/`` et les implémentations dans
l'infrastructure.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

#: Type MIME JWT d'une preuve DPoP (RFC 9449 §4.2, en-tête ``typ``).
DPOP_PROOF_TYPE = "dpop+jwt"

#: Type MIME de la ``DPoP-Nonce`` émise par le serveur (RFC 9449 §8).
DPOP_NONCE_TYPE = "DPoP-Nonce"

#: Fenêtre d'acceptation de l'``iat`` d'une preuve, de part et d'autre
#: de l'horloge serveur (RFC 9449 §11.1 : « écart raisonnable » — la
#: suite de certification rejette au-delà de 5 minutes).
DPOP_IAT_SKEW_SECONDS = 300

#: Délai maximal entre l'émission d'une preuve et son expiration
#: accepté par le serveur (le ``exp`` est optionnel, RFC 9449 §4.2).
DPOP_MAX_LIFETIME_SECONDS = 50 * 365 * 24 * 3600


@dataclass(frozen=True, slots=True)
class DPoPProof:
    """Preuve DPoP validée (RFC 9449 §4.2) : clé et claims normalisés.

    ``jkt`` est l'empreinte RFC 7638 (SHA-256) de la clé publique de
    l'en-tête ``jwk`` — la « proof-of-possession key thumbprint » liant
    le jeton à la clé. ``jti`` est l'identifiant unique de la preuve
    (rejeté en cas de rejeu, §11). ``htm`` / ``htu`` décrivent la
    requête HTTP que la preuve autorise (§4.3).
    """

    jkt: str
    jti: str
    htm: str
    htu: str
    nonce: str = ""


@dataclass(frozen=True, slots=True)
class DPoPReplay:
    """Entrée anti-replay du store des ``jti`` (RFC 9449 §11).

    Seule l'empreinte SHA-256 du ``jti`` est persistée (jamais le ``jti``
    en clair), avec la date à laquelle l'entrée peut être purgée —
    ``expires_at`` déborde volontairement l'expiration de la preuve pour
    couvrir toute la fenêtre d'``iat`` encore acceptée.
    """

    jti_hash: str
    expires_at: datetime
    seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def jti_hash(jti: str) -> str:
    """Empreinte SHA-256 (hexadécimale) d'un ``jti`` de preuve DPoP.

    Le ``jti`` n'est jamais conservé en clair en persistance (défense en
    profondeur identique au denylist, RFC 7009).
    """
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def access_token_hash(token: str) -> str:
    """Empreinte ``ath`` d'un access token (RFC 9449 §4.3).

    base64url sans padding du digest SHA-256 du jeton : c'est la valeur
    que le claim ``ath`` d'une preuve présentée à un resource server
    doit reproduire pour lier la preuve au jeton présenté.
    """
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
