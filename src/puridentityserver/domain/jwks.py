"""Entités du périmètre des clés JWT (RFC 7517 — JSON Web Key).

Les interfaces (ports) associées vivent dans ``interfaces/domain`` ;
le domaine ne contient ici que des entités pures, sans aucune dépendance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class KeyType(str, Enum):
    """Famille de clé cryptographique publiée dans un JWK (RFC 7518 §6)."""

    RSA = "RSA"
    EC = "EC"
    OCT = "oct"


class KeyUse(str, Enum):
    """Usage de la paire de clés (RFC 7517 §4.2).

    ``sig``    : signature des tokens OIDC (id_token / access_token),
                 clé publique exposée dans le JWKS.
    ``session``: signature des cookies de session navigateur, jamais
                 publiée — seule le serveur la valide.
    ``reset``  : signature des jetons de réinitialisation de mot de
                 passe (emails), jamais publiée.
    ``verify`` : signature des jetons de vérification de compte
                 (emails), jamais publiée.
    ``secret`` : chiffrement au repos des secrets clients HMAC
                 (``client_secret_jwt``), jamais publiée. Mise en rotation
                 automatiquement mais **jamais purgée** : un secret est
                 chiffré à vie dans le registre, l'ancienne clé doit
                 rester le temps du drain avant retrait manuel.
    """

    SIG = "sig"
    SESSION = "session"
    RESET = "reset"
    VERIFY = "verify"
    SECRET = "secret"  # ruff: ignore[hardcoded-password-string] — valeur de persistance de l'enum, pas un vrai mot de passe


class JWTAlgorithm(str, Enum):
    """Algorithmes de signature supportés (JWA RFC 7518).

    Les familles asymétriques (RS*/PS*/ES*) reposent sur des paires de
    clés générées par le serveur et publiées dans le JWKS ; la famille
    symétrique (HS*) signe l'``id_token`` avec le **secret partagé du
    client** (OIDC Core 1.0 §3.1.3.7) — aucune clé de serveur n'est
    générée ni publiée pour HS*.
    """

    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"

    @property
    def key_type(self) -> KeyType:
        """Type de clé JWK (``kty``) associé à l'algorithme."""
        if self in (
            JWTAlgorithm.RS256,
            JWTAlgorithm.RS384,
            JWTAlgorithm.RS512,
            JWTAlgorithm.PS256,
            JWTAlgorithm.PS384,
            JWTAlgorithm.PS512,
        ):
            return KeyType.RSA
        if self in (
            JWTAlgorithm.HS256,
            JWTAlgorithm.HS384,
            JWTAlgorithm.HS512,
        ):
            return KeyType.OCT
        return KeyType.EC

    @property
    def curve(self) -> str:
        """Courbe JWK (``crv``), vide pour les clés RSA et HMAC."""
        return {
            JWTAlgorithm.ES256: "P-256",
            JWTAlgorithm.ES384: "P-384",
            JWTAlgorithm.ES512: "P-521",
        }.get(self, "")


ASYMMETRIC_ALGORITHMS: tuple[JWTAlgorithm, ...] = (
    JWTAlgorithm.RS256,
    JWTAlgorithm.RS384,
    JWTAlgorithm.RS512,
    JWTAlgorithm.PS256,
    JWTAlgorithm.PS384,
    JWTAlgorithm.PS512,
    JWTAlgorithm.ES256,
    JWTAlgorithm.ES384,
    JWTAlgorithm.ES512,
)

SYMMETRIC_ALGORITHMS: tuple[JWTAlgorithm, ...] = (
    JWTAlgorithm.HS256,
    JWTAlgorithm.HS384,
    JWTAlgorithm.HS512,
)


ALL_SIGNING_ALGORITHMS: tuple[JWTAlgorithm, ...] = tuple(JWTAlgorithm)


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Paire de clés pour la signature JWT, quel que soit l'algorithme.

    Les clés sont stockées au format PEM (texte) pour rester indépendantes
    de toute bibliothèque cryptographique dans le domaine.
    """

    algorithm: JWTAlgorithm
    use: KeyUse = KeyUse.SIG
    kid: str = field(default_factory=lambda: f"{uuid4().hex[:12]}")
    private_key_pem: str = ""
    public_key_pem: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
