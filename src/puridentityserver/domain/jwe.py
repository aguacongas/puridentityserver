"""Entités du chiffrement de jetons JWE (RFC 7516 — JSON Web Encryption).

Le domaine ne contient ici que des entités pures, sans dépendance vers
une bibliothèque cryptographique : les algorithmes de gestion de clé
(RFC 7518 §4) et les méthodes de chiffrement de contenu (RFC 7518 §5)
sont déclarés en énumérations, avec les tailles de clés associées.
La construction/déchiffrement du JWE compact (RFC 7516 §7.1) vit dans
l'infrastructure (``cryptography``).
"""

from __future__ import annotations

from enum import Enum


class JWEKeyManagementAlgorithm(str, Enum):
    """Algorithmes de gestion de la clé de chiffrement (JWA RFC 7518 §4).

    ``RSA-OAEP`` / ``RSA-OAEP-256`` chiffrent la CEK avec la clé publique
    RSA du client (JWK ``kty = RSA`` enregistrée à la registration) ;
    ``A128KW`` / ``A256KW`` enveloppent une CEK aléatoire avec une clé
    symétrique dérivée du secret partagé du client (RFC 3394) ; ``dir``
    utilise directement la clé dérivée comme clé de contenu (RFC 7518
    §4.5).
    """

    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"
    A128KW = "A128KW"
    A256KW = "A256KW"
    DIRECT = "dir"


class JWEEncryptionMethod(str, Enum):
    """Méthodes de chiffrement de contenu supportées (JWA RFC 7518 §5).

    ``A*CBC-HS*`` (RFC 7518 §5.2) et ``A*GCM`` (RFC 7518 §5.3) sont les
    algorithmes ``enc`` exigibles d'un id_token chiffré (OIDC Core 1.0
    §16, « Encryption »).
    """

    A128CBC_HS256 = "A128CBC-HS256"
    A192CBC_HS384 = "A192CBC-HS384"
    A256CBC_HS512 = "A256CBC-HS512"
    A128GCM = "A128GCM"
    A192GCM = "A192GCM"
    A256GCM = "A256GCM"

    @property
    def cek_size(self) -> int:
        """Taille de la clé de chiffrement du contenu (CEK), en octets."""
        return {
            JWEEncryptionMethod.A128CBC_HS256: 32,
            JWEEncryptionMethod.A192CBC_HS384: 48,
            JWEEncryptionMethod.A256CBC_HS512: 64,
            JWEEncryptionMethod.A128GCM: 16,
            JWEEncryptionMethod.A192GCM: 24,
            JWEEncryptionMethod.A256GCM: 32,
        }[self]


ASYMMETRIC_ENCRYPTION_ALGORITHMS: tuple[JWEKeyManagementAlgorithm, ...] = (
    JWEKeyManagementAlgorithm.RSA_OAEP,
    JWEKeyManagementAlgorithm.RSA_OAEP_256,
)

SYMMETRIC_ENCRYPTION_ALGORITHMS: tuple[JWEKeyManagementAlgorithm, ...] = (
    JWEKeyManagementAlgorithm.A128KW,
    JWEKeyManagementAlgorithm.A256KW,
    JWEKeyManagementAlgorithm.DIRECT,
)

ALL_ENCRYPTION_ALGORITHMS: tuple[JWEKeyManagementAlgorithm, ...] = tuple(JWEKeyManagementAlgorithm)

ALL_ENCRYPTION_METHODS: tuple[JWEEncryptionMethod, ...] = tuple(JWEEncryptionMethod)

CBC_ENCRYPTION_METHODS: tuple[JWEEncryptionMethod, ...] = (
    JWEEncryptionMethod.A128CBC_HS256,
    JWEEncryptionMethod.A192CBC_HS384,
    JWEEncryptionMethod.A256CBC_HS512,
)

GCM_ENCRYPTION_METHODS: tuple[JWEEncryptionMethod, ...] = (
    JWEEncryptionMethod.A128GCM,
    JWEEncryptionMethod.A192GCM,
    JWEEncryptionMethod.A256GCM,
)

# Méthode de chiffrement par défaut, appliquée quand le client configure
# un algorithme de gestion de clé sans préciser ``enc`` (OIDC Core 1.0
# §3.1.3.6 : "enc" est requis, sa valeur par défaut n'étant pas définie —
# A128CBC-HS256 est la valeur recommandée par la spec).
DEFAULT_ENCRYPTION_METHOD = JWEEncryptionMethod.A128CBC_HS256
