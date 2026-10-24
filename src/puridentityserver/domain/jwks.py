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
    ``enc``    : chiffrement des request objects présentés à l'OP (OIDC
                 Core 1.0 §10.1, issue #204) — la clé privée ne quitte
                 jamais le serveur, la clé publique RSA est publiée au
                 JWKS OIDC et dans le ``jwks`` de l'entity statement
                 fédéré, seules sources où un RP puisse lire le matériel
                 de chiffrement.
    ``federation``: signature des entity statements et des chaînes de
                 confiance (OpenID Federation 1.1 §2.1, §3) — jamais
                 publiée au JWKS OIDC, la spec recommandant que ces clés
                 ne servent à aucun autre protocole.
    """

    SIG = "sig"
    SESSION = "session"
    RESET = "reset"
    VERIFY = "verify"
    ENC = "enc"
    SECRET = "secret"  # ruff: ignore[hardcoded-password-string] - valeur de persistance de l'enum, pas un vrai mot de passe
    # `federation` : signature des entity statements et de la chaîne de
    # confiance (OpenID Federation 1.1 §2.1, §3). Ces clés sont distinctes
    # des clés de signature OIDC : la spec recommande qu'elles ne servent
    # à aucun autre protocole.
    FEDERATION = "federation"


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
    #: JWA RFC 7519 §6 : en-tête seul, **aucune** signature — c'est
    #: l'algorithme que porte un client inscrit avec
    #: ``id_token_signed_response_alg=none``.
    NONE = "none"

    @property
    def key_type(self) -> KeyType:
        """Type de clé JWK (``kty``) associé à l'algorithme.

        ``none`` ne porte aucune clé : la propriété le signale plutôt que de
        renvoyer un type erroné (une paire ``none`` serait invalide au JWKS).
        """
        if self is JWTAlgorithm.NONE:
            raise ValueError("alg=none (JWA RFC 7519 §6) ne porte aucune clé de signature")
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


#: Algorithmes **signants** : toutes les valeurs de l'enum sauf ``none``, qui
#: ne possède aucune clé — la générer (paires serveur, JWKS, discovery) n'a
#: aucun sens et planterait la dérive de clé par ``key_type``.
ALL_SIGNING_ALGORITHMS: tuple[JWTAlgorithm, ...] = tuple(
    algorithm for algorithm in JWTAlgorithm if algorithm is not JWTAlgorithm.NONE
)

#: Algorithmes admis pour un ``request`` signé au backchannel authentication
#: endpoint (OIDC CIBA 1.0 §7.1.1) : ``PS256`` exigé par FAPI-CIBA-ID1,
#: ``ES256``/``RS256`` complémentaires. Publiés au discovery sous
#: ``backchannel_authentication_request_signing_alg_values_supported`` et
#: contrôlés à l'enregistrement (DCR) comme à la vérification.
CIBA_REQUEST_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.ES256.value,
    JWTAlgorithm.RS256.value,
)

#: Algorithmes JWS admis pour signer une preuve DPoP (RFC 9449 §4.2) : les
#: familles PSS (``PS*``) et ECDSA (``ES*``) uniquement. La famille RS*
#: (PKCS#1 v1.5) est refusée : la suite Certification FAPI2 l'attend
#: (module ``dpop-negative-tests``, cas « DPoP proof signed using RS256 »,
#: FAPI2-SP-FINAL-5.4). ``none`` et les familles symétriques HS* restent
#: interdits par la RFC. Publiés au discovery sous
#: ``dpop_signing_alg_values_supported`` et contrôlés à la validation de
#: chaque preuve.
DPOP_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.PS384.value,
    JWTAlgorithm.PS512.value,
    JWTAlgorithm.ES256.value,
    JWTAlgorithm.ES384.value,
    JWTAlgorithm.ES512.value,
)

#: Algorithmes JWS admis pour l'enveloppe JARM (``response_mode=jwt``,
#: JARM Final 1.0 §4.1) : ``PS256``/``ES256`` exigés par les profils FAPI,
#: ``RS256`` admis pour les clients standards. Familles symétriques HS* et
#: ``none`` exclus — la réponse d'autorisation est signée par l'OP avec sa
#: propre clé. Publiés au discovery sous
#: ``authorization_signing_alg_values_supported`` et contrôlés à la
#: validation de la demande portant ``response_mode=jwt``.
JARM_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.ES256.value,
    JWTAlgorithm.RS256.value,
)

#: Algorithmes JWS admis pour signer la réponse UserInfo en ``application/jwt``
#: (OIDC Core 1.0 §5.3.2) : ``PS256``/``ES256`` exigés par les profils FAPI
#: (module ``FAPICheckDiscEndpointUserinfoSigningAlgValuesSupported`` — au
#: moins un des deux exigé dès que le champ est publié), ``RS256`` admis pour
#: les clients standards. Signée par l'OP avec sa propre clé (``kid`` inclus).
#: Familles symétriques HS* et ``none`` exclus. Publiés au discovery sous
#: ``userinfo_signing_alg_values_supported`` et contrôlés à l'enregistrement
#: (``userinfo_signed_response_alg``, OIDC Registration 1.0 §2.1) — sans
#: déclaration du client, la réponse reste en JSON non signé.
USERINFO_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.ES256.value,
    JWTAlgorithm.RS256.value,
)


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
