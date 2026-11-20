"""Cas d'usage de l'issuance OpenID4VCI (slice 1, issue #172/#222)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.application.authorization_details import (
    CREDENTIAL_CONFIGURATION_ID,
    MDOC_CREDENTIAL_CONFIGURATION_ID,
    SUPPORTED_CREDENTIAL_CONFIGURATION_IDS,
    credential_configuration_for_identifier,
    has_authorization_details,
)
from puridentityserver.domain.authorization import AuthorizationCode, Scope
from puridentityserver.domain.credential_offer import (
    CREDENTIAL_OFFER_TTL,
    TX_CODE_LENGTH,
    CredentialOffer,
    credential_offer_payload,
)
from puridentityserver.domain.dpop import access_token_hash
from puridentityserver.domain.jwe import ECDH_ES, JWEEncryptionMethod
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.domain.revocation import token_hash
from puridentityserver.infrastructure.credential_pki import CredentialPKIRepository
from puridentityserver.infrastructure.dpop import jwk_thumbprint
from puridentityserver.infrastructure.jwe import (
    decrypt_compact_ecdh_es,
    ec_jwk,
    ec_public_key,
    encrypt_compact_ecdh_es,
    protected_header,
)
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.infrastructure.mdoc import (
    MDL_MANDATORY_ELEMENTS,
    MdocBindingError,
    MdocIssuerPKI,
    generate_mdoc_iaca,
    generate_mdoc_pki,
)
from puridentityserver.infrastructure.mdoc_storage import MdocPKIRepository
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.credential_offer_repository import (
    CredentialOfferRepository,
)
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse

#: Identifiant de la configuration de credential publiée par l'OP.
#: Réexporté depuis ``application.authorization_details`` (source unique).

#: Chemin du type de credential publié par l'OP (SD-JWT VC). Le ``vct`` du
#: credential et l'URL de sa Type Metadata (SD-JWT VC §6.3.1) en dérivent.
CREDENTIAL_VCT_PATH = "/credentials/example"

#: Type JOSE de l'en-tête d'un SD-JWT VC (SD-JWT VC §3.2.1).
SD_JWT_VC_TYP = "dc+sd-jwt"

#: Format mdoc (ISO 18013-5) accepté dans une requête de credential.
MDOC_FORMAT = "mso_mdoc"

#: DocType du mdoc émis par l'OP (ISO 18013-5 §9.1.2.1).
MDOC_DOCTYPE = "org.iso.18013.5.1.mDL"

#: Type JOSE d'une réponse de métadonnées signées (OID4VCI 1.0 §12.2.2).
ISSUER_METADATA_TYP = "openidvci-issuer-metadata+jwt"

#: Formats de credential acceptés dans une requête (SD-JWT VC et mdoc).
CREDENTIAL_FORMATS = frozenset({SD_JWT_VC_TYP, "vc+sd-jwt", MDOC_FORMAT})

#: En-têtes ``typ`` admis pour une preuve JWT (OID4VCI 1.0 §7.1).
PROOF_TYPES = frozenset({"openid4vci-proof+jwt", "jwt"})

#: Algorithmes de preuve annoncés dans la metadata de l'émetteur.
PROOF_ALGORITHMS = frozenset({"ES256", "RS256"})

#: Type JOSE d'un ``c_nonce`` signé par l'OP.
C_NONCE_TYP = "c_nonce+jwt"

#: Durée de vie d'un ``c_nonce``, en secondes (OID4VCI 1.0 §7).
C_NONCE_LIFETIME = 300


def credential_vct(issuer: str) -> str:
    """URL absolue du ``vct`` publié pour le credential de démonstration."""
    return f"{issuer.rstrip('/')}{CREDENTIAL_VCT_PATH}"


#: Valeurs de ``enc`` publiées, A256GCM en tête : émetteur et wallet
#: (suite OIDF) retiennent l'élément ``[0]`` par défaut (OID4VCI s8.2).
ENC_VALUES_SUPPORTED: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            JWEEncryptionMethod.A256GCM.value,
            *(method.value for method in JWEEncryptionMethod),
        )
    )
)
#: Algorithmes de gestion de clé asymétriques publiés (OID4VCI s12.2.4) :
#: seul ECDH-ES en mode Direct Key Agreement sert au chiffrement des
#: credential requests/réponses.
ALG_VALUES_SUPPORTED: tuple[str, ...] = (ECDH_ES,)
#: Seul ``DEF`` est enregistré comme algorithme de compression (RFC 7516 s4.1.3).
ZIP_VALUES_SUPPORTED: tuple[str, ...] = ("DEF",)
#: Taille de clé demandée au store pour la famille ``KeyUse.CREDENTIAL`` :
#: ignorée pour ES256 (courbe fixée à P-256), requise par le contrat
#: ``KeyManager.generate_key_pair``. Partagée avec la rotation au
#: démarrage (composition root).
CREDENTIAL_KEY_SIZE = 256


def _try_decrypt(token: str, private_key: EllipticCurvePrivateKey) -> bytes | None:
    """Tente le déchiffrement avec une clé candidate, ou ``None``.

    ``ValueError`` (mauvaise clé, contenu altéré) est absorbé : chaque
    clé du trousseau est essayée à son tour par ``_decrypt_with_any_key``.
    """
    try:
        return decrypt_compact_ecdh_es(token, private_key=private_key)
    except (TypeError, ValueError):
        return None


def _decrypt_with_any_key(
    token: str, header: dict[str, Any], keys: dict[str, EllipticCurvePrivateKey]
) -> bytes | None:
    """Déchiffre ``token`` avec la clé vivante adaptée, ou ``None``.

    La clé déclarée dans le ``kid`` de l'en-tête (RFC 7518 s4.5) est
    essayée en premier ; à défaut de correspondance — wallet ayant mis en
    cache une clé antérieure à la rotation (issue #310) — chaque clé
    vivante du trousseau est essayée à son tour.
    """
    kid = header.get("kid")
    candidates = list(keys.items())
    if isinstance(kid, str) and kid in keys:
        candidates.sort(key=lambda item: item[0] != kid)  # le kid déclaré en tête
    for _, private_key in candidates:
        plaintext = _try_decrypt(token, private_key)
        if plaintext is not None:
            return plaintext
    return None


def _encryption_metadata_blocks(encryption_jwks: list[dict[str, Any]]) -> dict[str, Any]:
    """Blocs d'encryption des métadonnées émetteur (OID4VCI 1.0 s12.2.4).

    ``credential_request_encryption`` porte le ``jwks`` de l'émetteur (une
    clé publique ``use = enc`` portant ``kid`` et ``alg``, exigés par la
    suite OIDF, par clé vivante de la famille ``KeyUse.CREDENTIAL`` : la
    plus récente d'abord, les anciennes encore en drain derrière) ;
    ``credential_response_encryption`` porte les ``alg_values_supported``
    asymétriques exigés côté wallet.
    ``encryption_required = false`` : le chiffrement reste optionnel.
    """
    return {
        "credential_request_encryption": {
            "jwks": {"keys": encryption_jwks},
            "enc_values_supported": list(ENC_VALUES_SUPPORTED),
            "encryption_required": False,
            "zip_values_supported": list(ZIP_VALUES_SUPPORTED),
        },
        "credential_response_encryption": {
            "alg_values_supported": list(ALG_VALUES_SUPPORTED),
            "enc_values_supported": list(ENC_VALUES_SUPPORTED),
            "encryption_required": False,
            "zip_values_supported": list(ZIP_VALUES_SUPPORTED),
        },
    }


def issuer_metadata_payload(
    issuer: str, *, encryption_jwks: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Construit le document de métadonnées de l'émetteur OID4VCI (non signé).

    Args:
        issuer: URL de l'émetteur.
        encryption_jwks: clés publiques EC P-256 de chiffrement à publier,
            la plus récente d'abord ; ``None`` (défaut) omet les blocs
            d'encryption — capability non annoncée.

    Returns:
        Le document de métadonnées, augmenté des blocs
        ``credential_request_encryption`` / ``credential_response_encryption``
        quand ``encryption_jwks`` est fourni (OID4VCI 1.0 s12.2.4).
    """
    normalized = issuer.rstrip("/")
    payload: dict[str, Any] = {
        "credential_issuer": normalized,
        "authorization_servers": [normalized],
        "credential_endpoint": f"{normalized}/credential",
        "nonce_endpoint": f"{normalized}/nonce",
        "credential_configurations_supported": {
            CREDENTIAL_CONFIGURATION_ID: {
                "format": SD_JWT_VC_TYP,
                "scope": "openid4vci",
                "vct": credential_vct(normalized),
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["RS256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256", "RS256"],
                    },
                    "attestation": {
                        "proof_signing_alg_values_supported": ["ES256", "RS256"],
                        "key_attestations_required": {},
                    },
                },
            },
            MDOC_CREDENTIAL_CONFIGURATION_ID: {
                "format": MDOC_FORMAT,
                "scope": "openid4vci",
                "doctype": MDOC_DOCTYPE,
                "cryptographic_binding_methods_supported": ["cose_key"],
                "credential_signing_alg_values_supported": [-7],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"],
                    },
                    "attestation": {
                        "proof_signing_alg_values_supported": ["ES256"],
                        "key_attestations_required": {},
                    },
                },
            },
        },
        "batch_credential_issuance": {"batch_size": 5},
        "deferred_credential_endpoint": f"{normalized}/deferred_credential",
        "notification_endpoint": f"{normalized}/notification",
    }
    if encryption_jwks is not None:
        payload.update(_encryption_metadata_blocks(encryption_jwks))
    return payload


@dataclass(frozen=True)
class CredentialError:
    """Erreur OID4VCI typée, rendue telle quelle par ``/credential``.

    Les codes suivent OID4VCI 1.0 §8.3.1 : ``invalid_proof`` et
    ``invalid_nonce`` pour les preuves, ``unknown_credential_configuration`` et
    ``unknown_credential_identifier`` pour une cible inconnue. Seul un défaut
    de jeton reste en 401, tout le reste est un 400.
    """

    error: str
    error_description: str
    status_code: int = 400


@dataclass(frozen=True)
class CredentialResponseEncryption:
    """Chiffrement de réponse demandé par le wallet (OID4VCI 1.0 s8.2).

    ``kid`` reprend le ``kid`` du jwk du wallet (le déchiffreur côté wallet
    sélectionne la clé par ``alg`` + ``kid``) ; ``compress`` signale le
    ``zip = DEF`` demandé, qui doit figurer dans l'en-tête de la réponse.
    """

    public_key: EllipticCurvePublicKey
    method: JWEEncryptionMethod
    kid: str = ""
    compress: bool = False


def _invalid_encryption(description: str) -> CredentialError:
    """Erreur ``invalid_encryption_parameters`` (OID4VCI 1.0 s8.3.1)."""
    return CredentialError("invalid_encryption_parameters", description)


def _request_encryption_header_error(header: dict[str, Any]) -> str | None:
    """Vérifie l'en-tête JWE d'une requête chiffrée contre la capability publiée.

    Returns:
        Le message de refus (opposé en ``invalid_encryption_parameters``),
        ou ``None`` quand l'en-tête est dans la capability.
    """
    if header.get("alg") != ECDH_ES:
        return "algorithme de gestion de clé non supporté"
    if header.get("enc") not in ENC_VALUES_SUPPORTED:
        return "méthode de chiffrement non supportée"
    zip_value = header.get("zip")
    if zip_value is not None and zip_value != "DEF":
        return "algorithme de compression non supporté"
    return None


def _response_encryption_method(
    value: object,
) -> tuple[JWEEncryptionMethod, CredentialError | None]:
    """Résout la méthode ``enc`` demandée, ou oppose l'erreur de capability.

    Sans ``enc``, la première valeur publiée (A256GCM) s'applique, comme
    le retient la suite OIDF.
    """
    if value is None:
        return (JWEEncryptionMethod.A256GCM, None)
    if not isinstance(value, str) or value not in ENC_VALUES_SUPPORTED:
        return (JWEEncryptionMethod.A256GCM, _invalid_encryption(f"enc non supporté : {value}"))
    return (JWEEncryptionMethod(value), None)


# Message d erreur d access token invalide, partage.
INVALID_ACCESS_TOKEN_ERROR = "access token invalide, expire ou non autorise"  # ruff: ignore[hardcoded-password-string]
#: Erreur opposée à un access token figure sur la denylist (RFC 6749 §5.2).
REVOKED_ACCESS_TOKEN_ERROR = "access token revoque"  # ruff: ignore[hardcoded-password-string]


async def access_token_revoked(repository: RevokedTokenRepository | None, token: str) -> bool:
    """Signale un access token placé sur la denylist (RFC 6749 §5.2).

    Sans dépôt injecté, la denylist est inactive et le jeton n'est jamais
    considéré révoqué. L'empreinte ``SHA-256`` du jeton est calculée ici
    (``token_hash``), jamais le jeton en clair.
    """
    if repository is None:
        return False
    return await repository.is_revoked(token_hash(token))


@dataclass(frozen=True)
class _SdJwtSigningMaterial:
    """Matériel de signature d'un credential SD-JWT (clé, alg, en-têtes)."""

    private_key: Any
    algorithm: str
    headers: dict[str, Any]


class OID4VCIIssuerUseCase:
    """Émet un credential verifiable (SD-JWT VC ou mdoc) pour l'OP.

    La preuve de possession (``proofs.jwt``) est obligatoire : la configuration
    publiée annonce ``cryptographic_binding_methods_supported``, donc une
    requête sans preuve est refusée (OID4VCI 1.0 §8.2). La liaison DPoP de
    l'access token est vérifiée de la même façon (RFC 9449 §7.1).

    Deux formats sont émis selon la configuration demandée : ``dc+sd-jwt``
    (défaut) et ``mso_mdoc`` (ISO 18013-5), dont la PKI (IACA + document
    signer) est générée à la volée à l'instanciation.
    """

    def __init__(
        self,
        *,
        issuer: str,
        key_manager: DefaultKeyManager,
        algorithm: JWTAlgorithm,
        token_manager: TokenManager,
        dpop: DpopProofValidator | None = None,
        mdoc_pki_repository: MdocPKIRepository | None = None,
        credential_pki_repository: CredentialPKIRepository | None = None,
        revoked_tokens: RevokedTokenRepository | None = None,
        encryption_enabled: bool = False,
        encryption_key_manager: DefaultKeyManager | None = None,
    ) -> None:
        """Initialise l'émetteur et mémorise les dépendances cryptographiques.

        ``encryption_enabled`` active la capability de chiffrement des
        credential requests/réponses (OID4VCI s8.2) ; les clés EC P-256 de
        la famille ``KeyUse.CREDENTIAL`` sont alors provisionnées à la
        première usage dans ``encryption_key_manager`` (store ``key_pair``
        partagé, load balancing), mises en rotation au démarrage selon
        ``jwks_rotation_days`` (issue #310).
        """
        self._issuer = issuer.rstrip("/")
        self._key_manager = key_manager
        self._algorithm = algorithm
        self._token_manager = token_manager
        self._dpop = dpop
        self._notifications: set[str] = set()
        self._mdoc_pki: MdocIssuerPKI | None = None
        self._mdoc_pki_repository: MdocPKIRepository | None = mdoc_pki_repository
        self._credential_pki_repository: CredentialPKIRepository | None = credential_pki_repository
        self._revoked_tokens: RevokedTokenRepository | None = revoked_tokens
        self._encryption_enabled = encryption_enabled
        self._encryption_key_manager: DefaultKeyManager | None = encryption_key_manager
        self._encryption_public_jwks: list[dict[str, Any]] | None = None
        self._encryption_private_keys: dict[str, EllipticCurvePrivateKey] = {}

    async def issue_nonce(self) -> dict[str, Any]:
        """Émet un ``c_nonce`` signé, sans état (OID4VCI 1.0 §7).

        Le nonce est un JWT court signé par la clé de signature de l'OP : sa
        validation ne dépend d'aucun stockage, donc reste correcte derrière
        plusieurs workers.
        """
        return {"c_nonce": await self._sign_nonce()}

    async def deferred_credential(
        self,
        bearer_token: str,
        transaction_id: str,
    ) -> dict[str, Any] | CredentialError:
        """Traite une requete deferred (issuance immediate : aucun transaction_id)."""
        claims = await self._token_manager.validate_access_token(
            token=bearer_token, issuer=self._issuer
        )
        if claims is None:
            return CredentialError("invalid_token", INVALID_ACCESS_TOKEN_ERROR, 401)
        if await access_token_revoked(self._revoked_tokens, bearer_token):
            return CredentialError("invalid_token", REVOKED_ACCESS_TOKEN_ERROR, 401)
        return CredentialError("invalid_transaction_id", "transaction_id inconnu ou deja consomme")

    async def notify(
        self,
        bearer_token: str,
        notification_id: str,
        event: str,
    ) -> CredentialError | None:
        """Enregistre une notification du wallet pour une issuance."""
        claims = await self._token_manager.validate_access_token(
            token=bearer_token, issuer=self._issuer
        )
        if claims is None:
            return CredentialError("invalid_token", INVALID_ACCESS_TOKEN_ERROR, 401)
        if await access_token_revoked(self._revoked_tokens, bearer_token):
            return CredentialError("invalid_token", REVOKED_ACCESS_TOKEN_ERROR, 401)
        if notification_id not in self._notifications:
            return CredentialError("invalid_notification_id", "notification_id inconnu", 400)
        if event not in {"credential_accepted", "credential_failure", "credential_deleted"}:
            return CredentialError("invalid_notification_request", "event non supporte", 400)
        # idempotent : on garde trace sans retraiter.
        self._notifications.discard(notification_id)
        self._notifications.add(notification_id)
        return None

    def _ensure_mdoc_pki(self) -> MdocIssuerPKI:
        """Genere la PKI mdoc a la volée si elle n'est pas encore chargee.

        Avec un depot persistant, l'IACA chargee (contact de documentation
        stable, commis dans le depot de certification) sert d'ancre : le
        document signer est reminte a chaque demarrage avec le contact et
        le point de distribution de CRL de l'emetteur courant. Sans depot,
        IACA et document signer sont generes a la vollee (ephemere local).
        """
        if self._mdoc_pki is not None:
            return self._mdoc_pki
        repository = self._mdoc_pki_repository
        iaca = repository.load() if repository is not None else None
        if repository is not None and iaca is None:
            iaca = generate_mdoc_iaca(self._issuer)
            repository.save(iaca)
        generated = generate_mdoc_pki(self._issuer, iaca=iaca)
        self._mdoc_pki = generated
        return generated

    def issuer_metadata(self) -> dict[str, Any]:
        """Renvoie les métadonnées non signées de l'émetteur.

        HAIP tranche 2 : publie le certificat de l'IACA pour qu'un verifier
        externe puisse l'utiliser comme ancre de confiance (x5c base64 DER,
        sans padding).
        """
        result = issuer_metadata_payload(self._issuer)
        pki = self._ensure_mdoc_pki()
        result["mdoc_iaca_certificates"] = [
            base64.urlsafe_b64encode(
                pki.issuer_certificate.public_bytes(cast(Encoding, Encoding.DER))
            )
            .rstrip(b"=")
            .decode("ascii")
        ]
        return result

    async def encryption_jwks(self) -> list[dict[str, Any]] | None:
        """Retourne les clés publiques de chiffrement à publier, ou ``None``.

        Sans activation (``oid4vci_encryption_enabled``) ou sans store, la
        capability n'est pas annoncée. Sinon les clés EC P-256 vivantes de
        la famille ``KeyUse.CREDENTIAL`` sont provisionnées à la première
        usage : chargées du store partagé, ou générée si la famille est
        vide — le rechargement qui suit fait converger deux instances
        concurrentes sur le même trousseau (tri déterministe
        ``created_at``/``kid``). La plus récente est en tête ; les clés
        antérieures restent en drain (jamais purgées) et déchiffrables.
        Les JWK sont mis en cache pour la durée de vie du processus.
        """
        if not self._encryption_enabled or self._encryption_key_manager is None:
            return None
        if self._encryption_public_jwks is not None:
            return self._encryption_public_jwks
        manager = self._encryption_key_manager
        await manager.ensure_active_key(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)
        keys = sorted(
            await manager.get_active_keys(),
            key=lambda key: (key.created_at, key.kid),
            reverse=True,
        )
        jwks: list[dict[str, Any]] = []
        private_keys: dict[str, EllipticCurvePrivateKey] = {}
        for key in keys:
            private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
            if not isinstance(private_key, EllipticCurvePrivateKey):
                raise ValueError("clé de chiffrement OID4VCI attendue en EC P-256")
            jwk = ec_jwk(private_key.public_key())
            kid = jwk_thumbprint(jwk)
            jwk["kid"] = kid
            jwk["alg"] = ECDH_ES
            jwk["use"] = "enc"
            jwks.append(jwk)
            private_keys[kid] = private_key
        self._encryption_public_jwks = jwks
        self._encryption_private_keys = private_keys
        return jwks

    async def _reload_encryption_jwks(self) -> None:
        """Vide le cache des clés de chiffrement puis le rebâtit depuis le store.

        Sert d'auto-guérison quand le déchiffrement échoue sur tout le
        trousseau en cache : une clé provisionnée par une autre instance
        après la construction du cache (course au premier démarrage,
        issue #310) devient alors utilisable, et le trousseau publié aux
        wallets est completifié en même temps.
        """
        self._encryption_public_jwks = None
        self._encryption_private_keys = {}
        await self.encryption_jwks()

    async def signed_issuer_metadata(self) -> str:
        """Signe les métadonnées de l'émetteur en ``application/jwt``.

        OID4VCI 1.0 §12.2.2 : la clé publique d'émission est embarquée dans
        l'en-tête JOSE (``jwk``), le payload porte ``sub`` (URL d'émetteur)
        et ``iat`` requis, plus tous les paramètres de métadonnées au premier
        niveau. La signature est réalisée avec la clé active de l'OP.
        """
        key: KeyPair = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        now = int(datetime.now(timezone.utc).timestamp())
        payload: dict[str, object] = dict(self.issuer_metadata())
        encryption_jwks = await self.encryption_jwks()
        if encryption_jwks is not None:
            payload.update(_encryption_metadata_blocks(encryption_jwks))
        payload["sub"] = self._issuer
        payload["iss"] = self._issuer
        payload["iat"] = now
        jwk = JWKKeyResponse.from_key_pair(key).model_dump(mode="json", exclude_none=True)
        headers = {"typ": ISSUER_METADATA_TYP, "kid": key.kid, "jwk": jwk}
        return cast(
            str,
            pyjwt.encode(payload, private_key, algorithm=self._algorithm.value, headers=headers),
        )

    async def issue_credential(
        self,
        bearer_token: str,
        *,
        credential_configuration_id: str | None = None,
        credential_identifier: str | None = None,
        requested_format: str | None = None,
        proofs: Iterable[str] = (),
        auth_scheme: str = "bearer",
        dpop_proof: str = "",
        htu: str = "",
        method: str = "POST",
    ) -> dict[str, Any] | CredentialError:
        """Retourne le JSON de réponse OID4VCI, ou l'erreur typée à rendre."""
        claims = await self._token_manager.validate_access_token(
            token=bearer_token, issuer=self._issuer
        )
        if claims is None:
            return CredentialError("invalid_token", INVALID_ACCESS_TOKEN_ERROR, 401)
        if await access_token_revoked(self._revoked_tokens, bearer_token):
            return CredentialError("invalid_token", REVOKED_ACCESS_TOKEN_ERROR, 401)

        if not await self._dpop_authorized(
            claims,
            token=bearer_token,
            auth_scheme=auth_scheme,
            dpop_proof=dpop_proof,
            htu=htu,
            method=method,
        ):
            return CredentialError(
                "invalid_token", "preuve DPoP absente ou non conforme au jeton", 401
            )

        sub = str(claims.get("sub") or claims.get("client_id") or "")
        if not sub:
            return CredentialError("invalid_token", "access token sans sujet", 401)

        credential_configuration_id, configuration_error = self._resolve_requested_configuration(
            claims,
            credential_configuration_id,
            credential_identifier,
            requested_format,
        )
        if configuration_error is not None:
            return configuration_error

        binding_jwks, proof_error = await self._binding_keys(proofs)
        if proof_error is not None:
            return proof_error

        result = await self._issue(sub, binding_jwks, credential_configuration_id)
        if isinstance(result, dict):
            notification_id = uuid.uuid4().hex
            self._notifications.add(notification_id)
            result["notification_id"] = notification_id
        return result

    async def decrypt_credential_request(self, body: bytes) -> dict[str, object] | CredentialError:
        """Déchiffre une requête ``/credential`` en JWE ECDH-ES (OID4VCI s8.2).

        Le media type ``application/jwt`` du corps désigne un credential
        request chiffré avec une clé publiée dans
        ``credential_request_encryption`` ; le ``kid`` de l'en-tête cible
        la clé retenue au chiffrement, avec repli sur l'ensemble du
        trousseau après rotation (drain, issue #310). Un en-tête hors
        capability (``alg``, ``enc`` ou ``zip`` inconnus) oppose
        ``invalid_encryption_parameters`` ; tout autre échec (corps
        illisible, déchiffrement refusé) oppose ``invalid_request``.
        """
        if await self.encryption_jwks() is None:
            return CredentialError("invalid_request", "requête chiffrée non prise en charge")
        try:
            token = body.decode("ascii")
            header = protected_header(token)
        except ValueError:  # couvre UnicodeDecodeError (sous-classe)
            return CredentialError("invalid_request", "requête chiffrée illisible")
        header_error = _request_encryption_header_error(header)
        if header_error is not None:
            return CredentialError("invalid_encryption_parameters", header_error)
        plaintext = _decrypt_with_any_key(token, header, self._encryption_private_keys)
        if plaintext is None:
            # Auto-guérison (issue #310) : le cache local peut avoir été
            # construit avant qu'une autre instance n'insère sa clé. Une
            # relecture du store suffit alors — la requête aboutit sans
            # erreur visible, et le trousseau publié est completifié.
            await self._reload_encryption_jwks()
            plaintext = _decrypt_with_any_key(token, header, self._encryption_private_keys)
        if plaintext is None:
            return CredentialError("invalid_request", "déchiffrement de la requête impossible")
        try:
            payload = json.loads(plaintext)
        except (TypeError, ValueError):
            return CredentialError("invalid_request", "déchiffrement de la requête impossible")
        if not isinstance(payload, dict):
            return CredentialError("invalid_request", "requête chiffrée attendue comme objet JSON")
        return cast(dict[str, object], payload)

    async def credential_response_encryption(
        self, payload: dict[str, object]
    ) -> tuple[CredentialResponseEncryption | None, CredentialError | None]:
        """Valide ``credential_response_encryption`` d'une requête (OID4VCI s8.2).

        Retourne ``(None, None)`` quand le wallet ne demande aucun
        chiffrement. Sans capability annoncée, ou avec des paramètres hors
        capability (``jwk`` absent ou non EC P-256, ``alg``/``enc``/``zip``
        inconnus), l'erreur typée ``invalid_encryption_parameters`` est
        opposée avant toute émission.
        """
        requested = payload.get("credential_response_encryption")
        if requested is None:
            return (None, None)
        if not isinstance(requested, dict):
            return (None, _invalid_encryption("credential_response_encryption invalide"))
        if await self.encryption_jwks() is None:
            return (None, _invalid_encryption("chiffrement de la réponse non activé"))
        return self._response_encryption_spec(cast(dict[str, Any], requested))

    def _response_encryption_spec(
        self, requested: dict[str, Any]
    ) -> tuple[CredentialResponseEncryption | None, CredentialError | None]:
        """Extrait et valide les paramètres de chiffrement demandés par le wallet."""
        jwk = requested.get("jwk")
        if not isinstance(jwk, dict):
            return (None, _invalid_encryption("jwk requis dans credential_response_encryption"))
        algorithm = jwk.get("alg")
        if algorithm is not None and algorithm != ECDH_ES:
            return (None, _invalid_encryption(f"alg de chiffrement non supporté : {algorithm}"))
        try:
            public_key = ec_public_key(jwk)
        except ValueError:
            return (None, _invalid_encryption("jwk de chiffrement attendu en EC P-256"))
        method, method_error = _response_encryption_method(requested.get("enc"))
        if method_error is not None:
            return (None, method_error)
        zip_value = requested.get("zip")
        if zip_value is not None and zip_value != "DEF":
            return (None, _invalid_encryption(f"zip non supporté : {zip_value}"))
        kid = jwk.get("kid")
        return (
            CredentialResponseEncryption(
                public_key=public_key,
                method=method,
                kid=kid if isinstance(kid, str) else "",
                compress=zip_value == "DEF",
            ),
            None,
        )

    async def seal_credential_response(
        self, result: dict[str, Any], encryption: CredentialResponseEncryption
    ) -> str:
        """Chiffre la réponse ``/credential`` en JWE ECDH-ES (OID4VCI s8.2).

        Le plaintext est le JSON de la réponse ; l'en-tête reprend le
        ``kid`` du jwk du wallet (sélection côté wallet) et ``zip = DEF``
        quand le wallet l'a demandé. Le chiffrement est exécuté hors de la
        boucle d'événements, comme le chiffrement d'id_token ; la
        capability a été validée par ``credential_response_encryption``
        avant émission.
        """
        plaintext = json.dumps(result, separators=(",", ":")).encode("utf-8")
        return await asyncio.to_thread(
            encrypt_compact_ecdh_es,
            method=encryption.method,
            plaintext=plaintext,
            recipient_public_key=encryption.public_key,
            kid=encryption.kid,
            compress=encryption.compress,
        )

    @staticmethod
    def _resolve_requested_configuration(
        claims: dict[str, object],
        credential_configuration_id: str | None,
        credential_identifier: str | None,
        requested_format: str | None,
    ) -> tuple[str | None, CredentialError | None]:
        """Résout la configuration ciblée selon le type d'autorisation du jeton."""
        authorization_details_claim = claims.get("authorization_details")
        if has_authorization_details(authorization_details_claim):
            resolved, configuration_error = OID4VCIIssuerUseCase._resolve_authorized_configuration(
                authorization_details_claim,
                credential_configuration_id,
                credential_identifier,
            )
            if configuration_error is not None:
                return (None, configuration_error)
            if requested_format is not None and requested_format not in CREDENTIAL_FORMATS:
                return (
                    None,
                    CredentialError(
                        "invalid_credential_request", "format de credential non supporte"
                    ),
                )
            return (resolved, None)
        scopes = str(claims.get("scope") or "").split()
        if "openid4vci" not in scopes:
            return (
                None,
                CredentialError(
                    "insufficient_scope",
                    "scope openid4vci requis pour emettre un credential",
                    403,
                ),
            )
        configuration_error = OID4VCIIssuerUseCase._configuration_error(
            credential_configuration_id, credential_identifier, requested_format
        )
        if configuration_error is not None:
            return (None, configuration_error)
        return (credential_configuration_id, None)

    @staticmethod
    def _resolve_authorized_configuration(
        authorization_details_claim: object,
        credential_configuration_id: str | None,
        credential_identifier: str | None,
    ) -> tuple[str | None, CredentialError | None]:
        """Résout la configuration depuis un ``credential_identifier`` accordé."""
        if credential_configuration_id is not None:
            return (
                None,
                CredentialError(
                    "invalid_credential_request",
                    "credential_configuration_id interdit quand authorization_details est present",
                ),
            )
        if credential_identifier is None:
            return (
                None,
                CredentialError(
                    "invalid_credential_request",
                    "credential_identifier requis quand authorization_details est present",
                ),
            )
        resolved_configuration = credential_configuration_for_identifier(
            authorization_details_claim, credential_identifier
        )
        if resolved_configuration is None:
            return (
                None,
                CredentialError("unknown_credential_identifier", "credential_identifier inconnu"),
            )
        return (resolved_configuration, None)

    @staticmethod
    def _configuration_error(
        credential_configuration_id: str | None,
        credential_identifier: str | None,
        requested_format: str | None,
    ) -> CredentialError | None:
        """Vérifie la cible demandée (configuration, identifiant, format)."""
        if credential_identifier is not None:
            # Le token endpoint ne distribue pas de ``credential_identifiers`` :
            # toute valeur reçue désigne donc une cible non émise par l'OP.
            return CredentialError("unknown_credential_identifier", "credential_identifier inconnu")
        if credential_configuration_id is None:
            return CredentialError(
                "invalid_credential_request",
                "credential_configuration_id ou credential_identifier requis",
            )
        if credential_configuration_id not in SUPPORTED_CREDENTIAL_CONFIGURATION_IDS:
            return CredentialError(
                "unknown_credential_configuration", "credential_configuration_id inconnu"
            )
        if requested_format is not None and requested_format not in CREDENTIAL_FORMATS:
            return CredentialError(
                "invalid_credential_request", "format de credential non supporte"
            )
        return None

    async def _binding_keys(
        self, proofs: Iterable[str]
    ) -> tuple[list[dict[str, Any]] | None, CredentialError | None]:
        """Vérifie chaque preuve JWT et rend les JWK à lier aux credentials."""
        candidates = [proof for proof in proofs if proof]
        if not candidates:
            return (
                None,
                CredentialError("invalid_proof", "preuve cryptographique (proofs.jwt) requise"),
            )
        binding_jwks: list[dict[str, Any]] = []
        for proof_jwt in candidates:
            claims, jwk = self._decode_proof(proof_jwt)
            if claims is None or jwk is None:
                return (None, CredentialError("invalid_proof", "preuve JWT invalide"))
            if not self._audience_matches(claims.get("aud")):
                return (
                    None,
                    CredentialError(
                        "invalid_proof", "audience de la preuve differente de l'emetteur"
                    ),
                )
            nonce = claims.get("nonce")
            if not isinstance(nonce, str) or not nonce:
                return (None, CredentialError("invalid_proof", "nonce absent de la preuve"))
            if not await self._c_nonce_valid(nonce):
                return (
                    None,
                    CredentialError(
                        "invalid_nonce",
                        "c_nonce inconnu, invalide ou expire",
                    ),
                )
            # Justification: en-tete lu avant verification de la signature
            proof_header = pyjwt.get_unverified_header(proof_jwt)  # NOSONAR(S5659)
            attestation = proof_header.get("key_attestation")
            if isinstance(attestation, str) and not self._key_attestation_valid(attestation, jwk):
                return (None, CredentialError("invalid_proof", "attestation de cle invalide"))
            binding_jwks.append(jwk)
        return (binding_jwks, None)

    def _audience_matches(self, audience: object) -> bool:
        """Contrôle que la preuve vise bien cet émetteur."""
        if isinstance(audience, str):
            return audience == self._issuer
        if isinstance(audience, list):
            return self._issuer in [item for item in audience if isinstance(item, str)]
        return False

    def _decode_proof(self, proof_jwt: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Vérifie la signature d'une preuve JWT et rend (claims, JWK)."""
        try:
            header = pyjwt.get_unverified_header(proof_jwt)  # NOSONAR(S5659)
        except pyjwt.PyJWTError:
            return None, None
        if header.get("typ") not in PROOF_TYPES:
            return None, None
        algorithm_name = header.get("alg")
        jwk = header.get("jwk")
        if (
            not isinstance(algorithm_name, str)
            or algorithm_name not in PROOF_ALGORITHMS
            or not isinstance(jwk, dict)
        ):
            return None, None
        algorithm = pyjwt.algorithms.get_default_algorithms().get(algorithm_name)
        if algorithm is None:
            return None, None
        try:
            public_key = algorithm.from_jwk(json.dumps(jwk))
            claims = pyjwt.decode(
                proof_jwt,
                public_key,
                algorithms=[algorithm_name],
                options={"verify_aud": False},
            )
        except (pyjwt.PyJWTError, ValueError, TypeError):
            return None, None
        if not isinstance(claims, dict):
            return None, None
        return claims, jwk

    def _key_attestation_public_key(self, header: dict[str, object]) -> Any | None:  # ruff: ignore[any-type]
        """Extrait la cle publique d une attestation (x5c ou jwk)."""
        x5c = header.get("x5c")
        if isinstance(x5c, list) and x5c and isinstance(x5c[0], str):
            try:
                padding = "=" * (-len(x5c[0]) % 4)
                der = base64.b64decode(x5c[0] + padding)
                return x509.load_der_x509_certificate(der).public_key()
            except Exception:
                return None

        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            return None
        try:
            alg_cls = (
                pyjwt.algorithms.RSAAlgorithm
                if jwk.get("kty") == "RSA"
                else pyjwt.algorithms.ECAlgorithm
            )
            return alg_cls.from_jwk(__import__("json").dumps(jwk))
        except Exception:
            return None

    def _key_attestation_covers(
        self, binding_jwk: dict[str, Any], claims: dict[str, object]
    ) -> bool:
        """Verifie que la cle de preuve figure dans attested_keys si present."""
        attested_keys = claims.get("attested_keys")
        if not isinstance(attested_keys, dict):
            return True
        keys = attested_keys.get("keys")
        if not isinstance(keys, list) or not keys:
            return True
        if binding_jwk in keys:
            return True
        binding_kid = binding_jwk.get("kid")
        return any(isinstance(item, dict) and item.get("kid") == binding_kid for item in keys)

    def _key_attestation_valid(self, attestation_jwt: str, binding_jwk: dict[str, Any]) -> bool:
        """Valide la signature d une attestation de cle."""
        try:
            # Justification: en-tete lu avant verification de la signature
            header = pyjwt.get_unverified_header(attestation_jwt)  # NOSONAR(S5659)
        except pyjwt.PyJWTError:
            return False
        algorithm_name = header.get("alg")
        if not isinstance(algorithm_name, str):
            return False

        public_key = self._key_attestation_public_key(dict(header))
        if public_key is None:
            return False

        try:
            claims = pyjwt.decode(
                attestation_jwt,
                public_key,
                algorithms=[algorithm_name],
                options={"verify_aud": False},
            )
        except (pyjwt.PyJWTError, ValueError, TypeError):
            return False
        if not isinstance(claims, dict):
            return False
        return self._key_attestation_covers(binding_jwk, claims)

    async def _sign_nonce(self) -> str:
        """Signe un ``c_nonce`` court avec la clé de signature de l'OP."""
        key: KeyPair = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        now = int(datetime.now(timezone.utc).timestamp())
        payload: dict[str, object] = {
            "iss": self._issuer,
            "iat": now,
            "exp": now + C_NONCE_LIFETIME,
            "jti": uuid.uuid4().hex,
        }
        headers = {"typ": C_NONCE_TYP, "kid": key.kid}
        return cast(
            str,
            pyjwt.encode(payload, private_key, algorithm=self._algorithm.value, headers=headers),
        )

    async def _c_nonce_valid(self, nonce: str) -> bool:
        """Vérifie qu'un ``c_nonce`` a été signé par l'OP et n'a pas expiré."""
        try:
            header = pyjwt.get_unverified_header(nonce)  # NOSONAR(S5659)
        except pyjwt.PyJWTError:
            return False
        if header.get("typ") != C_NONCE_TYP:
            return False
        kid = header.get("kid")
        if not isinstance(kid, str):
            return False
        key = await self._key_manager.get_key_by_kid(kid)
        if key is None or key.algorithm is not self._algorithm:
            return False
        try:
            public_key = load_pem_public_key(key.public_key_pem.encode("ascii"))
            pyjwt.decode(
                nonce,
                public_key,
                algorithms=[self._algorithm.value],
                issuer=self._issuer,
            )
        except (pyjwt.PyJWTError, ValueError, TypeError):
            return False
        return True

    #: Claims rendus selectivement divulgables pour le credential de demo.
    #: Chaque valeur est embarquee dans une divulgation salee (RFC 9901 s4.2).
    _SELECTIVE_CLAIMS: tuple[tuple[str, object], ...] = (
        ("given_name", "Alice"),
        ("family_name", "Martin"),
    )

    async def _issue(
        self,
        sub: str,
        binding_jwks: list[dict[str, Any]] | None,
        credential_configuration_id: str | None,
    ) -> dict[str, Any] | CredentialError:
        """Signe les credentials d un lot selon la configuration ciblee.

        La configuration ``mso_mdoc`` delivre un ``IssuerSigned`` CBOR (ISO
        18013-5) ; toute autre configuration delivre le SD-JWT VC de
        demonstration (RFC 9901 s8.1). ``sub`` n est utilise que par le
        chemin SD-JWT (claim ``sub`` du issuer JWT).
        """
        if credential_configuration_id == MDOC_CREDENTIAL_CONFIGURATION_ID:
            return self._issue_mdoc(binding_jwks)
        return await self._issue_sd_jwt(sub, binding_jwks)

    def _issue_mdoc(
        self, binding_jwks: list[dict[str, Any]] | None
    ) -> dict[str, Any] | CredentialError:
        """Emet un ``IssuerSigned`` CBOR par cle de liaison (format mso_mdoc).

        Chaque JWK de preuve est converti en device key COSE (EC P-256) et
        devient la cle de liaison du mdoc emis. Le CBOR est rendu en
        base64url sans padding (OID4VCI 1.0 s8.5.1). Une cle non EC P-256
        est refusee (``invalid_proof``) : elle ne peut pas servir de device
        key ISO 18013-5.

        Les 11 elements obligatoires du mDL (ISO 18013-5 table 20) sont
        emis dans le namespace ``org.iso.18013.5.1``. Les timestamps du
        MSO sont arrondis a l'heure, comme sur le chemin SD-JWT, pour que
        deux credentials d un meme lot ne soient pas correlables par leurs
        dates (RFC 9901 s10.1).
        """
        pki = self._ensure_mdoc_pki()
        elements = dict(MDL_MANDATORY_ELEMENTS)
        now = int(datetime.now(timezone.utc).timestamp())
        rounded_now = datetime.fromtimestamp((now // 3600) * 3600, tz=timezone.utc)
        credentials: list[dict[str, str]] = []
        for binding_jwk in binding_jwks or []:
            try:
                issued = pki.issue(
                    device_jwk=binding_jwk,
                    claims=elements,
                    doc_type=MDOC_DOCTYPE,
                    now=rounded_now,
                )
            except MdocBindingError as error:
                return CredentialError("invalid_proof", str(error))
            credentials.append(
                {
                    "credential": base64.urlsafe_b64encode(issued).rstrip(b"=").decode("ascii"),
                }
            )
        return {"credentials": credentials}

    async def _issue_sd_jwt(
        self, sub: str, binding_jwks: list[dict[str, Any]] | None
    ) -> dict[str, Any]:
        """Signe les SD-JWT VC d un lot et joint un nouveau ``c_nonce``.

        Les claims de ``_SELECTIVE_CLAIMS`` sont rendus selectivement
        divulgables : leur digest sale est porte par le membre ``_sd`` de
        l issuer JWT, et la divulgation complete figure apres le premier
        ``~`` dans le format combine (RFC 9901 s8.1) pour que le wallet
        puisse en reveler un sous-ensemble lors de la presentation.
        Des digests leurres (decoys) masquent le nombre reel de claims
        (RFC 9901 s4.2.6).
        """
        material = await self._sd_jwt_signing_material()
        now = int(datetime.now(timezone.utc).timestamp())
        # Arrondi à l'heure pour éviter la corrélation inter-credential du lot
        # (RFC 9901 §10.1) ; voir ``VCIEnsureBatchTimeClaimsNotLinkable``.
        rounded_now = (now // 3600) * 3600
        credentials: list[dict[str, str]] = []
        if not binding_jwks:
            binding_jwks = [None]  # type: ignore[list-item]
        for binding_jwk in binding_jwks:
            sd_payload: list[str] = []
            disclosures: list[str] = []
            for claim_name, claim_value in self._SELECTIVE_CLAIMS:
                salt = secrets.token_urlsafe(16)
                disclosure = [salt, claim_name, claim_value]
                disclosure_json = json.dumps(disclosure, separators=(",", ":"))
                digest = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(disclosure_json.encode("ascii")).digest()
                    )
                    .rstrip(b"=")
                    .decode("ascii")
                )
                sd_payload.append(digest)
                encoded_disclosure = (
                    base64.urlsafe_b64encode(disclosure_json.encode("ascii"))
                    .rstrip(b"=")
                    .decode("ascii")
                )
                disclosures.append(encoded_disclosure)
            # Digests leurres (RFC 9901 s4.2.6) pour masquer le nombre de
            # claims reellement divulgables.
            for _ in range(2):
                decoy_salt = secrets.token_urlsafe(16)
                decoy_json = json.dumps([decoy_salt], separators=(",", ":"))
                decoy_digest = (
                    base64.urlsafe_b64encode(hashlib.sha256(decoy_json.encode("ascii")).digest())
                    .rstrip(b"=")
                    .decode("ascii")
                )
                sd_payload.append(decoy_digest)
            payload: dict[str, object] = {
                "iss": self._issuer,
                "sub": sub,
                "iat": rounded_now,
                "exp": rounded_now + 3600,
                "vct": credential_vct(self._issuer),
                "_sd": sd_payload,
                "_sd_alg": "sha-256",
            }
            if binding_jwk is not None:
                payload["cnf"] = {"jwk": binding_jwk}
            credential = cast(
                str,
                pyjwt.encode(
                    payload,
                    material.private_key,
                    algorithm=material.algorithm,
                    headers=material.headers,
                ),
            )
            combined = credential + "~" + "~".join(disclosures) + "~"
            credentials.append(
                {
                    "credential": combined,
                }
            )
        return {"credentials": credentials}

    async def _sd_jwt_signing_material(self) -> _SdJwtSigningMaterial:
        """Materiel de signature du prochain credential SD-JWT.

        Avec un depot `credential_pki_path` charge, le credential est signe
        par la leaf RSA de la PKI d'emission et porte l'en-tete ``x5c``
        (HAIP section 4.5.1 ; ``kid`` derive du SKI de la leaf, ``alg``
        RS256 comme la metadata annonce deja). Sans depot (developpement),
        la cle active de l'OP signe et aucun ``x5c`` n'est emis.
        """
        repository = self._credential_pki_repository
        pki = repository.load() if repository is not None else None
        if pki is None:
            return await self._op_key_signing_material()
        return _SdJwtSigningMaterial(
            private_key=pki.leaf_private_key,
            algorithm="RS256",
            headers={
                "typ": SD_JWT_VC_TYP,
                "kid": pki.kid,
                "alg": "RS256",
                "x5c": pki.x5c,
            },
        )

    async def _op_key_signing_material(self) -> _SdJwtSigningMaterial:
        """Materiel de signature adossé à la cle active de l'OP."""
        key: KeyPair = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        return _SdJwtSigningMaterial(
            private_key=private_key,
            algorithm=self._algorithm.value,
            headers={"typ": SD_JWT_VC_TYP, "kid": key.kid, "alg": self._algorithm.value},
        )

    async def _dpop_authorized(
        self,
        claims: dict[str, object],
        *,
        token: str,
        auth_scheme: str,
        dpop_proof: str,
        htu: str,
        method: str,
    ) -> bool:
        """Contrôle la présentation d'un access token éventuellement lié DPoP.

        Un jeton lié (``cnf.jkt``) n'est accepté qu'avec le scheme ``DPoP``
        et une preuve dont l'empreinte correspond (RFC 9449 §7.1) ; le
        scheme ``Bearer`` reste admis pour un jeton non lié.
        """
        cnf = claims.get("cnf")
        bound_jkt = str(cnf.get("jkt", "")) if isinstance(cnf, dict) else ""
        if not bound_jkt:
            return True
        if auth_scheme != "dpop" or self._dpop is None or not dpop_proof:
            return False
        proof = await self._dpop.validate(
            proof=dpop_proof,
            htu=htu,
            method=method,
            ath=access_token_hash(token),
        )
        if isinstance(proof, DpopValidationError):
            return False
        return proof.jkt == bound_jkt


#: Scope exigé pour créer une offre de credential.
CREDENTIAL_OFFER_SCOPE = Scope.OID4VCI


@dataclass(frozen=True, slots=True)
class _OfferCaller:
    """Porteur identifié par l'access token de création d'offre.

    ``machine`` distingue un jeton ``client_credentials`` (``sub`` égal au
    ``client_id``, sans utilisateur final) d'un jeton utilisateur : seul un
    jeton machine peut désigner un sujet autre que le sien.
    """

    subject: str
    client_id: str
    machine: bool


class CredentialOfferUseCase:
    """Crée et résout les offres de credential (OID4VCI 1.0 §4.1.1).

    La création exige un access token portant le scope ``openid4vci``.
    L'offre porte un code pré-autorisé — usage unique et courte durée —
    stocké comme code d'autorisation, ce qui rend le grant
    ``urn:ietf:params:oauth:grant-type:pre-authorized_code`` immédiatement
    utilisable. ``credential_offer_uri`` référence l'offre persistée : le
    wallet la déréférence sans authentification, et la référence cesse de
    répondre dès que le code est consommé ou expiré.
    """

    def __init__(
        self,
        *,
        issuer: str,
        offer_repository: CredentialOfferRepository,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
        offer_ttl: int = CREDENTIAL_OFFER_TTL,
        revoked_tokens: RevokedTokenRepository | None = None,
    ) -> None:
        """Injecte l'émetteur, les stockages et la validation des jetons.

        ``revoked_tokens`` porte la denylist des access tokens (RFC 6749
        §5.2) opposée à la création d'une offre.
        """
        self._issuer = issuer.rstrip("/")
        self._offers = offer_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._offer_ttl = offer_ttl
        self._revoked_tokens = revoked_tokens

    async def create(
        self,
        access_token: str,
        *,
        credential_configuration_ids: Sequence[str] = (),
        subject: str = "",
        tx_code: bool = False,
    ) -> dict[str, Any] | CredentialError:
        """Crée une offre et retourne sa forme par valeur et par référence.

        ``subject`` désigne le titulaire du credential : il est facultatif
        pour un jeton utilisateur (défaut : le ``sub`` du jeton) et
        obligatoire pour un jeton machine. Un jeton utilisateur ne peut pas
        désigner un autre sujet que le sien. ``tx_code`` demande un code de
        transaction à 6 chiffres, restitué une seule fois dans la réponse
        (OID4VCI 1.0 §4.1.1 : canal séparé, absent par défaut).
        """
        caller = await self._caller(access_token)
        if isinstance(caller, CredentialError):
            return caller

        configurations = self._configuration_ids(credential_configuration_ids)
        if isinstance(configurations, CredentialError):
            return configurations

        resolved_subject = self._offer_subject(caller, subject)
        if isinstance(resolved_subject, CredentialError):
            return resolved_subject

        now = datetime.now(timezone.utc)
        tx_code_value = _transaction_code() if tx_code else ""
        code = AuthorizationCode(
            code=secrets.token_urlsafe(32),
            client_id="",
            redirect_uri="",
            subject=resolved_subject,
            scopes=frozenset({CREDENTIAL_OFFER_SCOPE}),
            pre_authorized=True,
            tx_code_hash=(
                hashlib.sha256(tx_code_value.encode("utf-8")).hexdigest() if tx_code_value else ""
            ),
            expires_at=now + timedelta(seconds=self._offer_ttl),
        )
        offer = CredentialOffer(
            offer_id=secrets.token_urlsafe(16),
            credential_configuration_ids=configurations,
            subject=resolved_subject,
            pre_authorized_code=code.code,
            client_id=caller.client_id,
            tx_code_required=bool(tx_code_value),
            created_at=now,
            expires_at=code.expires_at,
        )
        await self._codes.save(code)
        await self._offers.save(offer)
        response: dict[str, Any] = {
            "credential_offer": credential_offer_payload(offer, self._issuer),
            "credential_offer_uri": f"{self._issuer}/credential-offer/{offer.offer_id}",
        }
        if tx_code_value:
            response["tx_code"] = tx_code_value
        return response

    async def resolve(self, offer_id: str) -> dict[str, Any] | CredentialError:
        """Retourne l'offre référencée par ``offer_id`` pour le wallet.

        Une offre inconnue, expirée, ou dont le code pré-autorisé a déjà
        été consommé n'est plus servie : la référence ne survit pas à son
        usage unique.
        """
        offer = await self._offers.find_by_id(offer_id)
        now = datetime.now(timezone.utc)
        if offer is None or offer.is_expired(now):
            return self._unknown_offer()
        code = await self._codes.find_by_code(offer.pre_authorized_code)
        if code is None or code.is_consumed or code.expires_at < now:
            return self._unknown_offer()
        return credential_offer_payload(offer, self._issuer)

    async def _caller(self, access_token: str) -> _OfferCaller | CredentialError:
        """Valide le jeton et vérifie le scope exigé pour créer une offre."""
        claims = await self._token_manager.validate_access_token(
            token=access_token, issuer=self._issuer
        )
        if claims is None:
            return CredentialError("invalid_token", "access token invalide ou expire", 401)
        if await access_token_revoked(self._revoked_tokens, access_token):
            return CredentialError("invalid_token", REVOKED_ACCESS_TOKEN_ERROR, 401)
        scopes = str(claims.get("scope") or "").split()
        if CREDENTIAL_OFFER_SCOPE.value not in scopes:
            return CredentialError(
                "insufficient_scope", "scope openid4vci requis pour creer une offre", 403
            )
        subject = str(claims.get("sub") or "")
        if not subject:
            return CredentialError("invalid_token", "access token sans sujet", 401)
        client_id = str(claims.get("client_id") or "")
        return _OfferCaller(
            subject=subject,
            client_id=client_id,
            machine=bool(client_id) and client_id == subject,
        )

    @staticmethod
    def _configuration_ids(
        requested: Sequence[str],
    ) -> tuple[str, ...] | CredentialError:
        """Normalise et vérifie les configurations de credential demandées."""
        configurations = tuple(dict.fromkeys(requested)) or (CREDENTIAL_CONFIGURATION_ID,)
        if any(item not in SUPPORTED_CREDENTIAL_CONFIGURATION_IDS for item in configurations):
            return CredentialError(
                "unknown_credential_configuration", "credential_configuration_id inconnu"
            )
        return configurations

    @staticmethod
    def _offer_subject(caller: _OfferCaller, requested: str) -> str | CredentialError:
        """Détermine le titulaire du credential selon le type de porteur."""
        if requested:
            if not caller.machine and requested != caller.subject:
                return CredentialError(
                    "invalid_request", "le sujet demande differe du porteur du jeton", 403
                )
            return requested
        if caller.machine:
            return CredentialError(
                "invalid_request", "subject requis pour une offre creee par un client", 400
            )
        return caller.subject

    def _unknown_offer(self) -> CredentialError:
        """Erreur unique d'une référence d'offre non servie."""
        return CredentialError("not_found", "offre de credential inconnue ou expiree", 404)


def _transaction_code() -> str:
    """Génère un code de transaction numérique à ``TX_CODE_LENGTH`` chiffres."""
    return "".join(str(secrets.randbelow(10)) for _ in range(TX_CODE_LENGTH))
