"""Cas d'usage de l'issuance OpenID4VCI (slice 1, issue #172/#222)."""

from __future__ import annotations

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
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.application.authorization_details import (
    CREDENTIAL_CONFIGURATION_ID,
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
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.credential_offer_repository import (
    CredentialOfferRepository,
)
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse

#: Identifiant de la configuration de credential publiée par l'OP.
#: Réexporté depuis ``application.authorization_details`` (source unique).

#: Chemin du type de credential publié par l'OP (SD-JWT VC). Le ``vct`` du
#: credential et l'URL de sa Type Metadata (SD-JWT VC §6.3.1) en dérivent.
CREDENTIAL_VCT_PATH = "/credentials/example"

#: Type JOSE de l'en-tête d'un SD-JWT VC (SD-JWT VC §3.2.1).
SD_JWT_VC_TYP = "dc+sd-jwt"

#: Type JOSE d'une réponse de métadonnées signées (OID4VCI 1.0 §12.2.2).
ISSUER_METADATA_TYP = "openidvci-issuer-metadata+jwt"

#: Formats SD-JWT VC acceptés dans une requête de credential.
CREDENTIAL_FORMATS = frozenset({SD_JWT_VC_TYP, "vc+sd-jwt"})

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


def issuer_metadata_payload(issuer: str) -> dict[str, Any]:
    """Construit le document de métadonnées de l'émetteur OID4VCI (non signé)."""
    normalized = issuer.rstrip("/")
    return {
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
            }
        },
        "batch_credential_issuance": {"batch_size": 5},
        "deferred_credential_endpoint": f"{normalized}/deferred_credential",
        "notification_endpoint": f"{normalized}/notification",
    }


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


# Message d erreur d access token invalide, partage.
INVALID_ACCESS_TOKEN_ERROR = "access token invalide, expire ou non autorise"  # ruff: ignore[hardcoded-password-string]


class OID4VCIIssuerUseCase:
    """Émet un credential verifiable SD-JWT pour l'OP.

    La preuve de possession (``proofs.jwt``) est obligatoire : la configuration
    publiée annonce ``cryptographic_binding_methods_supported``, donc une
    requête sans preuve est refusée (OID4VCI 1.0 §8.2). La liaison DPoP de
    l'access token est vérifiée de la même façon (RFC 9449 §7.1).
    """

    def __init__(
        self,
        *,
        issuer: str,
        key_manager: DefaultKeyManager,
        algorithm: JWTAlgorithm,
        token_manager: TokenManager,
        dpop: DpopProofValidator | None = None,
    ) -> None:
        """Initialise l'émetteur et mémorise les dépendances cryptographiques."""
        self._issuer = issuer.rstrip("/")
        self._key_manager = key_manager
        self._algorithm = algorithm
        self._token_manager = token_manager
        self._dpop = dpop
        self._notifications: set[str] = set()

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
        if notification_id not in self._notifications:
            return CredentialError("invalid_notification_id", "notification_id inconnu", 400)
        if event not in {"credential_accepted", "credential_failure", "credential_deleted"}:
            return CredentialError("invalid_notification_request", "event non supporte", 400)
        # idempotent : on garde trace sans retraiter.
        self._notifications.discard(notification_id)
        self._notifications.add(notification_id)
        return None

    def issuer_metadata(self) -> dict[str, Any]:
        """Renvoie les métadonnées non signées de l'émetteur."""
        return issuer_metadata_payload(self._issuer)

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

        result = await self._issue(sub, binding_jwks)
        if isinstance(result, dict):
            notification_id = uuid.uuid4().hex
            self._notifications.add(notification_id)
            result["notification_id"] = notification_id
        return result

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
        if credential_configuration_id != CREDENTIAL_CONFIGURATION_ID:
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

    async def _issue(self, sub: str, binding_jwks: list[dict[str, Any]] | None) -> dict[str, Any]:
        """Signe les SD-JWT VC d un lot et joint un nouveau ``c_nonce``.

        Les claims de ``_SELECTIVE_CLAIMS`` sont rendus selectivement
        divulgables : leur digest sale est porte par le membre ``_sd`` de
        l issuer JWT, et la divulgation complete figure apres le premier
        ``~`` dans le format combine (RFC 9901 s8.1) pour que le wallet
        puisse en reveler un sous-ensemble lors de la presentation.
        Des digests leurres (decoys) masquent le nombre reel de claims
        (RFC 9901 s4.2.6).
        """
        key: KeyPair = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
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
            headers = {"typ": SD_JWT_VC_TYP, "kid": key.kid, "alg": self._algorithm.value}
            credential = cast(
                str,
                pyjwt.encode(
                    payload, private_key, algorithm=self._algorithm.value, headers=headers
                ),
            )
            combined = credential + "~" + "~".join(disclosures) + "~"
            credentials.append(
                {
                    "credential": combined,
                }
            )
        return {"credentials": credentials}

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
    ) -> None:
        """Injecte l'émetteur, les stockages et la validation des jetons."""
        self._issuer = issuer.rstrip("/")
        self._offers = offer_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._offer_ttl = offer_ttl

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
        if any(item != CREDENTIAL_CONFIGURATION_ID for item in configurations):
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
