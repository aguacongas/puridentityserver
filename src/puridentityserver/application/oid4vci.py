"""Cas d'usage de l'issuance OpenID4VCI (slice 1, issue #172/#222)."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.domain.dpop import access_token_hash
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse

#: Identifiant de la configuration de credential publiée par l'OP.
CREDENTIAL_CONFIGURATION_ID = "puridentityserver-sdjwt-vc"

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

    async def issue_nonce(self) -> dict[str, Any]:
        """Émet un ``c_nonce`` signé, sans état (OID4VCI 1.0 §7).

        Le nonce est un JWT court signé par la clé de signature de l'OP : sa
        validation ne dépend d'aucun stockage, donc reste correcte derrière
        plusieurs workers.
        """
        return {"c_nonce": await self._sign_nonce()}

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
            return CredentialError(
                "invalid_token", "access token invalide, expire ou non autorise", 401
            )

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

        configuration_error = self._configuration_error(
            credential_configuration_id, credential_identifier, requested_format
        )
        if configuration_error is not None:
            return configuration_error

        binding_jwks, proof_error = await self._binding_keys(proofs)
        if proof_error is not None:
            return proof_error

        return await self._issue(sub, binding_jwks)

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

    async def _issue(self, sub: str, binding_jwks: list[dict[str, Any]] | None) -> dict[str, Any]:
        """Signe les SD-JWT VC d un lot et joint un nouveau ``c_nonce``."""
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
            payload: dict[str, object] = {
                "iss": self._issuer,
                "sub": sub,
                "iat": rounded_now,
                "exp": rounded_now + 3600,
                "vct": credential_vct(self._issuer),
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
            credentials.append(
                {
                    # Format combiné SD-JWT (RFC 9901 §8.1) : JWT émetteur suivi de
                    # ``~`` et, ici, d'aucune divulgation. Sans le ``~`` final le
                    # credential n'est pas un SD-JWT valide.
                    "credential": f"{credential}~",
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
