"""Initiation verifier et validation des présentations OpenID4VP (issue #224).

Implémente le profil de vérification OpenID4VP 1.0 Final en ``direct_post.jwt``
(HAIP) :

- ``create_presentation_request`` : construit le request object signé
  (``typ = oauth-authz-req+jwt``, ``aud = https://self-issued.me/v2``) avec un
  ``client_id`` ``x509_hash:`` issu de la PKI du verifier, une clé de
  chiffrement éphémère P-256 par requête (HAIP §5-6 interdit tout réemploi),
  le ``dcql_query`` et le ``client_metadata`` attendus ;
- ``get_request_object`` : sert le request object au ``request_uri`` (GET
  idempotent, ou re-signé avec le ``wallet_nonce`` en POST) ;
- ``validate_presentation_response`` : déchiffre le JWE ``ECDH-ES`` de la
  réponse, contrôle le SD-JWT présenté (signatures du credential et du
  ``kb+jwt``, ``nonce``, ``aud``, ``sd_hash``, ``iat``) et rend le verdict de
  la section 8.2 (200 ``{"redirect_uri": ...}`` ou 4xx motivé).

Les vérifications de signature du credential ne s'appliquent que si un JWKS
public de confiance est configuré (``oid4vp_credential_jwks``) : sans lui, la
présentation est acceptée sans contrôle de l'émetteur (mode witness).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.api_jwk import PyJWK

from puridentityserver.domain.jwe import ECDH_ES
from puridentityserver.infrastructure.jwe import (
    b64u,
    decrypt_compact_ecdh_es,
    ec_jwk,
    ec_public_key,
    protected_header,
)
from puridentityserver.infrastructure.oid4vp_pki import (
    VerifierPKI,
    VerifierPKIRepository,
    generate_verifier_pki,
)

#: Media type du request object servi au ``request_uri`` (RFC 9101 §4.4).
REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"

#: ``response_type`` / ``response_mode`` du profil ``direct_post.jwt``.
RESPONSE_TYPE_VP = "vp_token"
RESPONSE_MODE_DIRECT_POST_JWT = "direct_post.jwt"

#: Valeur de ``typ`` exigée sur le request object (OID4VP 1.0 Final §5).
REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"

#: Audience du request object, fixée par OID4VP §5.8 sur l'issuer SIOP v2.
SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2"

#: Valeur de ``typ`` exigée sur le key binding JWT (SD-JWT §4.3).
KEY_BINDING_TYP = "kb+jwt"

#: Valeur de ``typ`` du credential SD-JWT émis par la suite (Appendix B.3.4).
SD_JWT_TYP = "dc+sd-jwt"

#: Méthodes de chiffrement annoncées : A128GCM en tête, le wallet prend la
#: première (HAIP §5 exige les deux valeurs).
SUPPORTED_ENC_VALUES = ("A128GCM", "A256GCM")

#: Format de credential unique exigé du wallet (``dc+sd-jwt`` = SD-JWT VC).
CREDENTIAL_FORMAT_DC_SD_JWT = "dc+sd-jwt"

#: ``vct`` du credential PID produit par la suite de conformance.
DEFAULT_VCT = "urn:eudi:pid:1"

#: Taille du nonce en octets (43 caractères base64url : borne haute des
#: exigences de la suite, 16 à 43 caractères et > 96 bits).
NONCE_SIZE_BYTES = 32

#: Tolérance horaire du ``iat`` du kb-jwt, en secondes (± 5 minutes ; les
#: modules ``KbJwtIatInPast`` / ``KbJwtIatInFuture`` décalent d'un an).
IAT_TOLERANCE_SECONDS = 300

#: Nombre maximal de demandes de présentation conservées en mémoire (FIFO).
MAX_PENDING_REQUESTS = 32

#: Claims autorisés du key binding JWT (SD-JWT §4.3, aucun autre).
KEY_BINDING_CLAIMS = frozenset({"iat", "aud", "nonce", "sd_hash"})

#: Algorithmes acceptés pour la signature du credential (EC par défaut de la
#: suite, RSA toléré si le seed de configuration change de type de clé).
CREDENTIAL_SIGNATURE_ALGORITHMS = ("ES256", "RS256")


class PresentationRejectedError(ValueError):
    """Rejet d'une présentation au ``response_uri`` : motif affichable en 4xx."""


@dataclass(frozen=True)
class VerificationOutcome:
    """Verdict de la vérification d'une présentation, pour la page de résultat.

    Attributes:
        accepted: ``True`` si la présentation a été acceptée (200).
        reason: motif du rejet, chaîne vide si acceptée.
    """

    accepted: bool
    reason: str


@dataclass(frozen=True)
class PresentationRequestCreated:
    """Demande de présentation créée, à transmettre au wallet.

    Attributes:
        request_id: identifiant de la demande (segment du ``response_uri``).
        client_id: ``client_id`` ``x509_hash:`` du verifier.
        request_uri: URL publique du request object signé.
        nonce: nonce de la requête, repris dans le ``kb+jwt``.
        request_object: request object JWT signé (repris tel quel en GET).
    """

    request_id: str
    client_id: str
    request_uri: str
    nonce: str
    request_object: str


@dataclass(frozen=True)
class PresentationResponseResult:
    """Issue du POST du wallet sur le ``response_uri``.

    Attributes:
        status_code: code HTTP de la réponse (200 accepté, 400 rejeté).
        body: corps JSON strict (``redirect_uri`` ou erreur OAuth).
        detail: motif du rejet, chaîne vide si acceptée.
    """

    status_code: int
    body: dict[str, Any]
    detail: str

    @property
    def accepted(self) -> bool:
        """Vrai quand la présentation a été acceptée (réponse 200)."""
        return self.status_code == 200


@dataclass
class _PendingRequest:
    """État d'une demande de présentation en attente de réponse wallet."""

    request_id: str
    client_id: str
    request_object: str
    signing_key: ec.EllipticCurvePrivateKey
    signing_header: dict[str, Any]
    nonce: str
    response_uri: str
    encryption_key: ec.EllipticCurvePrivateKey
    encryption_kid: str
    created_at: datetime
    outcome: VerificationOutcome | None = None


class OID4VPVerifierUseCase:
    """Initiation et validation des présentations OpenID4VP du verifier.

    Le registre des demandes en attente vit en mémoire (FIFO bornée) : une
    présentation n'est acceptée que si sa demande a été créée par ce
    processus, ce qui interdit tout rejeu de ``response_uri``.
    """

    def __init__(
        self,
        *,
        issuer: str,
        pki_repository: VerifierPKIRepository,
        credential_jwks: tuple[dict[str, Any], ...] = (),
    ) -> None:
        """Initialise le verifier.

        Args:
            issuer: URL de base de l'OP, servant de préfixe aux ``response_uri``.
            pki_repository: dépôt de la PKI (CA + leaf de signature).
            credential_jwks: JWKS public de confiance pour la signature des
                credentials ; vide = signature non contrôlée (mode witness).
        """
        self._issuer = issuer.rstrip("/")
        self._pki_repository = pki_repository
        self._credential_jwks = credential_jwks
        self._pki_cache: VerifierPKI | None = None
        self._pending: OrderedDict[str, _PendingRequest] = OrderedDict()

    def create_presentation_request(
        self, *, dcql_query: Mapping[str, Any] | None = None
    ) -> PresentationRequestCreated:
        """Crée une demande de présentation et signe son request object.

        Chaque appel génère un nonce et une clé de chiffrement éphémère
        distincts (HAIP §5-6, ``VP1FinalCheckEncryptionKeyNotReused``).

        Args:
            dcql_query: requête DCQL complète, défaut : credential PID
                ``dc+sd-jwt`` unique.

        Returns:
            La demande créée, prête à être soumise au wallet.
        """
        pki = self._pki()
        request_id = uuid.uuid4().hex
        nonce = b64u(secrets.token_bytes(NONCE_SIZE_BYTES))
        response_uri = f"{self._issuer}/oid4vp/vp_response/{request_id}"
        encryption_key = ec.generate_private_key(ec.SECP256R1())
        encryption_public = encryption_key.public_key()
        kid = _jwk_thumbprint(ec_jwk(encryption_public))
        claims = self._request_object_claims(
            client_id=pki.client_id,
            response_uri=response_uri,
            nonce=nonce,
            kid=kid,
            encryption_public=encryption_public,
            dcql_query=dcql_query,
        )
        header = {"typ": REQUEST_OBJECT_TYP, "x5c": pki.x5c, "kid": pki.leaf_thumbprint}
        request_object = cast(
            str,
            pyjwt.encode(
                claims,
                pki.leaf_private_key,  # type: ignore[arg-type]  # clé EC hors stubs PyJWT
                algorithm="ES256",
                headers=header,
            ),
        )
        pending = _PendingRequest(
            request_id=request_id,
            client_id=pki.client_id,
            request_object=request_object,
            signing_key=pki.leaf_private_key,
            signing_header=header,
            nonce=nonce,
            response_uri=response_uri,
            encryption_key=encryption_key,
            encryption_kid=kid,
            created_at=datetime.now(timezone.utc),
        )
        self._register(pending)
        return PresentationRequestCreated(
            request_id=request_id,
            client_id=pki.client_id,
            request_uri=f"{self._issuer}/oid4vp/request_uri/{request_id}",
            nonce=nonce,
            request_object=request_object,
        )

    def get_request_object(self, request_id: str, *, wallet_nonce: str | None = None) -> str | None:
        """Sert le request object d'une demande au ``request_uri``.

        En mode ``request_uri_method = post``, le wallet transmet un
        ``wallet_nonce`` de formulaire : le request object est alors re-signé
        avec ce claim supplémentaire (OID4VP 1.0 Final §5.10).

        Args:
            request_id: identifiant de la demande.
            wallet_nonce: ``wallet_nonce`` posté par le wallet, ou ``None``
                pour servir le request object d'origine (GET).

        Returns:
            Le JWT signé, ou ``None`` si la demande est inconnue.
        """
        pending = self._pending.get(request_id)
        if pending is None:
            return None
        if wallet_nonce is None:
            return pending.request_object
        claims = pyjwt.decode(pending.request_object, options={"verify_signature": False})
        claims["wallet_nonce"] = wallet_nonce
        return cast(
            str,
            pyjwt.encode(
                claims,
                pending.signing_key,  # type: ignore[arg-type]  # clé EC hors stubs PyJWT
                algorithm="ES256",
                headers=pending.signing_header,
            ),
        )

    def validate_presentation_response(
        self, request_id: str, *, response: str
    ) -> PresentationResponseResult:
        """Valide la présentation chiffrée postée par le wallet.

        Toute anomalie (JWE non déchiffrable, ``sd_hash``/``nonce``/``aud``
        erroné, ``iat`` hors tolérance, signature invalide) produit une
        réponse 400 motivée — comportement attendu des modules négatifs du
        plan de certification.

        Args:
            request_id: identifiant de la demande (segment du ``response_uri``).
            response: ``response`` du formulaire, JWE compact ECDH-ES.

        Returns:
            Le résultat à servir au wallet (200 avec ``redirect_uri``, 400
            avec l'erreur, ou 404 si la demande est inconnue).
        """
        pending = self._pending.get(request_id)
        if pending is None:
            return PresentationResponseResult(
                status_code=404,
                body={
                    "error": "invalid_request",
                    "error_description": "demande de presentation inconnue",
                },
                detail="demande de présentation inconnue",
            )
        try:
            credential = self._presented_credential(pending, response)
            self._verify_credential(pending, credential)
        except PresentationRejectedError as rejected:
            reason = str(rejected)
            pending.outcome = VerificationOutcome(accepted=False, reason=reason)
            return PresentationResponseResult(
                status_code=400,
                body={"error": "invalid_request", "error_description": reason},
                detail=reason,
            )
        pending.outcome = VerificationOutcome(accepted=True, reason="")
        return PresentationResponseResult(
            status_code=200,
            body={"redirect_uri": f"{self._issuer}/oid4vp/result/{request_id}"},
            detail="",
        )

    def result_page(self, request_id: str) -> str | None:
        """Construit la page HTML de résultat visitée via le ``redirect_uri``.

        Args:
            request_id: identifiant de la demande.

        Returns:
            La page HTML, ou ``None`` si la demande est inconnue.
        """
        pending = self._pending.get(request_id)
        if pending is None:
            return None
        if pending.outcome is None or not pending.outcome.accepted:
            reason = pending.outcome.reason if pending.outcome else "réponse non reçue"
            title, detail = "Presentation refusee", reason
        else:
            title, detail = "Presentation acceptee", "La credential a ete verifiee avec succes."
        return (
            '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
            f"<title>{title}</title></head><body>"
            f"<h1>{title}</h1><p>{detail}</p>"
            f"<p>Demande : {request_id}</p>"
            "</body></html>"
        )

    def _pki(self) -> VerifierPKI:
        """Charge la PKI du verifier, la générant et la persistant si absente."""
        if self._pki_cache is None:
            pki = self._pki_repository.load()
            if pki is None:
                pki = generate_verifier_pki()
                self._pki_repository.save(pki)
            self._pki_cache = pki
        return self._pki_cache

    def _register(self, pending: _PendingRequest) -> None:
        """Ajoute une demande au registre FIFO en bornant sa taille."""
        self._pending[pending.request_id] = pending
        while len(self._pending) > MAX_PENDING_REQUESTS:
            self._pending.popitem(last=False)

    def _request_object_claims(
        self,
        *,
        client_id: str,
        response_uri: str,
        nonce: str,
        kid: str,
        encryption_public: ec.EllipticCurvePublicKey,
        dcql_query: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Construit les claims du request object (OID4VP 1.0 Final §5)."""
        query: dict[str, Any] = (
            dict(dcql_query) if dcql_query is not None else _default_dcql_query()
        )
        return {
            "iss": client_id,
            "aud": SELF_ISSUED_AUDIENCE,
            "client_id": client_id,
            "response_type": RESPONSE_TYPE_VP,
            "response_mode": RESPONSE_MODE_DIRECT_POST_JWT,
            "response_uri": response_uri,
            "nonce": nonce,
            "iat": int(time.time()),
            "dcql_query": query,
            "client_metadata": _client_metadata(kid, encryption_public),
        }

    def _presented_credential(self, pending: _PendingRequest, response: str) -> str:
        """Déchiffre la réponse du wallet et en extrait le SD-JWT présenté.

        Args:
            pending: demande à laquelle la réponse se rattache.
            response: JWE compact posté par le wallet.

        Returns:
            La chaîne SD-JWT (credential + disclosures + kb-jwt).

        Raises:
            PresentationRejectedError: si le JWE ou le ``vp_token`` est invalide.
        """
        payload = self._decrypt_payload(pending, response)
        vp_token = payload.get("vp_token")
        if not isinstance(vp_token, dict) or len(vp_token) != 1:
            raise PresentationRejectedError("vp_token attendu comme objet d'un credential unique")
        credentials = next(iter(vp_token.values()))
        if not isinstance(credentials, list) or len(credentials) != 1:
            raise PresentationRejectedError(
                "vp_token doit contenir un tableau d'un seul credential"
            )
        credential = credentials[0]
        if not isinstance(credential, str) or not credential:
            raise PresentationRejectedError("credential sd-jwt absent du vp_token")
        return credential

    def _decrypt_payload(self, pending: _PendingRequest, response: str) -> dict[str, Any]:
        """Déchiffre le JWE ``ECDH-ES`` de la réponse avec la clé de la demande.

        Raises:
            PresentationRejectedError: si le document est illisible, le ``kid``
                inconnu ou le déchiffrement échoue.
        """
        try:
            header = protected_header(response)
        except ValueError as exc:
            raise PresentationRejectedError("response de presentation illisible") from exc
        if header.get("kid") != pending.encryption_kid:
            raise PresentationRejectedError("kid de chiffrement inconnu")
        try:
            plaintext = decrypt_compact_ecdh_es(response, private_key=pending.encryption_key)
            payload = json.loads(plaintext)
        except (ValueError, TypeError) as exc:
            raise PresentationRejectedError("response de presentation non dechiffrable") from exc
        if not isinstance(payload, dict):
            raise PresentationRejectedError("payload de response attendu comme objet JSON")
        return payload

    def _verify_credential(self, pending: _PendingRequest, credential: str) -> None:
        """Contrôle le SD-JWT présenté : structure, kb-jwt et signatures.

        Raises:
            PresentationRejectedError: dès la première anomalie détectée.
        """
        issuer_jwt, hashed_prefix, key_binding = _split_presented(credential)
        _verify_sd_jwt_header(issuer_jwt)
        kb_claims = _read_key_binding(key_binding)
        expected_hash = b64u(hashlib.sha256(hashed_prefix.encode("ascii")).digest())
        if kb_claims.get("nonce") != pending.nonce:
            raise PresentationRejectedError("nonce du kb-jwt invalide")
        if kb_claims.get("aud") != pending.client_id:
            raise PresentationRejectedError("audience du kb-jwt invalide")
        if kb_claims.get("sd_hash") != expected_hash:
            raise PresentationRejectedError("sd_hash du kb-jwt invalide")
        _verify_binding_iat(kb_claims["iat"])
        issuer_payload = _unverified_payload(issuer_jwt, label="credential")
        _verify_key_binding_signature(key_binding, issuer_payload)
        self._verify_issuer_signature(issuer_jwt)

    def _verify_issuer_signature(self, issuer_jwt: str) -> None:
        """Vérifie la signature du credential contre le JWKS de confiance.

        Sans ``oid4vp_credential_jwks``, le contrôle est escamoté (le rejet
        des modules ``InvalidCredentialSignature`` repose sur ce réglage).

        Raises:
            PresentationRejectedError: si aucune clé de confiance ne valide la
                signature.
        """
        if not self._credential_jwks:
            return
        for raw_key in self._credential_jwks:
            try:
                key = PyJWK.from_dict(raw_key).key
                pyjwt.decode(
                    issuer_jwt,
                    key,
                    algorithms=list(CREDENTIAL_SIGNATURE_ALGORITHMS),
                    options={
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_nbf": False,
                        "verify_iat": False,
                    },
                )
            except pyjwt.InvalidSignatureError:
                continue
            except (pyjwt.PyJWTError, TypeError, ValueError) as exc:
                # Type de clé inattendu (RSA/oct contre un ES256) ou JWK malformée.
                raise PresentationRejectedError("credential illisible") from exc
            return
        raise PresentationRejectedError("signature du credential non appariee au JWKS de confiance")


def _default_dcql_query() -> dict[str, Any]:
    """Requête DCQL de défaut : credential PID ``dc+sd-jwt`` unique."""
    return {
        "credentials": [
            {
                "id": "pid",
                "format": CREDENTIAL_FORMAT_DC_SD_JWT,
                "meta": {"vct_values": [DEFAULT_VCT]},
            }
        ]
    }


def _client_metadata(kid: str, encryption_public: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    """Construit le ``client_metadata`` attendu (OID4VP Appendix B.2.2).

    Exactement trois paramètres autorisés par la suite : ``jwks`` (clé
    éphémère d'une seule requête), ``vp_formats_supported`` et
    ``encrypted_response_enc_values_supported``.
    """
    jwk = dict(ec_jwk(encryption_public))
    jwk.update({"kid": kid, "alg": ECDH_ES, "use": "enc"})
    return {
        "jwks": {"keys": [jwk]},
        "vp_formats_supported": {CREDENTIAL_FORMAT_DC_SD_JWT: {}},
        "encrypted_response_enc_values_supported": list(SUPPORTED_ENC_VALUES),
    }


def _jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Empreinte base64url du JWK (RFC 7638), utilisée comme ``kid``."""
    material = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u(hashlib.sha256(material.encode("ascii")).digest())


def _split_presented(credential: str) -> tuple[str, str, str]:
    """Découpe un SD-JWT présenté (RFC 9901 §3.2).

    Args:
        credential: chaîne ``credential~disclosure*~kb-jwt``.

    Returns:
        Le JWT signé par l'émetteur, le préfixe à hasher (jusqu'au dernier
        ``~`` inclus, kb-jwt exclu) et le key binding JWT.

    Raises:
        PresentationRejectedError: si la chaîne est malformée.
    """
    parts = credential.split("~")
    if len(parts) < 2 or not parts[0] or not parts[-1]:
        raise PresentationRejectedError("sd-jwt presente malforme (kb-jwt attendu)")
    return parts[0], "~".join(parts[:-1]) + "~", parts[-1]


def _verify_sd_jwt_header(issuer_jwt: str) -> None:
    """Vérifie que le credential porte le ``typ`` SD-JWT attendu.

    Raises:
        PresentationRejectedError: si l'en-tête est illisible ou inattendu.
    """
    try:
        header = pyjwt.get_unverified_header(issuer_jwt)
    except pyjwt.PyJWTError as exc:
        raise PresentationRejectedError("credential sd-jwt illisible") from exc
    if header.get("typ") != SD_JWT_TYP:
        raise PresentationRejectedError("typ du credential attendu dc+sd-jwt")


def _unverified_payload(jwt_value: str, *, label: str) -> dict[str, Any]:
    """Décode les claims d'un JWT sans en vérifier la signature.

    Raises:
        PresentationRejectedError: si le document n'est pas un objet JSON lisible.
    """
    try:
        payload = pyjwt.decode(jwt_value, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        raise PresentationRejectedError(f"{label} illisible") from exc
    if not isinstance(payload, dict):
        raise PresentationRejectedError(f"{label} attendu comme objet JSON")
    return payload


def _read_key_binding(key_binding: str) -> dict[str, Any]:
    """Valide l'en-tête et les claims du kb-jwt (SD-JWT §4.3).

    Les claims doivent être exactement ``iat``, ``aud``, ``nonce`` et
    ``sd_hash`` : ni claim inattendu, ni claim manquant.

    Raises:
        PresentationRejectedError: sur tout écart.
    """
    try:
        header = pyjwt.get_unverified_header(key_binding)
        claims = pyjwt.decode(key_binding, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        raise PresentationRejectedError("kb-jwt illisible") from exc
    if header.get("typ") != KEY_BINDING_TYP:
        raise PresentationRejectedError("typ du kb-jwt attendu kb+jwt")
    if not isinstance(claims, dict):
        raise PresentationRejectedError("kb-jwt attendu comme objet JSON")
    unexpected = set(claims) - KEY_BINDING_CLAIMS
    if unexpected:
        raise PresentationRejectedError(f"claims inattendus dans le kb-jwt : {sorted(unexpected)}")
    missing = KEY_BINDING_CLAIMS - set(claims)
    if missing:
        raise PresentationRejectedError(f"claims manquants dans le kb-jwt : {sorted(missing)}")
    return claims


def _verify_binding_iat(iat: object) -> None:
    """Contrôle la fraîcheur de l'``iat`` du kb-jwt (± ``IAT_TOLERANCE_SECONDS``).

    Raises:
        PresentationRejectedError: si ``iat`` n'est pas un entier ou sort de la
            fenêtre de tolérance.
    """
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise PresentationRejectedError("iat du kb-jwt invalide")
    if abs(int(time.time()) - iat) > IAT_TOLERANCE_SECONDS:
        raise PresentationRejectedError("iat du kb-jwt hors fenetre de tolerance")


def _verify_key_binding_signature(key_binding: str, issuer_payload: Mapping[str, Any]) -> None:
    """Vérifie la signature du kb-jwt avec la clé de ``cnf.jwk`` du credential.

    Raises:
        PresentationRejectedError: si la clé de liaison est absente ou non EC, ou
            si la signature est invalide.
    """
    cnf = issuer_payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise PresentationRejectedError("cnf.jwk absent du credential")
    try:
        holder_key = ec_public_key(cnf["jwk"])
    except (ValueError, TypeError) as exc:
        raise PresentationRejectedError("cnf.jwk non exploitable (EC P-256 attendu)") from exc
    try:
        pyjwt.decode(
            key_binding,
            holder_key,  # type: ignore[arg-type]  # clé EC hors stubs PyJWT
            algorithms=list(CREDENTIAL_SIGNATURE_ALGORITHMS),
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except pyjwt.PyJWTError as exc:
        raise PresentationRejectedError("signature du kb-jwt invalide") from exc
