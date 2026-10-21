"""Cas d'usage : résolution des `verified_claims` et metadata eKYC de l'OP.

La spec « OpenID Identity Assurance Schema Definition 1.0 » (version finale)
permet à un RP de demander, via le paramètre OIDC ``claims`` (§5.5), les
claims vérifiés d'un utilisateur : l'OP répond alors avec un membre
``verified_claims`` conforme au schéma.

La résolution applique les règles de la spec :

- un claim demandé **inconnu** de l'OP est omis (aucune erreur) ;
- un claim demandé avec une ``value`` non satisfaite est omis, le membre
  ``verified_claims`` restant présent avec un élément ``claims`` éventuellement
  vide (spec §5.3) ;
- un ``trust_framework`` demandé qui ne correspond pas à celui du profil
  conduit à l'omission **complète** du membre (le RP ne peut pas traiter un
  framework qu'il ne comprend pas).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from puridentityserver.application.claims_request import ClaimsRequest
from puridentityserver.domain.identity_assurance import (
    VerifiedClaims,
    VerifiedClaimsRequest,
    parse_verified_claims,
    parse_verified_claims_request,
)
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.readers import UserReader

#: Nom du membre `verified_claims` dans les claims d'un utilisateur.
VERIFIED_CLAIMS_MEMBER = "verified_claims"

#: Localisations du paramètre `claims` (OIDC Core 1.0 §5.5.1).
ID_TOKEN_LOCATION = "id_token"  # ruff: ignore[hardcoded-password-string]  (localisation, pas un secret)
USERINFO_LOCATION = "userinfo"

#: Clé du payload d'access_token portant la demande eKYC à rejouer.
VERIFIED_CLAIMS_REQUEST_KEY = "verified_claims_request"


class IdentityAssuranceUseCase:
    """Résout les `verified_claims` demandés et expose la metadata eKYC.

    ``claims_provider`` donne accès au profil de l'utilisateur (claims
    vérifiés compris) ; ``user_reader`` permet d'agréger la metadata OP sur
    l'ensemble des profils connus.
    """

    def __init__(
        self,
        claims_provider: ClaimsProvider | None = None,
        user_reader: UserReader | None = None,
    ) -> None:
        """Injection du fournisseur de claims et du lecteur d'utilisateurs."""
        self._claims = claims_provider
        self._users = user_reader

    async def resolve(self, request: VerifiedClaimsRequest, subject: str) -> dict[str, Any] | None:
        """Construit le membre `verified_claims` conforme à la demande.

        Retourne ``None`` quand rien ne peut être servi : profil absent,
        `trust_framework` non satisfait, ou profil non conforme au schéma.
        """
        if self._claims is None or not subject:
            return None
        profile = await self._profile(subject)
        if profile is None:
            return None
        if not request.accepts_trust_framework(profile.trust_framework):
            return None
        if not request.accepts_assurance_level(profile.assurance_level):
            return None
        payload = profile.to_payload()
        payload["claims"] = _selected_claims(profile, request)
        return payload

    async def metadata(self) -> dict[str, tuple[str, ...]]:
        """Metadata eKYC de l'OP, dérivée des profils known.

        Les listes sont vides lorsqu'aucun profil ne porte de claims
        vérifiés : l'OP n'expose alors aucune capacité eKYC.
        """
        if self._users is None:
            return {}
        frameworks: set[str] = set()
        claims: set[str] = set()
        evidence: set[str] = set()
        documents: set[str] = set()
        methods: set[str] = set()
        for user in await self._users.find_all():
            profile = _profile_of(user.claims)
            if profile is None:
                continue
            frameworks.add(profile.trust_framework)
            claims.update(profile.claim_names)
            evidence.update(profile.evidence_types)
            documents.update(profile.document_types)
            methods.update(profile.check_methods)
        return {
            "trust_frameworks_supported": tuple(sorted(frameworks)),
            "claims_in_verified_claims_supported": tuple(sorted(claims)),
            "evidence_supported": tuple(sorted(evidence)),
            "documents_supported": tuple(sorted(documents)),
            "documents_check_methods_supported": tuple(sorted(methods)),
        }

    async def _profile(self, subject: str) -> VerifiedClaims | None:
        """Profil `verified_claims` d'un utilisateur (``None`` si absent)."""
        if self._claims is None:
            return None
        user_claims = await self._claims.get_claims(subject)
        return _profile_of(user_claims.claims)


def _profile_of(claims: Mapping[str, Any]) -> VerifiedClaims | None:
    """Extrait et valide le profil `verified_claims` d'un mapping de claims."""
    raw = claims.get(VERIFIED_CLAIMS_MEMBER)
    if raw is None:
        return None
    try:
        return parse_verified_claims(raw)
    except ValueError:
        # Un profil non conforme n'est jamais servi tel quel : il est omis.
        return None


def verified_claims_request(
    claims_request: ClaimsRequest | None, location: str
) -> VerifiedClaimsRequest | None:
    """Demande eKYC portée par le member `verified_claims` d'une localisation.

    ``location`` vaut ``id_token`` ou ``userinfo`` (OIDC Core 1.0 §5.5.1).
    ``None`` quand le member n'est pas demandé : le membre `verified_claims`
    ne doit alors pas être rendu du tout dans cette localisation.
    """
    if claims_request is None:
        return None
    raw = (
        claims_request.raw_id_token
        if location == ID_TOKEN_LOCATION
        else claims_request.raw_userinfo
    )
    if VERIFIED_CLAIMS_MEMBER not in raw:
        return None
    try:
        return parse_verified_claims_request(raw[VERIFIED_CLAIMS_MEMBER])
    except ValueError:
        return None


def verified_claims_request_from_payload(payload: object) -> VerifiedClaimsRequest | None:
    """Demande eKYC rejouée depuis le payload d'un access_token.

    Le payload mémorise la demande brute du member ``userinfo`` : sans elle,
    les contraintes de valeur (spec IA-5.7.4) seraient perdues et l'endpoint
    ``/userinfo`` ne pourrait pas distinguer une valeur exigée d'une valeur
    simplement demandée. ``None`` quand aucune demande n'a été mémorisée.
    """
    if not isinstance(payload, Mapping):
        return None
    if VERIFIED_CLAIMS_REQUEST_KEY not in payload:
        return None
    try:
        return parse_verified_claims_request(payload[VERIFIED_CLAIMS_REQUEST_KEY])
    except ValueError:
        return None


def verified_claims_payload(
    claims_request: ClaimsRequest | None,
) -> dict[str, Any] | None:
    """Demande eKYC brute à mémoriser dans l'access_token (member userinfo).

    ``None`` si le member ``userinfo`` ne demande rien : le payload reste
    alors inchangé.
    """
    if claims_request is None:
        return None
    member = claims_request.raw_userinfo.get(VERIFIED_CLAIMS_MEMBER)
    if member is None:
        return None
    return {VERIFIED_CLAIMS_REQUEST_KEY: member}


def _selected_claims(profile: VerifiedClaims, request: VerifiedClaimsRequest) -> dict[str, Any]:
    """Claims vérifiés retenus pour la demande (spec §5.3 et IA-5.7.4)."""
    selected: dict[str, Any] = {}
    for name in request.claim_names:
        if name not in profile.claims:
            continue
        value = profile.claims[name]
        demanded = request.claim_values.get(name)
        if demanded is not None and demanded != value:
            # Valeur exigée non satisfaite : le claim est omis.
            continue
        selected[name] = value
    return selected
