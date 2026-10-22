"""OpenID Federation 1.1 : entity statement, chaîne de confiance, résolution.

La spec « OpenID Federation 1.1 » (version finale, 5 mai 2026) définit
l'**entity statement** : un JWT signé décrivant une entité de la fédération
(les clés de signature de l'entité, ses metadata par type d'entité, ses
supérieurs). L'ensemble des statements forme une **chaîne de confiance**,
de l'entité feuille jusqu'à l'ancre de confiance.

Le domaine ne contient que des entités pures et la validation structurelle
(§3.2) : la vérification cryptographique et la résolution de chaîne relèvent
de la couche application.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

#: Type MIME d'un entity statement (spec §15.1).
ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt"

#: Type MIME d'une réponse de résolution (spec §15.3).
RESOLVE_RESPONSE_MEDIA_TYPE = "application/resolve-response+jwt"

#: Type MIME d'un JWK Set signé (spec §15.6).
JWK_SET_MEDIA_TYPE = "application/jwk-set+jwt"

#: Types d'entité standard reconnus (spec §5.1).
STANDARD_ENTITY_TYPES: tuple[str, ...] = (
    "federation_entity",
    "openid_relying_party",
    "openid_provider",
    "oauth_authorization_server",
    "oauth_client",
    "oauth_resource",
)

#: Clés de metadata d'une entité `federation_entity` (spec §5.2.2).
FEDERATION_ENTITY_URL_KEYS: tuple[str, ...] = (
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_historical_keys_endpoint",
    "trust_mark_endpoint",
    "trust_marked_entities_list_endpoint",
    "trust_mark_status_endpoint",
)

#: Opérateurs de metadata policy standard (spec §6.1.3.1).
STANDARD_METADATA_POLICY_OPERATORS: tuple[str, ...] = (
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
)

#: Claims d'entity statement comparés lors d'une comparaison de chaînes.
ENTITY_STATEMENT_CLAIMS: tuple[str, ...] = (
    "iss",
    "sub",
    "jwks",
    "metadata",
    "authority_hints",
    "trust_anchor_hints",
    "constraints",
    "metadata_policy",
    "metadata_policy_crit",
    "source_endpoint",
)

_ENTITY_IDENTIFIER = re.compile(r"^https://[^\s/?#]+(?:[/?][^\s?#]*)?$")


class FederationError(ValueError):
    """Entity statement, chaîne de confiance ou résolution non conforme."""


@dataclass(frozen=True, slots=True)
class EntityStatement:
    """Entity statement d'une entité (spec §3).

    ``issuer`` et ``subject`` sont les Entity Identifiers ; ils sont égaux
    pour une entity configuration (auto-signée) et distincts pour un
    subordinate statement (émis par un supérieur).
    """

    issuer: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    jwks: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    authority_hints: tuple[str, ...] = ()
    trust_anchor_hints: tuple[str, ...] = ()
    trust_marks: tuple[Mapping[str, Any], ...] = ()
    constraints: Mapping[str, Any] | None = None
    metadata_policy: Mapping[str, Any] | None = None
    metadata_policy_crit: tuple[str, ...] = ()
    source_endpoint: str = ""

    @property
    def is_self_signed(self) -> bool:
        """Indique si le statement est une entity configuration (auto-signé)."""
        return self.issuer == self.subject

    @property
    def entity_types(self) -> tuple[str, ...]:
        """Types d'entité déclarés par le statement (spec §5.1)."""
        return tuple(sorted(self.metadata))

    def to_claims(self) -> dict[str, Any]:
        """Sérialise les claims de l'entity statement."""
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": self.subject,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "jwks": dict(self.jwks),
        }
        if self.metadata:
            claims["metadata"] = dict(self.metadata)
        if self.authority_hints:
            claims["authority_hints"] = list(self.authority_hints)
        if self.trust_anchor_hints:
            claims["trust_anchor_hints"] = list(self.trust_anchor_hints)
        if self.trust_marks:
            claims["trust_marks"] = [dict(mark) for mark in self.trust_marks]
        if self.constraints is not None:
            claims["constraints"] = dict(self.constraints)
        if self.metadata_policy is not None:
            claims["metadata_policy"] = dict(self.metadata_policy)
        if self.metadata_policy_crit:
            claims["metadata_policy_crit"] = list(self.metadata_policy_crit)
        if self.source_endpoint:
            claims["source_endpoint"] = self.source_endpoint
        return claims

    def to_claims_for_comparison(self) -> dict[str, Any]:
        """Claims comparables entre deux statements (hors `iat`/`exp`/`trust_marks`).

        La comparaison de chaînes de confiance ignore les claims qui varient
        d'une émission à l'autre (horodatage, expiration, trust marks).
        """
        claims = {
            name: value
            for name, value in self.to_claims().items()
            if name in ENTITY_STATEMENT_CLAIMS
        }
        return claims


@dataclass(frozen=True, slots=True)
class TrustChain:
    """Chaîne de confiance vérifiée (spec §4).

    Les statements vont de l'entité feuille (auto-signé) à l'ancre de
    confiance (auto-signée) ; chaque statement est signé par le précédent.
    """

    statements: tuple[EntityStatement, ...]

    @property
    def subject(self) -> EntityStatement:
        """Entity configuration du sujet de la chaîne (le premier statement)."""
        if not self.statements:
            raise FederationError("Chaîne de confiance vide")
        return self.statements[0]

    @property
    def trust_anchor(self) -> EntityStatement:
        """Entity configuration de l'ancre de confiance (le dernier statement)."""
        if not self.statements:
            raise FederationError("Chaîne de confiance vide")
        return self.statements[-1]

    def resolved_metadata(self) -> dict[str, Any]:
        """Metadata résolues : celles du sujet, après application de la politique.

        La politique de metadata d'un supérieur s'applique à ses subordonnés
        (spec §6.1) ; seule la valeur ``value`` et l'opérateur ``default``
        sont implémentés, les autres opérateurs sont rejetés à la validation.
        """
        metadata = {name: dict(value) for name, value in self.subject.metadata.items()}
        for statement in self.statements[1:]:
            _apply_metadata_policy(statement.metadata_policy or {}, metadata)
        return metadata


def _apply_metadata_policy(policy: Mapping[str, Any], metadata: dict[str, dict[str, Any]]) -> None:
    """Applique la metadata policy d'un supérieur (spec §6.1).

    Seuls les types d'entité présents dans les metadata du sujet sont
    concernés, et un paramètre sans contrainte exploitable est ignoré.
    """
    for entity_type, operators in policy.items():
        values = metadata.get(entity_type)
        if values is None or not isinstance(operators, Mapping):
            continue
        for parameter, constraint in operators.items():
            if not isinstance(constraint, Mapping):
                continue
            resolved = _apply_policy_operator(parameter, constraint, values)
            if resolved is not None:
                values[parameter] = resolved


def _apply_policy_operator(
    parameter: str, constraint: Mapping[str, Any], values: Mapping[str, Any]
) -> object | None:
    """Applique un opérateur de metadata policy (spec §6.1.3.1).

    Seuls ``value`` et ``default`` sont appliqués ; les autres opérateurs
    sont refusés à la validation du statement (ils ne sont pas implémentés).
    """
    if "value" in constraint:
        return cast(object, constraint["value"])
    if "default" in constraint:
        return cast(object, values.get(parameter, constraint["default"]))
    return None


def parse_entity_statement(claims: Mapping[str, Any]) -> EntityStatement:
    """Construit un entity statement depuis ses claims (validation §3.2).

    Seules les règles **structurelles** sont vérifiées ici : présence et type
    des claims obligatoires, forme des metadata et des `authority_hints`. La
    vérification de la signature et de la chaîne relève de la couche
    application.
    """
    issuer = _required_string(claims, "iss")
    subject = _required_string(claims, "sub")
    if not _ENTITY_IDENTIFIER.match(issuer):
        raise FederationError(f"Entity Identifier invalide pour 'iss' : {issuer}")
    if not _ENTITY_IDENTIFIER.match(subject):
        raise FederationError(f"Entity Identifier invalide pour 'sub' : {subject}")
    issued_at = _required_timestamp(claims, "iat")
    expires_at = _required_timestamp(claims, "exp")
    if expires_at <= issued_at:
        raise FederationError("'exp' doit être postérieur à 'iat'")
    jwks = claims.get("jwks")
    if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list):
        raise FederationError("'jwks' doit être un JWK Set")
    metadata = _parse_metadata(claims)
    authority_hints, trust_anchor_hints = _parse_hints(claims)
    policy = claims.get("metadata_policy")
    if policy is not None:
        if not isinstance(policy, Mapping):
            raise FederationError("'metadata_policy' doit être un objet")
        validate_metadata_policy(policy)
    constraints = claims.get("constraints")
    if constraints is not None and not isinstance(constraints, Mapping):
        raise FederationError("'constraints' doit être un objet")
    source_endpoint = claims.get("source_endpoint", "")
    if source_endpoint and not isinstance(source_endpoint, str):
        raise FederationError("'source_endpoint' doit être une chaîne")
    return EntityStatement(
        issuer=issuer,
        subject=subject,
        issued_at=issued_at,
        expires_at=expires_at,
        jwks=dict(jwks),
        metadata={name: dict(value) for name, value in metadata.items()},
        authority_hints=authority_hints,
        trust_anchor_hints=trust_anchor_hints,
        constraints=dict(constraints) if isinstance(constraints, Mapping) else None,
        metadata_policy=dict(policy) if isinstance(policy, Mapping) else None,
        metadata_policy_crit=_string_array(claims, "metadata_policy_crit"),
        source_endpoint=str(source_endpoint),
    )


def validate_metadata_policy(policy: Mapping[str, Any]) -> None:
    """Vérifie la syntaxe d'une metadata policy (spec §6.1.3).

    Seuls les opérateurs standard sont acceptés : un opérateur inconnu
    invaliderait le statement (spec §3.2, étape 18).
    """
    for entity_type, operators in policy.items():
        if not isinstance(operators, Mapping):
            raise FederationError(f"metadata policy invalide pour '{entity_type}'")
        for parameter, constraint in operators.items():
            if not isinstance(constraint, Mapping):
                raise FederationError(
                    f"opérateur de metadata policy invalide pour '{entity_type}.{parameter}'"
                )
            unknown = set(constraint) - set(STANDARD_METADATA_POLICY_OPERATORS)
            if unknown:
                raise FederationError(
                    f"opérateurs de metadata policy non supportés : {sorted(unknown)}"
                )


def _parse_metadata(claims: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    """Valide le claim `metadata` et ses types d'entité (spec §5.1)."""
    metadata = claims.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise FederationError("'metadata' doit être un objet")
    unknown_types = set(metadata) - set(STANDARD_ENTITY_TYPES)
    if unknown_types:
        raise FederationError(f"types d'entité non standard : {sorted(unknown_types)}")
    return {name: dict(value) for name, value in metadata.items()}


def _parse_hints(claims: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Valide les hints de supérieure et d'ancre (spec §3.1.2)."""
    authority_hints = _string_array(claims, "authority_hints")
    trust_anchor_hints = _string_array(claims, "trust_anchor_hints")
    for hint in (*authority_hints, *trust_anchor_hints):
        if not _ENTITY_IDENTIFIER.match(hint):
            raise FederationError(f"Entity Identifier invalide dans les hints : {hint}")
    return authority_hints, trust_anchor_hints


def _validate_metadata_policy(policy: Mapping[str, Any]) -> None:
    """Valide une metadata policy (alias interne)."""
    validate_metadata_policy(policy)


def _required_string(claims: Mapping[str, Any], name: str) -> str:
    """Retourne un claim string obligatoire."""
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise FederationError(f"claim '{name}' requis et non vide")
    return value


def _required_timestamp(claims: Mapping[str, Any], name: str) -> datetime:
    """Retourne un claim timestamp obligatoire (secondes depuis l'époque)."""
    value = claims.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise FederationError(f"claim '{name}' requis et numérique")
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _string_array(claims: Mapping[str, Any], name: str) -> tuple[str, ...]:
    """Retourne un claim tableau de chaînes (vide si absent)."""
    value = claims.get(name)
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise FederationError(f"claim '{name}' doit être un tableau de chaînes")
    return tuple(value)
