"""Identité assurance : les `verified_claims` (OpenID Identity Assurance).

La spec « OpenID Identity Assurance Schema Definition 1.0 incorporating errata
set 1 » (version finale, 1er juillet 2026) définit le claim ``verified_claims``
: un conteneur qui porte les claims vérifiés d'un utilisateur **et** les
métadonnées du processus de vérification.

Le domaine ne contient que des entités pures et la validation du schéma (aucune
dépendance vers FastAPI, SQLAlchemy ou PyJWT).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

#: Types d'evidence définis par la spec (§5.4.4.1).
EVIDENCE_TYPES: tuple[str, ...] = (
    "document",
    "electronic_record",
    "vouch",
    "electronic_signature",
)

#: Membres autorisés sous ``verification`` (spec §5.4.2).
_VERIFICATION_MEMBERS: frozenset[str] = frozenset(
    {
        "trust_framework",
        "assurance_level",
        "assurance_process",
        "time",
        "verification_process",
        "evidence",
    }
)

#: Membres autorisés sous ``assurance_process`` (spec §5.4.2.3).
_ASSURANCE_PROCESS_MEMBERS: frozenset[str] = frozenset({"policy", "procedure", "assurance_details"})


class VerifiedClaimsError(ValueError):
    """Profil `verified_claims` non conforme au schéma de la spec."""


@dataclass(frozen=True, slots=True)
class VerifiedClaims:
    """Payload `verified_claims` d'un utilisateur (membre racine).

    ``trust_framework`` est obligatoire (spec §5.4.2.3.1) ; ``claims`` peut
    être vide (spec §5.3 : « The ``claims`` element may be empty »). Les
    autres membres de ``verification`` sont optionnels.
    """

    trust_framework: str
    claims: Mapping[str, Any] = field(default_factory=dict)
    assurance_level: str = ""
    verification_process: str = ""
    time: str = ""
    assurance_process: Mapping[str, Any] = field(default_factory=dict)
    evidence: tuple[Mapping[str, Any], ...] = ()

    def to_payload(self) -> dict[str, Any]:
        """Sérialise le membre ``verified_claims`` (sans l'enveloppe racine).

        Le résultat est directement insérable comme claim de l'``id_token`` ou
        du corps du ``/userinfo`` : ``{"verification": {...}, "claims": {...}}``.
        """
        verification: dict[str, Any] = {"trust_framework": self.trust_framework}
        if self.assurance_level:
            verification["assurance_level"] = self.assurance_level
        if self.verification_process:
            verification["verification_process"] = self.verification_process
        if self.time:
            verification["time"] = self.time
        if self.assurance_process:
            verification["assurance_process"] = dict(self.assurance_process)
        if self.evidence:
            verification["evidence"] = [dict(item) for item in self.evidence]
        return {"verification": verification, "claims": dict(self.claims)}

    @property
    def claim_names(self) -> tuple[str, ...]:
        """Noms des claims vérifiés portés par le profil (triés)."""
        return tuple(sorted(self.claims))

    @property
    def evidence_types(self) -> tuple[str, ...]:
        """Types d'evidence utilisés par le profil (triés, sans doublon)."""
        return tuple(sorted({str(item.get("type", "")) for item in self.evidence}))

    @property
    def document_types(self) -> tuple[str, ...]:
        """Types de document cités par les preuves (triés, sans doublon)."""
        types = {
            str(item.get("document_details", {}).get("type", ""))
            for item in self.evidence
            if isinstance(item.get("document_details"), Mapping)
        }
        return tuple(sorted(types - {""}))

    @property
    def check_methods(self) -> tuple[str, ...]:
        """Méthodes de contrôle citées par les preuves (triées, sans doublon)."""
        methods: set[str] = set()
        for item in self.evidence:
            details = item.get("check_details")
            if not isinstance(details, list):
                continue
            for detail in details:
                if isinstance(detail, Mapping):
                    methods.add(str(detail.get("check_method", "")))
        return tuple(sorted(methods - {""}))


@dataclass(frozen=True, slots=True)
class VerifiedClaimsRequest:
    """Demande eKYC : member `verified_claims` du paramètre OIDC `claims`.

    Les contraintes de la spec sont conservées : ``trust_framework`` (valeur
    ou liste de valeurs admises) et, pour chaque claim demandé, la valeur
    exigée et son caractère ``essential``.
    """

    trust_framework: str = ""
    trust_frameworks: tuple[str, ...] = ()
    assurance_level: str = ""
    assurance_levels: tuple[str, ...] = ()
    claim_names: tuple[str, ...] = ()
    claim_values: Mapping[str, str] = field(default_factory=dict)
    essential_claims: frozenset[str] = frozenset()

    def constrains_trust_framework(self) -> bool:
        """Indique si la demande impose un `trust_framework` particulier."""
        return bool(self.trust_framework or self.trust_frameworks)

    def accepts_trust_framework(self, framework: str) -> bool:
        """Indique si le `trust_framework` disponible satisfait la demande."""
        if not self.constrains_trust_framework():
            return True
        if self.trust_framework:
            return framework == self.trust_framework
        return framework in self.trust_frameworks

    def constrains_assurance_level(self) -> bool:
        """Indique si la demande impose un `assurance_level` particulier."""
        return bool(self.assurance_level or self.assurance_levels)

    def accepts_assurance_level(self, level: str) -> bool:
        """Indique si le `assurance_level` disponible satisfait la demande."""
        if not self.constrains_assurance_level():
            return True
        if self.assurance_level:
            return level == self.assurance_level
        return level in self.assurance_levels


def parse_verified_claims(raw: object) -> VerifiedClaims:
    """Valide un profil `verified_claims` brut et le convertit en entité.

    Le profil vient du store utilisateur (semé ou administration) : il est
    contrôlé **strictement** (spec §5.2, §5.4) — un profil non conforme est
    rejeté plutôt que servi tel quel.

    Raises:
        VerifiedClaimsError: si le profil ne respecte pas le schéma.
    """
    payload = _as_mapping(raw, "verified_claims")
    unknown = set(payload) - {"verification", "claims"}
    if unknown:
        raise VerifiedClaimsError(f"membres inattendus sous 'verified_claims' : {sorted(unknown)}")
    verification = _as_mapping(payload.get("verification"), "verified_claims.verification")
    claims = payload.get("claims")
    if not isinstance(claims, Mapping):
        raise VerifiedClaimsError("'verified_claims.claims' doit être un objet")
    unknown_verification = set(verification) - _VERIFICATION_MEMBERS
    if unknown_verification:
        raise VerifiedClaimsError(
            f"membres inattendus sous 'verification' : {sorted(unknown_verification)}"
        )
    framework = verification.get("trust_framework")
    if not isinstance(framework, str) or not framework:
        raise VerifiedClaimsError("'verification.trust_framework' doit être une chaîne non vide")
    assurance_level = _optional_string(verification, "assurance_level")
    verification_process = _optional_string(verification, "verification_process")
    time = _optional_string(verification, "time")
    assurance_process = _parse_assurance_process(verification.get("assurance_process"))
    evidence = _parse_evidence(verification.get("evidence"))
    return VerifiedClaims(
        trust_framework=framework,
        claims=dict(claims),
        assurance_level=assurance_level,
        verification_process=verification_process,
        time=time,
        assurance_process=assurance_process,
        evidence=evidence,
    )


def parse_verified_claims_request(raw: object) -> VerifiedClaimsRequest:
    """Analyse la demande eKYC (member `verified_claims` du paramètre `claims`).

    La structure suit le schéma de requête de la spec : ``verification``
    porte la contrainte de `trust_framework`, ``claims`` porte les claims
    demandés avec leurs contraintes (``essential``, ``value``).
    """
    if raw is None:
        return VerifiedClaimsRequest()
    payload = _as_mapping(raw, "verified_claims")
    verification = payload.get("verification")
    framework, frameworks = _constrainable(verification, "trust_framework")
    level, levels = _constrainable(verification, "assurance_level")
    claim_names: list[str] = []
    claim_values: dict[str, str] = {}
    essential: set[str] = set()
    claims = payload.get("claims")
    if isinstance(claims, Mapping):
        for name, claim_constraint in claims.items():
            claim_names.append(str(name))
            parsed = _constraint(claim_constraint, f"claims.{name}")
            if parsed is None:
                continue
            value = parsed.get("value")
            if isinstance(value, str):
                claim_values[str(name)] = value
            if parsed.get("essential") is True:
                essential.add(str(name))
    return VerifiedClaimsRequest(
        trust_framework=framework,
        trust_frameworks=frameworks,
        assurance_level=level,
        assurance_levels=levels,
        claim_names=tuple(claim_names),
        claim_values=claim_values,
        essential_claims=frozenset(essential),
    )


def _as_mapping(value: object, path: str) -> Mapping[str, Any]:
    """Vérifie qu'une valeur est un objet JSON et la retourne."""
    if not isinstance(value, Mapping):
        raise VerifiedClaimsError(f"'{path}' doit être un objet")
    return value


def _optional_string(payload: Mapping[str, Any], name: str) -> str:
    """Retourne un membre de `verification` s'il est une chaîne (sinon vide)."""
    value = payload.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise VerifiedClaimsError(f"'verification.{name}' doit être une chaîne")
    return value


def _parse_assurance_process(raw: object) -> Mapping[str, Any]:
    """Valide le membre `assurance_process` (spec §5.4.2.3)."""
    if raw is None:
        return {}
    payload = _as_mapping(raw, "verification.assurance_process")
    unknown = set(payload) - _ASSURANCE_PROCESS_MEMBERS
    if unknown:
        raise VerifiedClaimsError(
            f"membres inattendus sous 'assurance_process' : {sorted(unknown)}"
        )
    for name in ("policy", "procedure"):
        value = payload.get(name)
        if value is not None and not isinstance(value, str):
            raise VerifiedClaimsError(f"'assurance_process.{name}' doit être une chaîne")
    details = payload.get("assurance_details")
    if details is not None and (not isinstance(details, list) or not details):
        raise VerifiedClaimsError(
            "'assurance_process.assurance_details' doit être une liste non vide"
        )
    return dict(payload)


def _parse_evidence(raw: object) -> tuple[Mapping[str, Any], ...]:
    """Valide le membre `evidence` (spec §5.4.4)."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise VerifiedClaimsError("'verification.evidence' doit être une liste non vide")
    parsed: list[Mapping[str, Any]] = []
    for item in raw:
        entry = _as_mapping(item, "verification.evidence[]")
        evidence_type = entry.get("type")
        if evidence_type not in EVIDENCE_TYPES:
            raise VerifiedClaimsError(f"'evidence.type' doit valoir l'un de {list(EVIDENCE_TYPES)}")
        parsed.append(dict(entry))
    return tuple(parsed)


def _constrainable(verification: object, name: str) -> tuple[str, tuple[str, ...]]:
    """Lit une contrainte ``value``/``values`` d'un membre de `verification`.

    Le schéma de requête de la spec autorise ``null`` (aucune contrainte),
    ``{"value": …}`` ou ``{"values": [ … ]}`` pour un membre contraint
    (``trust_framework``, ``assurance_level``).
    """
    if not isinstance(verification, Mapping):
        return "", ()
    constraint = _constraint(verification.get(name), name)
    if constraint is None:
        return "", ()
    value = constraint.get("value")
    values = constraint.get("values")
    single = value if isinstance(value, str) else ""
    multiple = tuple(str(item) for item in values) if isinstance(values, list) else ()
    return single, multiple


def _constraint(raw: object, path: str) -> Mapping[str, Any] | None:
    """Valide une contrainte de requête (`null` ou objet `essential`/`value`)."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise VerifiedClaimsError(f"'{path}' doit être null ou un objet")
    return raw
