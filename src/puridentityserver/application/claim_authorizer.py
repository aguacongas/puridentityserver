"""Autorisation d'un jeton Bearer par claim configurable.

``BearerClaimAuthorizer`` valide d'abord le JWT (port
``BearerTokenVerifier`` : signature, ``iss``, ``exp``) puis exige qu'un
claim configurable porte une valeur autorisée. Le claim ``scope`` (chaîne
séparée par des espaces) est interprété comme une appartenance ; les autres
claims sont comparés par égalité (valeur unique ou liste).
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.interfaces.domain.bearer import BearerTokenVerifier


@dataclass(frozen=True, slots=True)
class ClaimRule:
    """Claim attendu et valeurs autorisées (``scope`` : appartenance)."""

    claim_name: str
    allowed_values: frozenset[str]

    def matches(self, claims: dict[str, object]) -> bool:
        """Vrai si ``claims`` porte le claim attendu avec une valeur autorisée."""
        value = claims.get(self.claim_name)
        if value is None:
            return False
        if isinstance(value, str):
            if self.claim_name == "scope":
                return bool(self.allowed_values.intersection(value.split()))
            return value in self.allowed_values
        if isinstance(value, (list, tuple)):
            return any(str(item) in self.allowed_values for item in value)
        return False


class BearerClaimAuthorizer:
    """Valide un JWT puis vérifie le claim configuré (jeton de gestion)."""

    def __init__(self, verifier: BearerTokenVerifier, rule: ClaimRule) -> None:
        """Injection du vérificateur de jeton et de la règle de claim."""
        self._verifier = verifier
        self._rule = rule

    async def authorise(self, token: str) -> bool:
        """Vrai si le jeton est valide et porte le claim attendu."""
        claims = await self._verifier.verify(token)
        if claims is None:
            return False
        return self._rule.matches(claims)
