"""Cas d'usage : association d'un compte OpenID Connect à un identifiant OpenID 2.0.

La spec « OpenID 2.0 to OpenID Connect Migration 1.0 » permet à un RP
OpenID 2.0 de relier l'identifiant historique d'un utilisateur à son `sub`
OpenID Connect : l'OP garde l'association et la restitue dans le claim
``openid2_id`` de l'ID Token lorsque le RP demande le scope ``openid2``.

Le support est **désactivé par défaut** (`openid20_migration_enabled`) : sans
activation, aucune association n'est constituée, le scope ``openid2`` n'est pas
accepté et aucun claim ``openid2_id`` n'est émis.
"""

from __future__ import annotations

from puridentityserver.domain.openid20 import OpenID20Identifier
from puridentityserver.interfaces.repositories.openid20_identifier_repository import (
    OpenID20IdentifierRepository,
)


class OpenID20MigrationUseCase:
    """Gère les associations entre un compte OpenID Connect et un identifiant 2.0.

    Sans le drapeau ``enabled``, les opérations sont neutres : aucune
    association n'est enregistrée et l'identifiant d'un compte reste vide.
    """

    def __init__(self, repository: OpenID20IdentifierRepository, *, enabled: bool = False) -> None:
        """Injection du store et de l'indicateur d'activation."""
        self._repository = repository
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Indique si le support de la migration est activé."""
        return self._enabled

    async def link(self, subject: str, identifier: str, realm: str = "") -> OpenID20Identifier:
        """Associe un identifiant OpenID 2.0 à un compte OpenID Connect.

        L'association remplace l'éventuelle association précédente du même
        couple (compte, `realm`).
        """
        association = OpenID20Identifier(subject=subject, identifier=identifier, realm=realm)
        if not self._enabled:
            return association
        await self._repository.save(association)
        return association

    async def identifier_for(self, subject: str, realm: str = "") -> str:
        """Retourne l'identifiant OpenID 2.0 associé au compte (vide si aucun).

        Le `realm` demandé doit correspondre à celui de l'association : la
        spec impose que le RP fournisse le `openid.realm` quand la réponse
        OpenID 2.0 a été appariée (spec §2, §3).
        """
        if not self._enabled:
            return ""
        association = await self._repository.find(subject, realm)
        return association.identifier if association is not None else ""

    async def all_identifiers(self) -> list[OpenID20Identifier]:
        """Liste les associations connues (consultation d'exploitation)."""
        if not self._enabled:
            return []
        return await self._repository.find_all()

    async def find_by_identifier(self, identifier: str) -> OpenID20Identifier | None:
        """Retourne l'association portant l'identifiant OpenID 2.0 donné.

        Sert à l'endpoint d'autorité (spec §6) : l'OP doit prouver qu'il est
        l'autorité de l'identifiant qu'il a servi dans l'ID Token.
        """
        if not self._enabled:
            return None
        return await self._repository.find_by_identifier(identifier)
