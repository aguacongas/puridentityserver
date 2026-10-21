"""Port de persistance des associations OpenID 2.0 (spec de migration).

Le store retient, pour chaque compte OpenID Connect, l'identifiant OpenID 2.0
qui lui est associé : c'est cette association qui permet à l'OP de renvoyer le
claim ``openid2_id`` dans l'ID Token (spec §4) et à l'exploitant de
consulter les anciens identifiants.
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.openid20 import OpenID20Identifier


class OpenID20IdentifierRepository(Protocol):
    """Contrat de stockage des identifiants OpenID 2.0 associés à une `sub`."""

    async def save(self, identifier: OpenID20Identifier) -> None:
        """Enregistre (ou remplace) l'association d'un compte OpenID Connect."""
        ...

    async def find(self, subject: str, realm: str = "") -> OpenID20Identifier | None:
        """Retourne l'association d'un compte pour le `realm` demandé."""
        ...

    async def find_by_identifier(self, identifier: str) -> OpenID20Identifier | None:
        """Retourne l'association portant l'identifiant OpenID 2.0 donné.

        Sert à l'endpoint d'autorité (spec §6) : l'OP doit prouver qu'il est
        bien l'autorité de l'identifiant qu'il a servi.
        """
        ...

    async def find_all(self) -> list[OpenID20Identifier]:
        """Liste toutes les associations connues (consultation d'exploitation)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du stockage."""
        ...
