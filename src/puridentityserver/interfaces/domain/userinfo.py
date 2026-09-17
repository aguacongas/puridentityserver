"""Port de résolution des claims utilisateur (OIDC Core 1.0 §5.3).

Le port isole la couche application de la source de vérité des profils
utilisateurs : l'infrastructure fournit une implémentation qui s'appuie
sur le user store (``UserRepository``), prête à être remplacée par un
autre backend (LDAP, API…).
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.userinfo import UserClaims


class ClaimsProvider(Protocol):
    """Interface de résolution des claims d'un utilisateur par ``sub``.

    Les implémentations concrètes (mémoire pour la démo, SQL/LDAP plus
    tard) sont fournies en infrastructure et choisies à la composition
    root selon la configuration du serveur.
    """

    async def get_claims(self, subject: str) -> UserClaims:
        """Retourne les claims de l'utilisateur identifié par ``subject``."""
        ...
