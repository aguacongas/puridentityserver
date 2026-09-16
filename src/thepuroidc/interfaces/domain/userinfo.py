"""Port de résolution des claims utilisateur (OIDC Core 1.0 §5.3).

Le port isole la couche application de la source de vérité des profils
utilisateurs : l'infrastructure fournit l'implémentation de démonstration
en mémoire, prête à être remplacée par un vrai user store.
"""

from __future__ import annotations

from typing import Protocol

from thepuroidc.domain.userinfo import UserClaims


class ClaimsProvider(Protocol):
    """Interface de résolution des claims d'un utilisateur par ``sub``.

    Les implémentations concrètes (mémoire pour la démo, SQL/LDAP plus
    tard) sont fournies en infrastructure et choisies à la composition
    root selon la configuration du serveur.
    """

    def get_claims(self, subject: str) -> UserClaims:
        """Retourne les claims de l'utilisateur identifié par ``subject``."""
        ...
