"""Port de persistance des profils utilisateurs (OIDC Core 1.0 §5.3)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.userinfo import UserClaims


class UserRepository(Protocol):
    """Contrat de stockage des profils utilisateurs.

    Le port définit les opérations nécessaires au cycle de vie des
    profils (enregistrement, recherche par ``subject``) ainsi que son
    cycle de vie propre (initialisation du schéma, libération des
    ressources). Les implémentations concrètes (mémoire, SQL, …) sont
    fournies en infrastructure et choisies à la composition root selon
    la configuration du serveur.
    """

    async def save(self, user: UserClaims) -> None:
        """Enregistre le profil utilisateur (insertion ou mise à jour par ``subject``)."""
        ...

    async def save_all(self, users: list[UserClaims]) -> None:
        """Enregistre plusieurs profils en une seule opération (seed)."""
        ...

    async def find_by_subject(self, subject: str) -> UserClaims | None:
        """Retourne le profil identifié par ``subject``, ou ``None``."""
        ...

    async def find_all(self) -> list[UserClaims]:
        """Retourne tous les profils enregistrés."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
