"""Ports de lecture seule des resources administrées par le serveur.

Frontière de lecture du serveur **protocole** (et, par composition, du
serveur ``full``) : clients, profils utilisateurs, IdentityResources et
ApiResources sont administrés par le serveur **administration** ; le
protocole ne doit jamais les modifier, seulement les lire pour valider
les requêtes, construire les jetons et servir la discovery. Ces ports
n'exposent donc aucune opération d'écriture (pas de ``save``/``delete``).

Le serveur ``full`` partage les mêmes instances de stockage et injecte
les mêmes lecteurs : la frontière est identique que le protocole soit
déployé seul (lecture d'un magasin partagé) ou avec l'administration
(mémoire seule, mono-processus).
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import Client
from puridentityserver.domain.identity_resource import IdentityResource
from puridentityserver.domain.userinfo import UserClaims


class ClientReader(Protocol):
    """Accès en lecture seule au registre des clients OAuth/OIDC."""

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client identifié par ``client_id``, ou ``None``."""
        ...

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients enregistrés."""
        ...

    async def is_cors_origin_allowed(self, origin: str) -> bool:
        """Indique si l'``origin`` est autorisée en CORS par un client actif."""
        ...


class UserReader(Protocol):
    """Accès en lecture seule aux profils utilisateurs (OIDC Core 1.0 §5.3)."""

    async def find_by_subject(self, subject: str) -> UserClaims | None:
        """Retourne le profil identifié par ``subject``, ou ``None``."""
        ...

    async def find_all(self) -> list[UserClaims]:
        """Retourne tous les profils enregistrés."""
        ...


class IdentityResourceReader(Protocol):
    """Accès en lecture seule aux IdentityResources (scopes identité OIDC §5.4)."""

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        ...

    async def find_all(self) -> list[IdentityResource]:
        """Retourne toutes les resources enregistrées."""
        ...


class ApiResourceReader(Protocol):
    """Accès en lecture seule aux ApiResources (scopes d'API protégés)."""

    async def find_by_name(self, name: str) -> ApiResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        ...

    async def find_all(self) -> list[ApiResource]:
        """Retourne toutes les resources enregistrées."""
        ...
