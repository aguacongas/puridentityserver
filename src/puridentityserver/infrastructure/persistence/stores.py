"""Conteneur des stores partagés et cycle de vie des stockages.

``Stores`` regroupe les onze repositories de persistance du serveur,
construits une seule fois par ``build_stores`` depuis les ``Settings``.
Le serveur ``full`` partage ces instances entre l'administration et le
protocole ; les serveurs ``admin`` et ``protocol`` isolés les construisent
chacun de leur côté (déploiement séparé sur un magasin partagé).

Le cycle de vie est décomposé en deux étages :

- ``initialise_resources`` / ``close_resources`` : stockages des
  resources administrées (clients, IdentityResources, ApiResources),
  communs à l'administration et au protocole ;
- ``initialise_protocol_stores`` / ``close_protocol_stores`` : stockages
  privés du protocole (clés, codes, jetons, sessions d'appareil…).
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.identity.config import apply_schema
from puridentityserver.infrastructure.persistence.factory import (
    build_api_resource_repository,
    build_authorization_code_repository,
    build_client_repository,
    build_consent_repository,
    build_device_authorization_repository,
    build_identity_resource_repository,
    build_key_pair_repository,
    build_pushed_authorization_repository,
    build_refresh_token_repository,
    build_revoked_token_repository,
    build_user_repository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.repositories.api_resource_repository import (
    ApiResourceRepository,
)
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.consent_repository import ConsentRepository
from puridentityserver.interfaces.repositories.device_authorization_repository import (
    DeviceAuthorizationRepository,
)
from puridentityserver.interfaces.repositories.identity_resource_repository import (
    IdentityResourceRepository,
)
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairRepository
from puridentityserver.interfaces.repositories.pushed_authorization_repository import (
    PushedAuthorizationRepository,
)
from puridentityserver.interfaces.repositories.refresh_token_repository import (
    RefreshTokenRepository,
)
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)
from puridentityserver.interfaces.repositories.user_repository import UserRepository


@dataclass(slots=True)
class Stores:
    """Instances des repositories de persistance du serveur."""

    key_pair: KeyPairRepository
    client: ClientRepository
    code: AuthorizationCodeRepository
    user: UserRepository
    revoked: RevokedTokenRepository
    refresh: RefreshTokenRepository
    device: DeviceAuthorizationRepository
    pushed: PushedAuthorizationRepository
    consent: ConsentRepository
    identity_resource: IdentityResourceRepository
    api_resource: ApiResourceRepository


def build_stores(settings: Settings) -> Stores:
    """Construit les onze repositories selon ``STORAGE_TYPE``/``STORAGE_DSN``."""
    return Stores(
        key_pair=build_key_pair_repository(settings),
        client=build_client_repository(settings),
        code=build_authorization_code_repository(settings),
        user=build_user_repository(settings),
        revoked=build_revoked_token_repository(settings),
        refresh=build_refresh_token_repository(settings),
        device=build_device_authorization_repository(settings),
        pushed=build_pushed_authorization_repository(settings),
        consent=build_consent_repository(settings),
        identity_resource=build_identity_resource_repository(settings),
        api_resource=build_api_resource_repository(settings),
    )


async def initialise_resources(stores: Stores, settings: Settings) -> None:
    """Ouvre les stockages des resources et applique les seeds administrés.

    Commun à l'administration, au protocole et au serveur ``full`` : crée
    le schéma utilisateur (identité), initialise les stores clients et
    resources, puis alimente les IdentityResources/ApiResources seedées.
    """
    await apply_schema()
    await stores.client.initialise()
    await stores.identity_resource.initialise()
    await stores.api_resource.initialise()
    for resource in settings.seed_identity_resources:
        await stores.identity_resource.save(resource)
    for api_resource in settings.seed_api_resources:
        await stores.api_resource.save(api_resource)


async def initialise_protocol_stores(stores: Stores, settings: Settings) -> None:
    """Ouvre les stockages privés du protocole et seeder les clients."""
    await stores.key_pair.initialise()
    await stores.code.initialise()
    await stores.user.initialise()
    await stores.revoked.initialise()
    await stores.refresh.initialise()
    await stores.device.initialise()
    await stores.pushed.initialise()
    await stores.consent.initialise()
    for client in settings.seed_clients:
        await stores.client.save(client)


async def close_resources(stores: Stores) -> None:
    """Ferme les stockages des resources administrées."""
    await stores.client.close()
    await stores.identity_resource.close()
    await stores.api_resource.close()


async def close_protocol_stores(stores: Stores) -> None:
    """Ferme les stockages privés du protocole."""
    await stores.key_pair.close()
    await stores.code.close()
    await stores.user.close()
    await stores.revoked.close()
    await stores.refresh.close()
    await stores.device.close()
    await stores.pushed.close()
    await stores.consent.close()
