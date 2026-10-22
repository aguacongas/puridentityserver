"""Enregistrement automatique d'un client fédéré (OpenID Federation 1.1 §12.1).

Dans le mode ``automatic``, le RP d'une fédération s'identifie auprès de l'OP
par son **Entity Identifier** : l'OP résout la chaîne de confiance de cette
entité et déduit le client de l'entity statement (spec §12.1) — le RP n'a
rien à enregistrer au préalable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from puridentityserver.application.federation import FederationUseCase
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
)


class TrustChainClientResolver:
    """Dérive un client OIDC de l'entity statement d'un RP fédéré.

    Les metadata du RP sont lues dans le type d'entité ``openid_relying_party``
    de l'entity statement (spec §5.1) : URI de redirection, clés publiques
    (``jwks``) et méthode d'authentification. Un client dérivé est **public**
    et s'authentifie par ``private_key_jwt`` avec ses clés de fédération.
    """

    def __init__(self, federation: Callable[[], FederationUseCase | None]) -> None:
        """Injection d'un accès paresseux au cas d'usage de la Fédération.

        L'appelable est résolu à chaque demande : le cas d'usage de la
        Fédération est construit après les lecteurs (il a besoin du
        discovery), la résolution Client ne l'est qu'à la demande d'un
        client.
        """
        self._federation = federation

    async def resolve(self, entity_identifier: str) -> Client | None:
        """Résout le client fédéré identifié par ``entity_identifier``.

        ``None`` si l'entité n'est pas dans une chaîne de confiance acceptée
        ou si ses metadata ne permettent pas de dériver un client.
        """
        federation = self._federation()
        if federation is None:
            return None
        chain = await federation.resolve_trust_chain(entity_identifier, "")
        if chain is None:
            return None
        metadata = chain.resolved_metadata().get("openid_relying_party")
        if not isinstance(metadata, Mapping):
            return None
        redirect_uris = metadata.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return None
        jwks = metadata.get("jwks")
        if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list):
            return None
        return Client(
            client_id=entity_identifier,
            redirect_uris=frozenset(str(uri) for uri in redirect_uris),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.PUBLIC,
            token_endpoint_auth_method=TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
            jwks=tuple(_key_of(item) for item in jwks["keys"]),
            is_active=True,
        )


def _key_of(item: object) -> dict[str, Any]:
    """Clé publique JWK d'un JWK Set (spec §5.1)."""
    if not isinstance(item, Mapping):
        return {}
    return {str(name): value for name, value in item.items()}
