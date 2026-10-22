"""Enregistrement automatique d'un client fédéré (OpenID Federation 1.1 §12.1).

Dans le mode ``automatic``, le RP d'une fédération s'identifie auprès de l'OP
par son **Entity Identifier** : l'OP résout la chaîne de confiance de cette
entité et déduit le client de l'entity statement (spec §12.1) — le RP n'a
rien à enregistrer au préalable.
"""

from __future__ import annotations

from collections.abc import Callable

from puridentityserver.application.federation import FederationUseCase
from puridentityserver.domain.authorization import Client
from puridentityserver.domain.federation import derive_client


class TrustChainClientResolver:
    """Dérive un client OIDC de l'entity statement d'un RP fédéré.

    La chaîne de confiance du RP est résolue puis ses metadata
    ``openid_relying_party`` (après politique, spec §6.1) fournissent les
    redirect URI et les clés du client (``derive_client``).
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
        return derive_client(entity_identifier, chain.resolved_metadata())
