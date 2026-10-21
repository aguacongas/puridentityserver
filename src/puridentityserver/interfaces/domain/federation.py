"""Ports de la Fédération (OpenID Federation 1.1).

L'entity statement est un JWT générique (ni un ``id_token``, ni un
``access_token``) : il lui faut un signataire et un vérificateur dédiés, ainsi
qu'un lecteur d'entity statements distants (les statements de la hiérarchie
sont publiés par les entités supérieures).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from puridentityserver.domain.jwks import JWTAlgorithm


class FederationTokenManager(Protocol):
    """Signature et vérification des entity statements (spec §3, §15.1)."""

    async def sign_entity_statement(
        self,
        *,
        algorithm: JWTAlgorithm,
        claims: Mapping[str, Any],
        key_id: str,
    ) -> str:
        """Signe un entity statement (JWS compact, en-tête ``typ`` dédié).

        L'en-tête ``typ`` vaut ``entity-statement+jwt`` (spec §3) et porte le
        ``kid`` de la clé de signature (spec §3) : sans eux, le statement est
        rejeté à la validation.
        """
        ...

    async def unverified_claims(self, token: str) -> dict[str, Any] | None:
        """Décode les claims d'un entity statement **sans** vérifier la signature.

        Permet de lire le claim ``jwks`` d'un statement auto-signé, clé
        fournie par l'entity statement lui-même (spec §3.2, étape 10).
        """
        ...

    async def verify_entity_statement(
        self,
        *,
        token: str,
        jwks: Mapping[str, Any],
        issuer: str = "",
        subject: str = "",
    ) -> dict[str, Any] | None:
        """Vérifie la signature d'un entity statement contre un JWK Set.

        ``issuer`` et ``subject``, lorsqu'ils sont fournis, doivent
        correspondre aux claims ``iss``/``sub`` (spec §3.2, étapes 4 et 5).
        Retourne les claims vérifiés, ``None`` si le statement est invalide
        (signature, ``typ``, expiration, émetteur ou sujet inattendu).
        """
        ...


class FederationEntityFetcher(Protocol):
    """Lecture d'un entity statement distant (spec §8.1, §9)."""

    async def fetch_entity_statement(self, url: str) -> str | None:
        """Lit l'entity statement publié à ``url`` ; ``None`` si inaccessible."""
        ...


class FederationKeyProvider(Protocol):
    """Clés publiques de l'entité pour le claim ``jwks`` (spec §3.1.1)."""

    async def public_jwks(self) -> dict[str, Any]:
        """Retourne le JWK Set des clés de signature de l'entité."""
        ...


class FederationMetadataProvider(Protocol):
    """Metadata de l'OP publiées dans l'entity statement (spec §5.2)."""

    async def federation_metadata(self) -> Mapping[str, Any]:
        """Retourne les metadata par type d'entité (``openid_provider``…)."""
        ...
