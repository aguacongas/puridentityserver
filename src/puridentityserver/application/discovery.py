"""Cas d'utilisation : découverte du serveur OpenID Connect (Discovery 1.0).

Construit le document ``/.well-known/openid-configuration`` : endpoints du
serveur plus ``scopes_supported`` / ``claims_supported`` dérivés des
IdentityResources enregistrées (OIDC Core 1.0 §5.4). Sans repository
injecté, les resources par défaut s'appliquent.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES
from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS
from puridentityserver.interfaces.repositories.readers import (
    ApiResourceReader,
    IdentityResourceReader,
)


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Configuration de base de l'émission du document de discovery."""

    issuer: str
    base_url: str = ""
    registration_enabled: bool = False
    par_enabled: bool = True
    signing_algorithms: tuple[str, ...] = tuple(
        algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS
    )


class DiscoveryUseCase:
    """Produit les métadonnées de discovery depuis la configuration de l'émetteur."""

    def __init__(
        self,
        config: DiscoveryConfig,
        identity_resources: IdentityResourceReader | None = None,
        api_resources: ApiResourceReader | None = None,
    ) -> None:
        """Injection de la configuration de l'émetteur et des registres de resources."""
        self._config = config
        self._identity_resources = identity_resources
        self._api_resources = api_resources

    async def execute(self) -> dict[str, object]:
        """Construit les métadonnées OIDC Discovery (§3 OIDC Discovery 1.0)."""
        base = self._resolve_base_url()
        scopes_supported, claims_supported = await self._scopes_and_claims()
        metadata: dict[str, object] = {
            "issuer": self._config.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "userinfo_endpoint": f"{base}/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "introspection_endpoint": f"{base}/introspect",
            "revocation_endpoint": f"{base}/revoke",
            "end_session_endpoint": f"{base}/end_session",
            "device_authorization_endpoint": f"{base}/device_authorization",
            "id_token_signing_alg_values_supported": list(self._config.signing_algorithms),
            "scopes_supported": scopes_supported,
            "claims_supported": claims_supported,
        }
        if self._config.registration_enabled:
            metadata["registration_endpoint"] = f"{base}/register"
        if self._config.par_enabled:
            metadata["pushed_authorization_request_endpoint"] = f"{base}/par"
        return metadata

    async def _scopes_and_claims(self) -> tuple[list[str], list[str]]:
        """Scopes et claims publiés, dérivés des IdentityResources + scopes d'API."""
        resources = DEFAULT_IDENTITY_RESOURCES
        if self._identity_resources is not None:
            stored = await self._identity_resources.find_all()
            if stored:
                resources = tuple(stored)
        scopes = [resource.name for resource in resources if resource.show_in_discovery_document]
        claims: list[str] = []
        seen: set[str] = set()
        for resource in resources:
            for claim in sorted(resource.user_claims):
                if claim not in seen:
                    seen.add(claim)
                    claims.append(claim)
        scopes.extend(sorted(await self._api_scope_names()))
        return scopes, claims

    async def _api_scope_names(self) -> set[str]:
        """Scopes d'API déclarés par les ApiResources enregistrées."""
        if self._api_resources is None:
            return set()
        stored = await self._api_resources.find_all()
        return {scope for resource in stored for scope in resource.scopes}

    def _resolve_base_url(self) -> str:
        return (self._config.base_url or self._config.issuer).rstrip("/")
