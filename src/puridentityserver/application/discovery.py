"""Cas d'utilisation du serveur OpenID Connect."""

from dataclasses import dataclass

from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Configuration de base de l'émission du document de discovery."""

    issuer: str
    base_url: str = ""
    signing_algorithms: tuple[str, ...] = tuple(
        algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS
    )


class DiscoveryUseCase:
    """Produit les métadonnées de discovery depuis la configuration de l'émetteur."""

    def __init__(self, config: DiscoveryConfig) -> None:
        """Injection de la configuration de l'émetteur."""
        self._config = config

    def execute(self) -> dict[str, object]:
        """Construit les métadonnées OIDC Discovery (§3 OIDC Discovery 1.0)."""
        base = self._resolve_base_url()
        return {
            "issuer": self._config.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "userinfo_endpoint": f"{base}/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "introspection_endpoint": f"{base}/introspect",
            "revocation_endpoint": f"{base}/revoke",
            "end_session_endpoint": f"{base}/end_session",
            "id_token_signing_alg_values_supported": list(self._config.signing_algorithms),
        }

    def _resolve_base_url(self) -> str:
        return (self._config.base_url or self._config.issuer).rstrip("/")
