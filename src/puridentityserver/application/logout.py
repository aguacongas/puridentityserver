"""Cas d'utilisation RP-Initiated Logout (OIDC Core 1.0 §5, OIDC RP-Initiated Logout 1.0).

Termine la session de l'utilisateur au serveur et, le cas échéant,
redirige le user agent vers l'URI de sortie enregistrée par le client.

Contrats OIDC respectés :

- ``id_token_hint`` : l'id_token fourni est validé (signature JWKS du
  serveur, émetteur). Un jeton d'un autre émetteur, expiré, ou dont le
  ``aud`` ne résout vers aucun client enregistré est traité comme
  invalide → l'op est notifiée, la session n'est pas terminée.
- ``post_logout_redirect_uri`` : seules les URI préalablement
  enregistrées (``post_logout_redirect_uris`` du client) sont acceptées ;
  toute autre valeur est rejetée (anti open-redirect).
- ``state`` : renvoyé tel quel dans la redirection de sortie afin que le
  client puisse relier la réponse à sa demande.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.domain.authorization import Client
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.client_repository import ClientRepository


@dataclass(frozen=True, slots=True)
class LogoutConfig:
    """Configuration de l'endpoint de terminaison de session."""

    issuer: str


@dataclass(frozen=True, slots=True)
class LogoutRequest:
    """Demande RP-Initiated Logout (OIDC Core 1.0 §5.2)."""

    id_token_hint: str = ""
    post_logout_redirect_uri: str = ""
    state: str = ""


@dataclass(frozen=True, slots=True)
class LogoutResult:
    """Sortie de la terminaison : redirection et traçabilité côté client.

    ``post_logout_redirect_uri`` n'est renseigné que si l'URI demandée est
    enregistrée ; sinon l'op affiche une page de confirmation générique.
    """

    post_logout_redirect_uri: str = ""
    state: str = ""
    subject: str = ""
    client_id: str = ""


@dataclass(frozen=True, slots=True)
class LogoutError:
    """Rejet de la demande (hint invalide ou URI de sortie non enregistrée)."""

    error: str
    error_description: str = ""


class LogoutUseCase:
    """Résout la demande de logout et décide de la redirection de sortie.

    La session RP (cookie de l'op) est purgée par la couche API ; le
    usecase se concentre sur les règles OIDC : validation de l'``id_token_hint``,
    résolution du client et contrôle de l'``post_logout_redirect_uri``.
    """

    def __init__(
        self,
        config: LogoutConfig,
        client_repository: ClientRepository,
        token_manager: TokenManager,
    ) -> None:
        """Injection de la configuration et des dépendances du périmètre."""
        self._config = config
        self._client_repository = client_repository
        self._token_manager = token_manager

    async def execute(self, request: LogoutRequest) -> LogoutResult | LogoutError:
        """Traite une demande de RP-Initiated Logout.

        Retourne :

        - ``LogoutError.invalid_request`` si l'``id_token_hint`` est
          invalide (signature, émetteur, client inconnu) ou si
          l'``post_logout_redirect_uri`` n'est pas enregistrée ;
        - ``LogoutResult`` sinon, avec l'URI de sortie validée le cas
          échéant et le ``state`` à rejouer.
        """
        client: Client | None = None
        subject = ""

        if request.id_token_hint:
            claims = await self._token_manager.validate_id_token(
                token=request.id_token_hint,
                issuer=self._config.issuer,
            )
            if claims is None:
                return LogoutError("invalid_request", "id_token_hint invalide")
            audience = claims.get("aud")
            client_id = audience if isinstance(audience, str) else ""
            candidate = await self._client_repository.find_by_id(client_id)
            if candidate is None or not candidate.is_active:
                return LogoutError(
                    "invalid_request", "id_token_hint d'un client inconnu ou inactif"
                )
            client = candidate
            subject_value = claims.get("sub")
            subject = str(subject_value) if subject_value is not None else ""

        if request.post_logout_redirect_uri:
            if client is None:
                client = await self._client_for_post_logout_uri(request.post_logout_redirect_uri)
            if client is None or request.post_logout_redirect_uri not in (
                client.post_logout_redirect_uris
            ):
                return LogoutError("invalid_request", "post_logout_redirect_uri non enregistrée")

        return LogoutResult(
            post_logout_redirect_uri=request.post_logout_redirect_uri,
            state=request.state,
            subject=subject,
            client_id=client.client_id if client is not None else "",
        )

    async def _client_for_post_logout_uri(self, uri: str) -> Client | None:
        """Retrouve le client ayant enregistré l'URI de sortie (sans hint).

        Parcourt le registre clients : seule une URI appartenant aux
        ``post_logout_redirect_uris`` d'un client actif est acceptée.
        """
        for candidate in await self._client_repository.find_all():
            if candidate.is_active and uri in candidate.post_logout_redirect_uris:
                return candidate
        return None
