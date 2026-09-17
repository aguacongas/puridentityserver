"""Cas d'utilisation : Device Authorization Grant (RFC 8628).

La demande ``/device_authorization`` valide le client et génère un
``device_code`` opque (jamais stocké en clair) couplé à un ``user_code``
court que l'utilisateur saisit sur la page de vérification (``/device``).
L'utilisateur s'y connecte puis autorise (ou refuse) l'appareil : la
session passe à ``APPROVED`` (sujet fixé) ou ``DENIED``. Le client pole
ensuite ``/token`` avec le ``grant_type`` device pour récupérer les jetons.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.application.client_auth import (
    CLIENT_UNKNOWN_ERROR,
    verify_client_secret,
)
from puridentityserver.domain.authorization import (
    ClientType,
    DeviceAuthorization,
    DeviceAuthorizationStatus,
    Scope,
    format_user_code,
    normalize_user_code,
    resolve_lifetime_seconds,
)
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.device_authorization_repository import (
    DeviceAuthorizationRepository,
)

_USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


@dataclass(frozen=True, slots=True)
class DeviceConfig:
    """Paramètres du device authorization endpoint (RFC 8628 §3.1)."""

    issuer: str
    base_url: str = ""
    ttl_seconds: int = 900
    interval_seconds: int = 5


@dataclass(slots=True)
class DeviceAuthorizationRequest:
    """Paramètres fournis par le client à ``/device_authorization``."""

    client_id: str
    client_secret: str = ""
    scope: str = ""


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationResult:
    """Réponse de ``/device_authorization`` (RFC 8628 §3.2)."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationError:
    """Erreur du device authorization endpoint."""

    error: str
    error_description: str = ""


@dataclass(frozen=True, slots=True)
class DeviceDecision:
    """Issu de la page de vérification : décision prise ou code invalide."""

    accepted: bool
    message: str


class DeviceAuthorizationUseCase:
    """Valide le client, génère les codes et applique la décision de l'utilisateur."""

    def __init__(
        self,
        config: DeviceConfig,
        client_repository: ClientRepository,
        device_codes: DeviceAuthorizationRepository,
    ) -> None:
        """Injection de la configuration et des repositories."""
        self._config = config
        self._clients = client_repository
        self._device_codes = device_codes

    async def execute(
        self, request: DeviceAuthorizationRequest
    ) -> DeviceAuthorizationResult | DeviceAuthorizationError:
        """Expose les codes de l'appareil après validation du client (RFC 8628 §3.1)."""
        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return DeviceAuthorizationError("invalid_client", CLIENT_UNKNOWN_ERROR)
        if client.client_type == ClientType.CONFIDENTIAL and not verify_client_secret(
            client, request.client_secret
        ):
            return DeviceAuthorizationError("invalid_client", "Secret client invalide")

        scopes = client.scopes
        if request.scope:
            requested = Scope.from_space_separated(request.scope)
            if requested - client.scopes:
                return DeviceAuthorizationError(
                    "invalid_scope", "Portée jamais enregistrée pour le client"
                )
            scopes = requested

        device_code = token_urlsafe()
        user_code = self._generate_user_code()
        now = datetime.now(timezone.utc)
        ttl = resolve_lifetime_seconds(
            client.device_code_lifetime_seconds, self._config.ttl_seconds
        )
        interval = resolve_lifetime_seconds(
            client.device_code_interval_seconds, self._config.interval_seconds
        )
        await self._device_codes.save(
            DeviceAuthorization(
                device_code_hash=token_hash(device_code),
                user_code=user_code,
                client_id=client.client_id,
                scopes=scopes,
                expires_at=now + timedelta(seconds=ttl),
                interval=interval,
            )
        )
        formatted = format_user_code(user_code)
        verification_uri = f"{self._resolve_base_url()}/device"
        return DeviceAuthorizationResult(
            device_code=device_code,
            user_code=formatted,
            verification_uri=verification_uri,
            verification_uri_complete=f"{verification_uri}?user_code={formatted}",
            expires_in=ttl,
            interval=interval,
        )

    async def approve(self, user_code: str, subject: str) -> DeviceDecision:
        """Autorise l'appareil en fixant le ``subject`` de l'utilisateur connecté."""
        return await self._decide(user_code, DeviceAuthorizationStatus.APPROVED, subject=subject)

    async def deny(self, user_code: str) -> DeviceDecision:
        """Refuse l'autorisation de l'appareil (poll → ``access_denied``)."""
        return await self._decide(user_code, DeviceAuthorizationStatus.DENIED)

    async def _decide(
        self,
        user_code: str,
        status: DeviceAuthorizationStatus,
        subject: str = "",
    ) -> DeviceDecision:
        """Applique la décision de l'utilisateur après vérification du code."""
        code = normalize_user_code(user_code)
        if not code:
            return DeviceDecision(False, "Saisissez le code affiché sur votre appareil.")
        stored = await self._device_codes.find_by_user_code(code)
        if stored is None:
            return DeviceDecision(False, "Code inconnu : vérifiez la saisie.")
        if stored.expires_at < datetime.now(timezone.utc):
            await self._device_codes.delete(stored.device_code_hash)
            return DeviceDecision(False, "Ce code a expiré : relancez la demande sur l'appareil.")
        if stored.status == DeviceAuthorizationStatus.APPROVED:
            return DeviceDecision(False, "Cet appareil est déjà autorisé.")
        if stored.status == DeviceAuthorizationStatus.DENIED:
            return DeviceDecision(False, "Cet appareil a déjà été refusé.")
        action = "autorisé" if status == DeviceAuthorizationStatus.APPROVED else "refusé"
        if status == DeviceAuthorizationStatus.APPROVED:
            await self._device_codes.approve(stored.device_code_hash, subject)
        else:
            await self._device_codes.deny(stored.device_code_hash)
        return DeviceDecision(True, f"Appareil {action} : vous pouvez retourner à l'appareil.")

    def _generate_user_code(self) -> str:
        """Génère un code de 8 caractères (40 bits) sans caractères ambigus."""
        return "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(8))

    def _resolve_base_url(self) -> str:
        return (self._config.base_url or self._config.issuer).rstrip("/")
