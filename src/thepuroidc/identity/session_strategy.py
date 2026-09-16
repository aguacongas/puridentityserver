"""Stratégie de cookie de session JWT — signature RS256 rotative.

Délègue la signature/validation au ``RotatingTokenSigner`` (par clé
``KeyUse.SESSION``, jamais publiée — seule le serveur la valide) :

- ``write_token`` signe le jeton de session avec la clé de session la
  plus récente, ``kid`` dans le header JWS, ``iat``/``exp`` renseignés.
- ``read_token`` résout la clé par ``kid`` : une clé inactive mais encore
  dans sa période de grâce valide toujours la session, une session signée
  avec une clé supprimée (expiration + grâce) force un nouveau login.
"""

from __future__ import annotations

from fastapi_users import exceptions, models
from fastapi_users.authentication.strategy.base import (
    Strategy,
    StrategyDestroyNotSupportedError,
)
from fastapi_users.manager import BaseUserManager

from thepuroidc.identity.rotating_signer import RotatingTokenSigner


class SessionJWTStrategy(Strategy[models.UP, models.ID]):
    """Stratégie de session signée avec une clé rotative et typée par ``kid``."""

    def __init__(self, signer: RotatingTokenSigner, lifetime_seconds: int) -> None:
        """Injecte le signataire rotatif et la durée de vie du cookie de session."""
        self._signer = signer
        self._lifetime_seconds = lifetime_seconds

    async def write_token(self, user: models.UP) -> str:
        """Signe le JWT de session (``sub``/``aud``) avec la clé active, ``kid`` inclus."""
        return await self._signer.write(
            {"sub": str(user.id), "aud": self._signer.audience},
            self._lifetime_seconds,
        )

    async def read_token(
        self, token: str | None, user_manager: BaseUserManager[models.UP, models.ID]
    ) -> models.UP | None:
        """Valide la session : résout la clé par ``kid`` puis vérifie la signature."""
        data = await self._signer.read(token)
        if data is None:
            return None
        user_id = data.get("sub")
        if user_id is None:
            return None
        try:
            parsed_id = user_manager.parse_id(user_id)
            return await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID, ValueError):
            return None

    async def destroy_token(self, token: str, user: models.UP) -> None:
        """Les sessions JWT restent valides jusqu'à expiration (aucune révocation)."""
        raise StrategyDestroyNotSupportedError()
