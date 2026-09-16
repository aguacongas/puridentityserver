"""Stratégie de cookie de session signé RS256 — rotation de clés native.

Remplace ``JWTStrategy`` de FastAPI Users (secret unique, sans ``kid`` ni
rotation) par une stratégie s'appuyant sur un ``KeyManager`` dédié aux
cookies (``KeyUse.SESSION``), distinct de celui des tokens OIDC :

- ``write_token`` applique la rotation, signe avec la clé de session la
  plus récente et embarque son ``kid`` dans le header JWS.
- ``read_token`` résout la clé par ``kid`` : une clé inactive mais encore
  dans sa période de grâce valide toujours la session, une session signée
  avec une clé supprimée (expiration + grace) force un nouveau login.
"""

from __future__ import annotations

from typing import cast

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from fastapi_users import exceptions, models
from fastapi_users.authentication.strategy.base import (
    Strategy,
    StrategyDestroyNotSupportedError,
)
from fastapi_users.manager import BaseUserManager

from thepuroidc.domain.jwks import JWTAlgorithm, KeyPair
from thepuroidc.interfaces.domain.jwks import KeyManager


class SessionJWTStrategy(Strategy[models.UP, models.ID]):
    """Stratégie de session signée avec une clé rotative et typée par ``kid``."""

    def __init__(
        self,
        key_manager: KeyManager,
        lifetime_seconds: int,
        *,
        token_audience: list[str] | None = None,
        key_size: int = 2048,
        rotation_days: int = 90,
        grace_period_days: int = 7,
    ) -> None:
        """Injecte le gestionnaire de clés de session et la politique de rotation."""
        self._key_manager = key_manager
        self._lifetime_seconds = lifetime_seconds
        self._token_audience = (
            token_audience if token_audience is not None else ["fastapi-users:auth"]
        )
        self._key_size = key_size
        self._rotation_days = rotation_days
        self._grace_period_days = grace_period_days

    async def _active_signing_key(self) -> KeyPair:
        """Applique la rotation puis retourne la clé de session la plus récente."""
        await self._key_manager.mark_expired_keys(self._rotation_days, self._grace_period_days)
        active = [
            key
            for key in await self._key_manager.get_active_keys()
            if key.algorithm is JWTAlgorithm.RS256
        ]
        if not active:
            await self._key_manager.ensure_active_key(self._key_size, JWTAlgorithm.RS256)
            active = [
                key
                for key in await self._key_manager.get_active_keys()
                if key.algorithm is JWTAlgorithm.RS256
            ]
        if not active:
            raise RuntimeError("Aucune clé de session active disponible")
        return max(active, key=lambda key: key.created_at)

    async def write_token(self, user: models.UP) -> str:
        """Signe le JWT de session (``sub``/``aud``) avec la clé active, ``kid`` inclus."""
        key_pair = await self._active_signing_key()
        private_key = load_pem_private_key(key_pair.private_key_pem.encode("ascii"), None)
        return cast(
            str,
            pyjwt.encode(
                {"sub": str(user.id), "aud": self._token_audience},
                private_key,
                algorithm=JWTAlgorithm.RS256.value,
                headers={"kid": key_pair.kid},
            ),
        )

    async def read_token(
        self, token: str | None, user_manager: BaseUserManager[models.UP, models.ID]
    ) -> models.UP | None:
        """Valide la session : résout la clé par ``kid`` puis vérifie la signature."""
        if token is None:
            return None
        try:
            header = pyjwt.get_unverified_header(token)  # NOSONAR(S5659)
            kid = header["kid"]
        except (pyjwt.PyJWTError, KeyError):
            return None

        key_pair = await self._key_manager.get_key_by_kid(kid)
        if key_pair is None:
            return None
        public_key = load_pem_public_key(key_pair.public_key_pem.encode("ascii"))
        try:
            data = pyjwt.decode(
                token,
                public_key,
                algorithms=[JWTAlgorithm.RS256.value],
                audience=self._token_audience,
            )
        except pyjwt.PyJWTError:
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
