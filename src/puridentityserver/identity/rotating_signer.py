"""Signataire JWT RS256 à rotation native de clés (usage serveur privé).

Factorise l'usage d'un ``KeyManager`` à rotation de clés pour tous les
jetons signés par le serveur qui ne sont jamais publiés dans le JWKS :
cookies de session (``KeyUse.SESSION``), jetons de réinitialisation de
mot de passe (``KeyUse.RESET``) et de vérification de compte
(``KeyUse.VERIFY``).

- ``write`` applique la rotation (périmation des clés actives) puis signe
  avec la clé la plus récente en embarquant son ``kid`` dans le header
  JWS et une date d'expiration ``exp`` issue de la durée demandée.
- ``read`` résout la clé par ``kid`` : une clé périmée mais encore dans
  sa période de grâce valide toujours le jeton, un jeton signé avec une
  clé supprimée (rotation + grâce écoulées) est rejeté.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import cast

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.interfaces.domain.jwks import KeyManager

_DEFAULT_AUDIENCE = "puridentityserver"


class RotatingTokenSigner:
    """Signe et valide des jetons JWT avec une clé rotative typée par ``kid``."""

    def __init__(
        self,
        key_manager: KeyManager,
        *,
        token_audience: list[str] | None = None,
        key_size: int = 2048,
        rotation_days: int = 90,
        grace_period_days: int = 7,
    ) -> None:
        """Injecte le gestionnaire de clés de la famille et la politique de rotation."""
        self._key_manager = key_manager
        self._token_audience = token_audience if token_audience is not None else [_DEFAULT_AUDIENCE]
        self._key_size = key_size
        self._rotation_days = rotation_days
        self._grace_period_days = grace_period_days

    @property
    def audience(self) -> list[str]:
        """Audience attendue lors de la validation d'un jeton."""
        return self._token_audience

    async def _active_signing_key(self) -> KeyPair:
        """Applique la rotation puis retourne la clé la plus récente."""
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
            raise RuntimeError(
                f"Aucune clé active disponible pour {self._key_manager.__class__.__name__}"
            )
        return max(active, key=lambda key: key.created_at)

    async def write(self, claims: Mapping[str, object], lifetime_seconds: int) -> str:
        """Signe ``claims`` avec la clé active, ajoute ``exp`` et embarque ``kid``."""
        key_pair = await self._active_signing_key()
        now = int(time.time())
        payload = dict(claims)
        payload["iat"] = now
        payload["exp"] = now + lifetime_seconds
        private_key = load_pem_private_key(key_pair.private_key_pem.encode("ascii"), None)
        return cast(
            str,
            pyjwt.encode(
                payload,
                private_key,
                algorithm=JWTAlgorithm.RS256.value,
                headers={"kid": key_pair.kid},
            ),
        )

    async def read(self, token: str | None) -> dict[str, object] | None:
        """Valide ``token`` (résolution par ``kid``, signature, audience) et le décode."""
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
            return pyjwt.decode(
                token,
                public_key,
                algorithms=[JWTAlgorithm.RS256.value],
                audience=self._token_audience,
            )
        except pyjwt.PyJWTError:
            return None
