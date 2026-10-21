"""Rôle OpenID 2.0 de l'OP (spec de migration, sections 2 et 4).

Pour une migration en interne, l'OP joue aussi le rôle d'OP OpenID 2.0 :
``checkid_setup`` engage l'authentification de l'utilisateur et rend un
*handle* opaque, ``check_authentication`` restitue l'assertion correspondante
(identifiant OpenID 2.0 compris).

L'état de la demande (``checkid_setup``) et le *handle* sont des jetons
**signés** par l'OP (le magasin de clés de signature) : ils ne sont donc ni
falsifiables ni expirables par le tiers.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.application.openid20_migration import OpenID20MigrationUseCase
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.openid20 import OpenID20Identifier
from puridentityserver.infrastructure.jwks import first_active_key
from puridentityserver.interfaces.domain.jwks import KeyManager

#: Durée de validité de l'état de la demande et du handle (secondes).
OPENID20_STATE_TTL_SECONDS = 600


class OpenID20ProviderError(Exception):
    """Refus de la demande OpenID 2.0 (état ou handle invalide, expiré)."""

    def __init__(self, error: str, description: str) -> None:
        """Conserve le code d'erreur et sa description."""
        super().__init__(description)
        self.error = error
        self.error_description = description


class OpenID20ProviderUseCase:
    """Gère le rôle OpenID 2.0 de l'OP (setup, handle, assertion).

    ``enabled`` conditionne l'ensemble : sans activation, aucune route n'est
    exposée et le cas d'usage refuse toute demande.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        migration: OpenID20MigrationUseCase,
        *,
        issuer: str,
        base_url: str = "",
        enabled: bool = False,
        algorithm: JWTAlgorithm = JWTAlgorithm.RS256,
        ttl_seconds: int = OPENID20_STATE_TTL_SECONDS,
    ) -> None:
        """Injection des clés, du cas d'usage de migration et de l'activation."""
        self._key_manager = key_manager
        self._migration = migration
        self._issuer = issuer
        self._base_url = (base_url or issuer).rstrip("/")
        self._enabled = enabled
        self._algorithm = algorithm
        self._ttl_seconds = ttl_seconds

    @property
    def enabled(self) -> bool:
        """Indique si le rôle OpenID 2.0 est activé."""
        return self._enabled

    @property
    def base_url(self) -> str:
        """URL publique de l'OP (sans slash final)."""
        return self._base_url

    def identifier_url(self, identifier_id: str) -> str:
        """URL de l'identifiant OpenID 2.0 (hébergée par l'OP).

        L'OP sert cette URL en JSON ``{"iss": ...}`` : c'est la preuve
        d'autorité attendue par le RP (spec §6).
        """
        return f"{self._base_url}/openid20/id/{identifier_id}"

    async def ensure_identifier(self, subject: str, realm: str) -> str:
        """Retourne l'identifiant OpenID 2.0 du compte, en le créant au besoin.

        L'identifiant est **stable** pour un couple (compte, realm) : une
        migration rejouée ne change pas l'identifiant connu des RP.
        """
        existing = await self._migration.identifier_for(subject, realm)
        if existing:
            return existing
        identifier = self.identifier_url(uuid4().hex)
        await self._migration.link(subject, identifier, realm)
        return identifier

    async def authority_of(self, identifier: str) -> OpenID20Identifier | None:
        """Retourne l'association portée par l'identifiant donné (§6)."""
        return await self._migration.find_by_identifier(identifier)

    async def issue_state(self, namespace: str, realm: str, return_to: str) -> str:
        """Émet l'état signé de la demande OpenID 2.0 (``checkid_setup``).

        ``namespace`` est l'``openid.ns`` du RP, ``realm`` son
        ``openid.realm`` et ``return_to`` l'URL de retour du RP.
        """
        self._require_enabled()
        return await self._sign(
            {
                "kind": "state",
                "ns": namespace,
                "realm": realm,
                "return_to": return_to,
            }
        )

    async def read_state(self, state: str) -> dict[str, str]:
        """Relit l'état signé d'une demande OpenID 2.0."""
        claims = await self._verify(state, "state")
        return {
            "ns": str(claims.get("ns", "")),
            "realm": str(claims.get("realm", "")),
            "return_to": str(claims.get("return_to", "")),
        }

    async def issue_handle(self, subject: str, namespace: str, realm: str, claimed_id: str) -> str:
        """Émet le handle OpenID 2.0 d'un utilisateur authentifié.

        Le handle porte l'identifiant OpenID 2.0 (``claimed_id``) : le RP le
        rend à l'OP par ``check_authentication`` pour obtenir l'assertion.
        """
        self._require_enabled()
        return await self._sign(
            {
                "kind": "handle",
                "sub": subject,
                "ns": namespace,
                "realm": realm,
                "claimed_id": claimed_id,
            }
        )

    async def read_handle(self, handle: str) -> dict[str, str]:
        """Relit le handle OpenID 2.0 et les éléments de son assertion.

        L'identifiant OpenID 2.0 ``identifier`` est celui **associé** au
        compte dans la table de migration ; ``claimed_id`` est celui porté
        par le handle (l'identifiant revendiqué au moment du setup).
        """
        claims = await self._verify(handle, "handle")
        subject = str(claims.get("sub", ""))
        realm = str(claims.get("realm", ""))
        return {
            "sub": subject,
            "ns": str(claims.get("ns", "")),
            "realm": realm,
            "claimed_id": str(claims.get("claimed_id", "")),
            "identifier": await self._migration.identifier_for(subject, realm),
        }

    def _require_enabled(self) -> None:
        """Refuse l'opération lorsque le rôle OpenID 2.0 est désactivé."""
        if not self._enabled:
            raise OpenID20ProviderError("invalid_request", "Le support OpenID 2.0 n'est pas activé")

    async def _sign(self, payload: dict[str, Any]) -> str:
        """Signe un jeton d'état OpenID 2.0 (algorithme serveur)."""
        key = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), None)
        now = int(time.time())
        claims = {
            **payload,
            "iss": self._issuer,
            "iat": now,
            "exp": now + self._ttl_seconds,
        }
        return str(
            pyjwt.encode(
                claims,
                private_key,
                algorithm=self._algorithm.value,
                headers={"kid": key.kid},
            )
        )

    async def _verify(self, token: str, kind: str) -> dict[str, Any]:
        """Vérifie la signature et le type d'un jeton d'état OpenID 2.0."""
        key = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), None)
        try:
            claims = pyjwt.decode(
                token,
                private_key.public_key(),
                algorithms=[self._algorithm.value],
                issuer=self._issuer,
                options={"require": ["exp", "iat"]},
            )
        except pyjwt.PyJWTError as error:
            raise OpenID20ProviderError(
                "invalid_request", f"État OpenID 2.0 invalide : {error}"
            ) from error
        if claims.get("kind") != kind:
            raise OpenID20ProviderError("invalid_request", "État OpenID 2.0 : type inattendu")
        return dict(claims)
