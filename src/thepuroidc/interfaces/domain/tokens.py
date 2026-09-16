"""Port d'émission et de validation des jetons OIDC (id_token, access_token)."""

from __future__ import annotations

from typing import Protocol

from thepuroidc.domain.authorization import Scope
from thepuroidc.domain.jwks import JWTAlgorithm


class TokenManager(Protocol):
    """Interface de création et de validation des jetons signés par le serveur.

    L'infrastructure fournit l'implémentation concrète (PyJWT) illustrant
    le câblage par défaut : le port isole les usecases de la
    bibliothèque de signature.
    """

    async def create_id_token(
        self,
        *,
        algorithm: JWTAlgorithm,
        issuer: str,
        subject: str,
        audience: str,
        nonce: str,
        expires_at: int,
        issued_at: int,
        scopes: frozenset[Scope],
    ) -> str:
        """Crée un id_token signé JWS (JWT) pour le client ``audience``."""
        ...

    async def create_access_token(
        self,
        *,
        algorithm: JWTAlgorithm,
        issuer: str,
        subject: str,
        audience: str,
        expires_at: int,
        issued_at: int,
        scopes: frozenset[Scope],
    ) -> str:
        """Crée un access_token signé JWS (JWT) pour le client ``audience``."""
        ...

    async def validate_access_token(
        self,
        *,
        token: str,
        issuer: str,
    ) -> dict[str, object] | None:
        """Décode et valide un access_token (signature JWKS, iss, exp).

        Retourne les claims du jeton s'il est valide, ``None`` sinon
        (signature invalide, émetteur inattendu, expiration…).
        """
        ...
