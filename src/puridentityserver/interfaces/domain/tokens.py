"""Port d'émission et de validation des jetons OIDC (id_token, access_token)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.jwks import JWTAlgorithm


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
        at_hash: str = "",
        c_hash: str = "",
    ) -> str:
        """Crée un id_token signé JWS (JWT) pour le client ``audience``.

        ``at_hash`` (implicit/hybrid) lie l'id_token à l'access token,
        ``c_hash`` (hybrid) au code d'autorisation (OIDC Core 1.0 §3.3.2.11).
        """
        ...

    async def create_access_token(
        self,
        *,
        algorithm: JWTAlgorithm,
        issuer: str,
        subject: str,
        audience: str | list[str],
        expires_at: int,
        issued_at: int,
        scopes: frozenset[Scope],
    ) -> str:
        """Crée un access_token signé JWS (JWT) pour ``audience``.

        L'audience est le ``client_id`` émetteur, ou le(s) nom(s) des
        ``ApiResource`` dont des scopes ont été accordés au jeton (RFC
        7519 §4.1.3 : ``aud`` peut être une chaîne ou une liste).
        """
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

    async def validate_id_token(
        self,
        *,
        token: str,
        issuer: str,
    ) -> dict[str, object] | None:
        """Décode et valide un id_token (signature JWKS, iss, exp).

        Sert notamment à évaluer l'``id_token_hint`` du RP-Initiated Logout
        (OIDC Core 1.0 §5) : le claim ``aud`` n'est pas vérifié ici, sa
        résolution vers un client est laissée au cas d'utilisation appelant.
        """
        ...
