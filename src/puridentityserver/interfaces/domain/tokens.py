"""Ports d'émission, de validation et de chiffrement des jetons OIDC.

Couvre l'id_token (signature JWS et chiffrement JWE) et l'access_token ;
les implémentations concrètes vivent dans l'infrastructure (PyJWT /
``cryptography``).
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import Client, Scope
from puridentityserver.domain.jwks import JWTAlgorithm


class JWEUnavailableError(Exception):
    """Matériel de chiffrement d'``id_token`` indisponible.

    Levée quand un id_token demandé chiffré (``id_token_encrypted_response_alg``
    configuré) ne peut pas l'être : chiffreur absent de la composition,
    secret partagé non récupérable, ou clé publique RSA manquante dans le
    ``jwks`` du client. Les cas d'utilisation la traduisent en erreur
    ``invalid_client`` (OIDC Core 1.0 §3.1.3.6).
    """


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
        session_id: str = "",
        expires_at: int,
        issued_at: int,
        scopes: frozenset[Scope],
        at_hash: str = "",
        c_hash: str = "",
        auth_time: int = 0,
        shared_secret: str = "",
    ) -> str:
        """Crée un id_token signé JWS (JWT) pour le client ``audience``.

        ``at_hash`` (implicit/hybrid) lie l'id_token à l'access token,
        ``c_hash`` (hybrid) au code d'autorisation (OIDC Core 1.0 §3.3.2.11).
        ``shared_secret`` fournit le secret partagé du client pour la
        signature symétrique HS* (OIDC Core 1.0 §3.1.3.7).
        ``session_id`` porte le ``sid`` de la session navigateur (OIDC
        Session Management 1.0 §2) : le claim ``sid`` est ajouté seulement
        si non vide, pour rester stable pour les flux sans session.
        ``auth_time`` (OIDC Core 1.0 §2) : le claim ``auth_time`` n'est
        ajouté que s'il est non nul, pour ne pas émettre un temps
        d'authentification invalide.
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

    async def create_logout_token(
        self,
        *,
        issuer: str,
        subject: str,
        audience: str,
        sid: str,
        expires_at: int,
        issued_at: int,
        jwt_id: str,
    ) -> str:
        """Crée un ``logout_token`` (OIDC Back-Channel Logout 1.0 §2.2).

        Signé côté serveur (famille ``sig``), destiné à un client
        ``backchannel_logout_uri`` unique (``aud`` = ``client_id``).
        ``sub`` identifie l'utilisateur déconnecté, ``sid`` sa session
        (OIDC Session Management) ; ``jti`` rend le jeton unique. Le claim
        ``events`` (``http://schemas.openid.net/event/backchannel-logout``)
        marque un jeton de déconnexion — jamais un id_token.
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


class IdTokenEncrypter(Protocol):
    """Interface de chiffrement d'un ``id_token`` (JWE compact, RFC 7516).

    L'infrastructure fournit l'implémentation concrète (``cryptography``),
    documentée par le wrapper RFC 7516 — conformément à la contrainte du
    dépôt (la crypto ne passe jamais par une implémentation maison). Le
    port isole les usecases de la bibliothèque de chiffrement.
    """

    async def encrypt_id_token(
        self,
        *,
        id_token: str,
        client: Client,
        shared_secret: str = "",
    ) -> str:
        """Chiffre l'``id_token`` JWS en JWE compact pour le client.

        ``shared_secret`` porte le secret partagé du client pour les
        familles symétriques (A*KW / ``dir``) ; les algorithmes RSA-OAEP
        utilisent la clé publique RSA du ``jwks`` du client. L'``id_token``
        chiffré imbriqué porte ``cty: JWT`` (OIDC Core 1.0 §3.1.3.6).
        """
        ...
