"""Émission des jetons id_token / access_token via PyJWT.

Implémentation concrète du port ``TokenManager`` : elle s'appuie sur un
``KeyManager`` injecté pour choisir la clé de signature active et signe
le jeton avec le ``kid`` correspondant (JWS compact, RFC 7519).
"""

from __future__ import annotations

from typing import cast

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm, KeyPair
from puridentityserver.interfaces.domain.jwks import KeyManager

_HMAC_ALGORITHMS = frozenset(SYMMETRIC_ALGORITHMS)


class PyJWTTokenManager:
    """Crée et valide des jetons JWT à l'aide de la clé de l'algorithme demandé."""

    def __init__(self, key_manager: KeyManager) -> None:
        """Injection du gestionnaire de clés (fournit la clé de signature)."""
        self._key_manager = key_manager

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
        shared_secret: str = "",
    ) -> str:
        """Construit l'``id_token`` : identité ``sub`` + audience ``client_id``.

        Le claim ``nonce`` ne figure que s'il est renseigné : un id_token de
        refresh ne doit pas porter de nonce (OIDC Core 1.0 §12.2). Les
        empreintes ``at_hash`` / ``c_hash`` (liens implicit/hybrid) ne sont
        ajoutées que lorsqu'elles sont fournies (OIDC Core 1.0 §3.3.2.11).
        ``shared_secret`` porte le secret partagé du client pour les
        algorithmes symétriques HS* (OIDC Core 1.0 §3.1.3.7) ; il est
        ignoré pour les familles asymétriques. ``session_id`` reproduit le
        ``sid`` (OIDC Session Management 1.0 §2) dans le claim ``sid``
        seulement s'il est non vide.
        """
        payload: dict[str, object] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": issued_at,
            "scope": " ".join(sorted(scope.value for scope in scopes)),
        }
        if nonce:
            payload["nonce"] = nonce
        if session_id:
            payload["sid"] = session_id
        if at_hash:
            payload["at_hash"] = at_hash
        if c_hash:
            payload["c_hash"] = c_hash
        return await self._sign(algorithm, payload, shared_secret)

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
        """Construit l'access_token : identité ``sub`` + scopes accordés.

        ``aud`` porte le ``client_id`` ou les noms des ressources
        protégées dont des scopes ont été accordés (chaîne ou liste).
        """
        payload: dict[str, object] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": issued_at,
            "scope": " ".join(sorted(scope.value for scope in scopes)),
        }
        return await self._sign(algorithm, payload)

    async def validate_access_token(
        self,
        *,
        token: str,
        issuer: str,
    ) -> dict[str, object] | None:
        """Valide la signature (JWKS), l'issuer et l'expiration d'un access_token."""
        return await self._validate(token, issuer)

    async def validate_id_token(
        self,
        *,
        token: str,
        issuer: str,
    ) -> dict[str, object] | None:
        """Valide la signature (JWKS), l'issuer et l'expiration d'un id_token.

        Attention : le claim ``aud`` n'est pas contrôlé ici — l'appelant
        (typicalement le RP-Initiated Logout) résout le ``aud`` vers le
        client afin de traiter un id_token d'un autre RP comme invalide
        (OIDC Core 1.0 §5.2).
        """
        return await self._validate(token, issuer)

    async def _validate(self, token: str, issuer: str) -> dict[str, object] | None:
        """Décode et valide un jeton signé par le serveur (signature, iss, exp)."""
        try:
            # Le header (alg/kid) sert uniquement à choisir la clé de vérification ;
            # la signature et les claims sont ensuite intégralement validés par pyjwt.decode
            # ci-dessous, de sorte qu'aucune donnée non vérifiée n'est jamais utilisée.
            header = pyjwt.get_unverified_header(token)  # NOSONAR(S5659)
            algorithm = JWTAlgorithm(header["alg"])
        except (pyjwt.PyJWTError, KeyError, ValueError):
            return None

        key = await self._key_for(header.get("kid"), algorithm)
        if key is None:
            return None

        public_key = load_pem_public_key(key.public_key_pem.encode("ascii"))
        try:
            return cast(
                dict[str, object],
                pyjwt.decode(
                    token,
                    public_key,
                    algorithms=[algorithm.value],
                    issuer=issuer,
                    options={"verify_aud": False},
                ),
            )
        except pyjwt.PyJWTError:
            return None

    async def _key_for(self, kid: object | None, algorithm: JWTAlgorithm) -> KeyPair | None:
        """Retourne la clé active de l'algorithme correspondant au ``kid``."""
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is not algorithm:
                continue
            if kid is None or key.kid == kid:
                return key
        return None

    async def _sign(
        self, algorithm: JWTAlgorithm, payload: dict[str, object], shared_secret: str = ""
    ) -> str:
        """Signe le payload avec la clé de l'algorithme (serveur ou secret client)."""
        if algorithm in _HMAC_ALGORITHMS:
            if not shared_secret:
                raise ValueError(
                    f"{algorithm.value} signe l'id_token avec le secret partagé du client, absent"
                )
            return cast(
                str,
                pyjwt.encode(
                    payload,
                    shared_secret.encode("utf-8"),
                    algorithm=algorithm.value,
                ),
            )
        key_pair = await self._first_active_key(algorithm)
        private_key = load_pem_private_key(key_pair.private_key_pem.encode("ascii"), None)
        return cast(
            str,
            pyjwt.encode(
                payload,
                private_key,
                algorithm=algorithm.value,
                headers={"kid": key_pair.kid},
            ),
        )

    async def _first_active_key(self, algorithm: JWTAlgorithm) -> KeyPair:
        """Retourne la première clé active de l'algorithme, en génère si besoin."""
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is algorithm:
                return key
        await self._key_manager.ensure_active_key(4096, algorithm)
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is algorithm:
                return key
        raise RuntimeError(f"Aucune clé active disponible pour l'algorithme {algorithm.value}")
