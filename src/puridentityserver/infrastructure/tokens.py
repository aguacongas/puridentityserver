"""Émission des jetons id_token / access_token via PyJWT.

Implémentation concrète du port ``TokenManager`` : elle s'appuie sur un
``KeyManager`` injecté pour choisir la clé de signature active et signe
le jeton avec le ``kid`` correspondant (JWS compact, RFC 7519).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import first_active_key
from puridentityserver.interfaces.domain.jwks import KeyManager
from puridentityserver.interfaces.domain.tokens import IdTokenConditionalClaims

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
        expires_at: int,
        issued_at: int,
        conditional_claims: IdTokenConditionalClaims | None = None,
        shared_secret: str = "",
        additional_claims: Mapping[str, object] | None = None,
    ) -> str:
        """Construit l'``id_token`` : identité ``sub`` + audience ``client_id``.

        Les claims optionnels conditionnels sont portés par
        ``conditional_claims`` (``nonce``, ``sid``, ``at_hash``,
        ``c_hash``, ``s_hash``, ``auth_time``) : le ``nonce`` ne figure
        que s'il est renseigné — un id_token de refresh ne doit pas
        porter de nonce (OIDC Core 1.0 §12.2) — et les empreintes
        ``at_hash`` / ``c_hash`` (liens implicit/hybrid) et ``s_hash``
        (empreinte du ``state``, FAPI1-ADV-5.2.2.1-5) ne sont ajoutées
        que lorsqu'elles sont fournies (OIDC Core 1.0 §3.3.2.11).
        ``shared_secret`` porte le secret partagé du client pour les
        algorithmes symétriques HS* (OIDC Core 1.0 §3.1.3.7) ; il est
        ignoré pour les familles asymétriques. ``additional_claims`` est
        fusionné sans jamais écraser les claims standards ci-dessus (ex.
        ``acr`` fourni par l'appelant seulement quand ``acr_values`` est
        non vide).
        """
        conditional = conditional_claims or IdTokenConditionalClaims()
        payload: dict[str, object] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": issued_at,
        }
        if conditional.nonce:
            payload["nonce"] = conditional.nonce
        if conditional.session_id:
            payload["sid"] = conditional.session_id
        if conditional.at_hash:
            payload["at_hash"] = conditional.at_hash
        if conditional.c_hash:
            payload["c_hash"] = conditional.c_hash
        if conditional.s_hash:
            payload["s_hash"] = conditional.s_hash
        if conditional.auth_time:
            payload["auth_time"] = conditional.auth_time
        for name, value in (additional_claims or {}).items():
            payload.setdefault(name, value)
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
        additional_claims: Mapping[str, object] | None = None,
    ) -> str:
        """Construit l'access_token : identité ``sub`` + scopes accordés.

        ``aud`` porte le ``client_id`` ou les noms des ressources
        protégées dont des scopes ont été accordés (chaîne ou liste).
        Le claim ``jti`` (RFC 9068 §2.1) rend chaque jeton unique :
        deux émissions dans la même seconde avec des paramètres
        identiques produiraient autrement un JWT octet-identique, ce
        qui casserait la détection de rotation côté client. Les
        ``additional_claims`` complètent le payload sans jamais écraser
        les claims standards (ex. le claim ``claims`` portant les noms
        de claims userinfo demandés, relus par ``/userinfo``).
        """
        payload: dict[str, object] = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "exp": expires_at,
            "iat": issued_at,
            "jti": str(uuid4()),
            "scope": " ".join(sorted(scope.value for scope in scopes)),
        }
        for name, value in (additional_claims or {}).items():
            payload.setdefault(name, value)
        return await self._sign(algorithm, payload)

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
        """Construit un ``logout_token`` : ``events`` + ``sub``/``sid`` + ``jti``.

        Toujours signé avec la clé serveur ``sig`` (famille publiée au
        JWKS) pour que le client puisse vérifier le jeton. Le claim
        événementiel (OIDC Back-Channel Logout 1.0 §2.1) le distingue d'un
        ``id_token`` ; ``sid`` n'est embarqué que lorsqu'il est renseigné.
        """
        payload: dict[str, object] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "iat": issued_at,
            "exp": expires_at,
            "jti": jwt_id,
            "events": {"http://schemas.openid.net/event/backchannel-logout": {}},  # NOSONAR(S5332)
        }
        if sid:
            payload["sid"] = sid
        return await self._sign(JWTAlgorithm.RS256, payload)

    async def create_userinfo_jwt(
        self,
        *,
        issuer: str,
        audience: str,
        algorithm: JWTAlgorithm,
        claims: Mapping[str, object],
    ) -> str:
        """Crée la réponse UserInfo signée en JWT (OIDC Core 1.0 §5.3.2).

        ``iss``/``aud``/``iat`` priment sur les claims fournis : le JWT
        signé doit porter l'émetteur et le ``client_id`` destinataire
        (§5.3.2), une collision de nom ne peut les écraser. ``_sign``
        emploie la clé active de l'algorithme avec son ``kid`` (JWKS).
        """
        now = int(datetime.now(timezone.utc).timestamp())
        payload: dict[str, object] = {"iss": issuer, "aud": audience, "iat": now}
        for name, value in claims.items():
            payload.setdefault(name, value)
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
        allow_expired: bool = False,
    ) -> dict[str, object] | None:
        """Valide la signature (JWKS), l'issuer et l'expiration d'un id_token.

        Attention : le claim ``aud`` n'est pas contrôlé ici — l'appelant
        (typicalement le RP-Initiated Logout) résout le ``aud`` vers le
        client afin de traiter un id_token d'un autre RP comme invalide
        (OIDC Core 1.0 §5.2). ``allow_expired`` accepte un id_token échu
        (usage ``id_token_hint``, §14).
        """
        return await self._validate(token, issuer, allow_expired=allow_expired)

    async def _validate(
        self, token: str, issuer: str, *, allow_expired: bool = False
    ) -> dict[str, object] | None:
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
                    options={"verify_aud": False, "verify_exp": not allow_expired},
                ),
            )
        except pyjwt.PyJWTError:
            return None

    async def _key_for(self, kid: object | None, algorithm: JWTAlgorithm) -> KeyPair | None:
        """Retourne la clé de validation : par ``kid``, sinon la clé active.

        La résolution par ``kid`` couvre aussi les clés **retirées** encore
        conservées : un jeton signé juste avant une rotation reste
        vérifiable (OIDC Core 1.0 §10.1).
        """
        if isinstance(kid, str) and kid:
            key = await self._key_manager.get_key_by_kid(kid)
            return key if key is not None and key.algorithm is algorithm else None
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is algorithm:
                return key
        return None

    async def _sign(
        self, algorithm: JWTAlgorithm, payload: dict[str, object], shared_secret: str = ""
    ) -> str:
        """Signe le payload avec la clé de l'algorithme (serveur ou secret client).

        ``none`` (JWA RFC 7519 §6) émet l'en-tête et les claims sans segment
        de signature (``base64(header).base64(payload).``) : c'est le jeton
        demandé par un client ayant enregistré
        ``id_token_signed_response_alg=none`` (OIDC Core 1.0 §3.1.3.7).
        """
        if algorithm is JWTAlgorithm.NONE:
            # types-PyJWT limite la clé à un objet crypto : le JWT non signé
            # n'en porte aucune (JWA RFC 7519 §6).
            return cast(str, pyjwt.encode(payload, None, algorithm="none"))  # type: ignore[arg-type]
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
        return await first_active_key(self._key_manager, algorithm)
