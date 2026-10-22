"""Implémentations PyJWT et HTTP de la Fédération (OpenID Federation 1.1).

L'entity statement est un JWS compact : la signature et la vérification
passent par PyJWT (jamais par une implémentation maison). La lecture des
statements distants utilise ``urllib`` (bibliothèque standard, comme le
reste du dépôt).
"""

from __future__ import annotations

import asyncio
import socket
import urllib.request
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwt import PyJWK  # type: ignore[attr-defined]  # non exposé par types-PyJWT

from puridentityserver.domain.federation import ENTITY_STATEMENT_MEDIA_TYPE
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.interfaces.domain.jwks import KeyManager
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse

_ALLOWED_SCHEMES = frozenset({"https"})


class PyJWTFederationTokenManager:
    """Signe et vérifie les entity statements (PyJWT).

    La clé de signature est celle gérée par le ``KeyManager`` injecté : les
    clés de la fédération sont distinctes des clés de signature OIDC
    (OpenID Federation 1.1 §2.1).
    """

    def __init__(self, key_manager: KeyManager, algorithm: JWTAlgorithm) -> None:
        """Injection du gestionnaire de clés et de l'algorithme de signature."""
        self._key_manager = key_manager
        self._algorithm = algorithm

    async def sign_entity_statement(
        self,
        *,
        algorithm: JWTAlgorithm,
        claims: Mapping[str, Any],
        key_id: str,
    ) -> str:
        """Signe un entity statement (JWS compact, en-tête ``typ`` dédié)."""
        key = await self._active_key()
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), None)
        return str(
            pyjwt.encode(
                dict(claims),
                private_key,
                algorithm=algorithm.value,
                headers={"kid": key_id or key.kid, "typ": ENTITY_STATEMENT_MEDIA_TYPE},
            )
        )

    def unverified_claims(self, token: str) -> dict[str, Any] | None:
        """Décode les claims d'un entity statement sans vérifier la signature."""
        try:
            # Le claim `jwks` sert a verifier la signature du statement
            # lui-meme (spec 3.2, etape 10) : la lecture non verifiee ne
            # sert qu'a le localiser, la verification suit immediatement.
            claims = pyjwt.decode(token, options={"verify_signature": False})  # NOSONAR(S5659)
        except pyjwt.PyJWTError:
            return None
        return dict(claims)

    def verify_entity_statement(
        self,
        *,
        token: str,
        jwks: Mapping[str, Any],
        issuer: str = "",
        subject: str = "",
    ) -> dict[str, Any] | None:
        """Vérifie la signature d'un entity statement contre un JWK Set."""
        header = _statement_header(token)
        if header is None:
            return None
        candidates = _candidate_keys(jwks, str(header["kid"]))
        for candidate in candidates:
            claims = self._verify_with(token, candidate, issuer, subject)
            if claims is not None:
                return claims
        return None

    def _verify_with(
        self,
        token: str,
        candidate: Mapping[str, Any],
        issuer: str,
        subject: str,
    ) -> dict[str, Any] | None:
        """Vérifie le statement avec une clé candidate et contrôle iss/sub."""
        public_key = _public_key_of(candidate)
        if public_key is None:
            return None
        try:
            claims = pyjwt.decode(
                token,
                cast(Any, public_key),
                algorithms=[_algorithm_of(candidate)],
                options={"require": ["iss", "sub", "iat", "exp"]},
            )
        except pyjwt.PyJWTError:
            return None
        if issuer and claims.get("iss") != issuer:
            return None
        if subject and claims.get("sub") != subject:
            return None
        return dict(claims)

    async def _active_key(self) -> KeyPair:
        """Clé de signature active de l'algorithme configuré."""
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is self._algorithm:
                return key
        await self._key_manager.ensure_active_key(4096, self._algorithm)
        for key in await self._key_manager.get_active_keys():
            if key.algorithm is self._algorithm:
                return key
        raise RuntimeError(f"Aucune clé active pour l'algorithme {self._algorithm.value}")


class KeyManagerFederationKeyProvider:
    """Clés publiques de l'entité pour le claim ``jwks`` (spec §3.1.1)."""

    def __init__(self, key_manager: KeyManager) -> None:
        """Injection du gestionnaire de clés de la fédération."""
        self._key_manager = key_manager

    async def public_jwks(self) -> dict[str, Any]:
        """Retourne le JWK Set des clés de signature de l'entité."""
        keys = [
            JWKKeyResponse.from_key_pair(key_pair).model_dump(mode="json", exclude_none=True)
            for key_pair in await self._key_manager.get_active_keys()
        ]
        return {"keys": keys}


class HTTPFederationEntityFetcher:
    """Lecture d'un entity statement distant (spec §9).

    Seuls les schémas ``https`` sont acceptés et les adresses locales sont
    refusées par défaut (protection contre les requêtes vers l'intérieur du
    réseau, comme pour le fetch des request objects).
    """

    def __init__(self, *, allow_local_targets: bool = False) -> None:
        """``allow_local_targets`` ouvre les destinations locales (tests)."""
        self._allow_local_targets = allow_local_targets

    async def fetch_entity_statement(self, url: str) -> str | None:
        """Lit l'entity statement publié à ``url`` ; ``None`` si inaccessible."""
        target = _validated_url(url, self._allow_local_targets)
        if target is None:
            return None
        try:
            return await asyncio.to_thread(_read_statement, target)
        except (OSError, ValueError):
            return None


def _read_statement(url: str) -> str:
    """GET l'URL et retourne le corps (le statement est un JWT en texte)."""
    request = urllib.request.Request(url, headers={"Accept": ENTITY_STATEMENT_MEDIA_TYPE})  # ruff: ignore[suspicious-url-open-usage] - https validé en amont
    with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage] - https validé en amont
        return cast(str, response.read().decode("utf-8"))


def _validated_url(url: str, allow_local_targets: bool) -> str | None:
    """Retourne l'URL à appeler (fragment retiré) ou ``None`` si refusée."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if not allow_local_targets and not _public_host(parts.hostname):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _public_host(hostname: str) -> bool:
    """True si toutes les adresses résolues de ``hostname`` sont publiques."""
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for address in addresses:
        ip = str(address[4][0])
        if not _is_public_ip(ip):
            return False
    return bool(addresses)


def _is_public_ip(ip: str) -> bool:
    """True si l'adresse n'est pas privée, locale ou de liaison."""
    return not (
        ip.startswith("127.")
        or ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("169.254.")
        or ip.startswith("::1")
        or ip.startswith("fc")
        or ip.startswith("fd")
        or ip.startswith("fe80")
        or _is_private_172(ip)
    )


def _is_private_172(ip: str) -> bool:
    """True pour le bloc privé 172.16.0.0/12."""
    if not ip.startswith("172."):
        return False
    try:
        second = int(ip.split(".")[1])
    except (IndexError, ValueError):
        return False
    return 16 <= second <= 31


def _statement_header(token: str) -> Mapping[str, Any] | None:
    """En-tête JWS d'un entity statement (``typ`` et ``kid`` obligatoires)."""
    try:
        header = pyjwt.get_unverified_header(token)  # NOSONAR(S5659) - sert a choisir la cle
    except pyjwt.PyJWTError:
        return None
    if header.get("typ") != ENTITY_STATEMENT_MEDIA_TYPE:
        return None
    key_id = header.get("kid")
    if not isinstance(key_id, str) or not key_id:
        return None
    return cast(Mapping[str, Any], header)


def _candidate_keys(jwks: Mapping[str, Any], key_id: str) -> list[Mapping[str, Any]]:
    """Clés du JWK Set correspondant au ``kid`` de l'en-tête."""
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return []
    return [key for key in keys if isinstance(key, Mapping) and key.get("kid") == key_id]


def _public_key_of(jwk: Mapping[str, Any]) -> object | None:
    """Construit la clé publique PyJWT à partir d'un JWK (RFC 7517 §4)."""
    try:
        return cast(object, PyJWK(dict(jwk)).key)
    except (pyjwt.PyJWTError, ValueError, KeyError, TypeError):
        return None


def _algorithm_of(jwk: Mapping[str, Any]) -> str:
    """Algorithme JWS déclaré par le JWK (``alg`` par défaut ``RS256``)."""
    algorithm = jwk.get("alg")
    return algorithm if isinstance(algorithm, str) and algorithm else "RS256"
