"""Vérification des assertions JWT signées par le client.

Deux usages distincts du RFC 7523 :

- **authentification du client** (§2.2) : une assertion ``client_assertion``
  (``client_secret_jwt`` / ``private_key_jwt``) identifie et authentifie le
  client — ``iss`` et ``sub`` valent le ``client_id``, ``aud`` le token
  endpoint ;
- **grant jwt-bearer** (§2.1) : l'assertion (champ ``assertion``) délègue un
  sujet au serveur — ``iss`` nomme l'émetteur (le client), ``sub`` le sujet
  au nom de qui les jetons sont demandés, les deux pouvant différer.

La vérification partagée controle la signature (HMAC avec le secret du
client, ou clé publique de son JWKS enregistré/embarqué), ``aud`` (token
endpoint), ``exp`` et la cohérence ``iss``/``sub`` selon l'usage.
"""

from __future__ import annotations

import asyncio
from typing import cast

import jwt as pyjwt
from jwt import PyJWKClient, PyJWKSet  # type: ignore[attr-defined]  # non exposés par types-PyJWT

from puridentityserver.domain.authorization import Client
from puridentityserver.interfaces.domain.secrets import SecretCipher

_HMAC_ALGORITHMS = ("HS256", "HS384", "HS512")
_JWKS_TIMEOUT = 10


class PyJWTClientAssertionVerifier:
    """Vérifie les assertions client via PyJWT, secret partagé ou JWKS enregistré.

    Les assertions HMAC (``client_secret_jwt``, grant jwt-bearer signé
    secret) sont vérifiées avec le secret déchiffré par le ``secret_cipher``
    injecté ; les assertions asymétriques le sont avec la clé publique du
    client (``jwks`` embarqués ou ``jwks_uri`` distante, mise en cache par
    ``PyJWKClient``).
    """

    def __init__(self, secret_cipher: SecretCipher | None = None) -> None:
        """Injection du chiffreur des secrets clients (nécessaire pour HMAC)."""
        self._secret_cipher = secret_cipher

    async def verify(
        self,
        *,
        token: str,
        client: Client,
        audience: str,
        require_iss_eq_sub: bool,
    ) -> dict[str, object] | None:
        """Vérifie l'assertion selon l'algorithme de son en-tête (HMAC ou asymétrique)."""
        try:
            algorithm = pyjwt.get_unverified_header(token)["alg"]  # NOSONAR(S5659)
        except (pyjwt.PyJWTError, KeyError):
            return None
        if algorithm in _HMAC_ALGORITHMS:
            secret = await self._hmac_secret(client)
            if secret is None:
                return None
            return verify_hmac_assertion(
                token,
                secret=secret,
                audience=audience,
                issuer=client.client_id,
                require_iss_eq_sub=require_iss_eq_sub,
            )
        return await verify_jwks_assertion(
            token,
            audience=audience,
            issuer=client.client_id,
            jwks=client.jwks,
            jwks_uri=client.jwks_uri,
            require_iss_eq_sub=require_iss_eq_sub,
        )

    async def _hmac_secret(self, client: Client) -> str | None:
        """Déchiffre le secret du client pour la vérification HMAC, sinon ``None``."""
        if self._secret_cipher is None or not client.client_secret_ciphertext:
            return None
        try:
            return await self._secret_cipher.decrypt(client.client_secret_ciphertext)
        except ValueError:
            return None


def _required_options(require_iss_eq_sub: bool) -> dict[str, object]:
    """Options PyJWT : ``iss``/``aud`` vérifiés, ``sub`` aligné si client auth."""
    options: dict[str, object] = {"require": ["exp", "iss", "aud"]}
    if require_iss_eq_sub:
        options["verify_sub"] = False  # contrôlé après décodage (iss == sub)
    return options


def verify_hmac_assertion(
    token: str,
    *,
    secret: str,
    audience: str,
    issuer: str,
    require_iss_eq_sub: bool = True,
) -> dict[str, object] | None:
    """Vérifie une assertion signée HMAC avec le secret partagé (RFC 7518 §3.2).

    Seuls les algorithmes HS256/HS384/HS512 sont acceptés ; l'algorithme de
    l'en-tête est repris tel quel pour ``decode`` (PyJWT refuse une
    signature vérifiée avec un autre algorithme).
    """
    if not secret:
        return None
    try:
        algorithm = pyjwt.get_unverified_header(token)["alg"]  # NOSONAR(S5659)
    except (pyjwt.PyJWTError, KeyError):
        return None
    if algorithm not in _HMAC_ALGORITHMS:
        return None
    return _decode(
        token,
        secret.encode("utf-8"),
        algorithms=_HMAC_ALGORITHMS,
        audience=audience,
        issuer=issuer,
        require_iss_eq_sub=require_iss_eq_sub,
    )


async def verify_jwks_assertion(
    token: str,
    *,
    audience: str,
    issuer: str,
    jwks: tuple[dict[str, object], ...] = (),
    jwks_uri: str = "",
    require_iss_eq_sub: bool = True,
) -> dict[str, object] | None:
    """Vérifie une assertion signée asymétriquement avec une clé enregistrée.

    Les clés publiques proviennent des ``jwks`` embarqués du client ou sont
    récupérées à sa ``jwks_uri`` (reprise du pattern ``PyJWKClient`` de la
    vérification distante des jetons de gestion — ``infrastructure/bearer``) ;
    le choix de la clé s'appuie sur le ``kid`` de l'assertion.
    """
    if not jwks and not jwks_uri:
        return None
    try:
        signing_key = await asyncio.to_thread(_resolve_signing_key, token, jwks, jwks_uri)
        algorithm = pyjwt.get_unverified_header(token)["alg"]  # NOSONAR(S5659)
    except (pyjwt.PyJWTError, KeyError, OSError, ValueError):
        return None
    if signing_key is None:
        return None
    return _decode(
        token,
        signing_key,
        algorithms=[algorithm],
        audience=audience,
        issuer=issuer,
        require_iss_eq_sub=require_iss_eq_sub,
    )


def _resolve_signing_key(
    token: str,
    jwks: tuple[dict[str, object], ...],
    jwks_uri: str,
) -> object | None:
    """Retourne la clé de vérification (JWKS embarqué ou distant) de l'assertion.

    ``PyJWKSet`` ne propose pas de résolution par JWT : le ``kid`` de
    l'en-tête est donc lu directement et la clé correspondante est choisie
    dans le set (le ``kid`` est obligatoire pour les assertions à JWKS).
    """
    if jwks:
        try:
            kid = pyjwt.get_unverified_header(token).get("kid")
        except pyjwt.PyJWTError:
            return None
        if not kid:
            return None
        jwk_set = PyJWKSet(list(jwks))
        for candidate in jwk_set.keys:
            if candidate.key_id == kid:
                return cast(object, candidate)
        return None
    client = PyJWKClient(jwks_uri, timeout=_JWKS_TIMEOUT)
    return cast(object, client.get_signing_key_from_jwt(token))


def _decode(
    token: str,
    key: object,
    *,
    algorithms: tuple[str, ...] | list[str],
    audience: str,
    issuer: str,
    require_iss_eq_sub: bool,
) -> dict[str, object] | None:
    """Décode et valide l'assertion (signature, ``aud``, ``exp``, ``iss``)."""
    try:
        claims = pyjwt.decode(
            token,
            key,  # type: ignore[arg-type]  # clé JWK (types-PyJWT ne couvre pas le cas client)
            algorithms=algorithms,
            audience=audience,
            issuer=issuer,
            options=_required_options(require_iss_eq_sub),
        )
    except pyjwt.PyJWTError:
        return None
    if require_iss_eq_sub and claims.get("sub") != claims.get("iss"):
        return None
    if not claims.get("sub"):
        return None
    return claims
