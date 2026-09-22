"""Conformité des clés JWKS enregistrées par un client (RFC 7517/7518).

Validation **structurelle** de chaque JWK (famille ``kty`` supportée —
``RSA``/``EC``, jamais ``oct`` côté client —, membres ``n``/``e`` ou
``crv``/``x``/``y`` requis et en base64url valide, module RSA ≥ 2048 bits
comme l'exige le RFC 7518 §4.3, ``use`` et ``alg`` cohérents avec la
famille) et d'**usage** : le matériel déclaré doit pouvoir servir les
algorithmes métier du client — chiffrement ``RSA-OAEP*`` de l'``id_token``
et authentification ``private_key_jwt``.

Ces vérifications sont d'abord appliquées à l'enregistrement (rejet
``invalid_client_metadata``), puis rejouées à l'émission en défense en
profondeur (``infrastructure/jwe``, assertions JWKS).
"""

from __future__ import annotations

import base64
import binascii
import re

from puridentityserver.domain.jwe import JWEKeyManagementAlgorithm
from puridentityserver.domain.jwks import JWTAlgorithm

# Alphabet base64url (RFC 7515 §2) des membres binaires d'un JWK.
_B64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]*$")

# Taille minimale du module RSA imposée par le RFC 7518 §4.3 (RSA-OAEP*).
_MIN_RSA_MODULUS_BITS = 2048

_SUPPORTED_KTYS = frozenset({"RSA", "EC"})

_USE_VALUES = frozenset({"sig", "enc"})

_EC_CURVES = frozenset({"P-256", "P-384", "P-521"})

_ALGORITHMS_BY_KTY: dict[str, frozenset[str]] = {
    "RSA": frozenset(
        algorithm.value
        for algorithm in (
            JWTAlgorithm.RS256,
            JWTAlgorithm.RS384,
            JWTAlgorithm.RS512,
            JWTAlgorithm.PS256,
            JWTAlgorithm.PS384,
            JWTAlgorithm.PS512,
        )
    )
    | frozenset(
        {JWEKeyManagementAlgorithm.RSA_OAEP.value, JWEKeyManagementAlgorithm.RSA_OAEP_256.value}
    ),
    "EC": frozenset(
        algorithm.value
        for algorithm in (JWTAlgorithm.ES256, JWTAlgorithm.ES384, JWTAlgorithm.ES512)
    ),
}


def validate_client_jwks(keys: tuple[dict[str, object], ...]) -> tuple[str, ...]:
    """Problèmes structurels des clés (vide si conforme) ; ``jwks[i] : raison``."""
    return tuple(
        f"jwks[{index}] : {problem}"
        for index, key in enumerate(keys)
        if (problem := _jwk_problem(key))
    )


def usable_for_signing(keys: tuple[dict[str, object], ...]) -> tuple[dict[str, object], ...]:
    """Clés pouvant servir de signature (jamais une clé déclarée ``use: enc``)."""
    return tuple(key for key in keys if _use(key) != "enc")


def require_signing_key(keys: tuple[dict[str, object], ...]) -> str | None:
    """Message d'erreur si aucune clé RSA/EC signante (``use`` ``sig`` ou absent)."""
    for key in usable_for_signing(keys):
        if _kty(key) in _SUPPORTED_KTYS:
            return None
    return (
        "Aucune clé de signature dans jwks utilisable pour private_key_jwt "
        "(kty RSA ou EC, use 'sig' ou absent)"
    )


def require_encryption_rsa_key(keys: tuple[dict[str, object], ...]) -> str | None:
    """Message d'erreur si aucune clé RSA utilisable pour ``RSA-OAEP*``."""
    for key in keys:
        if _kty(key) != "RSA" or _use(key) == "sig":
            continue
        modulus = _positive_int(key.get("n"))
        if modulus is not None and modulus.bit_length() >= _MIN_RSA_MODULUS_BITS:
            return None
    return (
        "Aucune clé publique RSA dans jwks utilisable pour RSA-OAEP "
        "(kty RSA, use 'enc' ou absent, module >= 2048 bits)"
    )


def _jwk_problem(key: dict[str, object]) -> str:
    """Première violation structurelle du JWK (chaîne vide si conforme)."""
    kty = _kty(key)
    if kty not in _SUPPORTED_KTYS:
        return f"kty '{key.get('kty')}' non supporté (clients : RSA, EC)"
    use = key.get("use")
    if use is not None and (not isinstance(use, str) or use not in _USE_VALUES):
        return f"use '{use}' non supporté (attendu 'sig' ou 'enc')"
    algorithm = key.get("alg")
    if algorithm is not None and (
        not isinstance(algorithm, str) or algorithm not in _ALGORITHMS_BY_KTY[kty]
    ):
        return f"alg '{algorithm}' non supporté pour une clé {kty}"
    if kty == "RSA":
        return _rsa_problem(key)
    return _ec_problem(key)


def _rsa_problem(key: dict[str, object]) -> str:
    """Vérifie ``n``/``e`` (base64url valide) et la taille du module."""
    modulus = _positive_int(key.get("n"))
    exponent = _positive_int(key.get("e"))
    if modulus is None or exponent is None:
        return "clé RSA incomplète : membres n et e requis en base64url valide"
    if modulus.bit_length() < _MIN_RSA_MODULUS_BITS:
        return (
            f"module RSA de {modulus.bit_length()} bits : "
            f"minimum {_MIN_RSA_MODULUS_BITS} bits (RFC 7518 §4.3)"
        )
    return ""


def _ec_problem(key: dict[str, object]) -> str:
    """Vérifie ``crv`` (courbe supportée) et ``x``/``y`` (base64url valide)."""
    curve = key.get("crv")
    if not isinstance(curve, str) or curve not in _EC_CURVES:
        return f"crv '{curve}' non supporté (attendu P-256, P-384 ou P-521)"
    if _positive_int(key.get("x")) is None or _positive_int(key.get("y")) is None:
        return "clé EC incomplète : membres x et y requis en base64url valide"
    return ""


def _kty(key: dict[str, object]) -> str:
    """Famille ``kty`` normalisée (majuscules), vide si absente."""
    value = key.get("kty")
    return str(value).upper() if isinstance(value, str) else ""


def _use(key: dict[str, object]) -> str:
    """Usage ``use`` du JWK (chaîne vide si absent)."""
    value = key.get("use")
    return value if isinstance(value, str) else ""


def _positive_int(value: object) -> int | None:
    """Décode un membre JWK base64url big-endian en entier strictement positif."""
    if not isinstance(value, str) or _B64URL_PATTERN.match(value) is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    number = int.from_bytes(raw, "big")
    return number if number > 0 else None
