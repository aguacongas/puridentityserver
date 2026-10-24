"""Schémas du JSON Web Key Set (RFC 7517)."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import BaseModel

from puridentityserver.domain.jwe import JWEKeyManagementAlgorithm
from puridentityserver.domain.jwks import KeyPair, KeyUse


class JWKKeyResponse(BaseModel):
    """Clé publique au format JSON Web Key (RFC 7517 §4).

    Les champs présents dépendent de la famille de clé : ``n``/``e`` pour
    RSA, ``crv``/``x``/``y`` pour EC. Les membres inapplicables sont
    **ommis** du JSON (et non sérialisés ``null``) : un JWK ne porte que
    les paramètres de sa clé (RFC 7517 §4) - la suite de certification
    lit ces membres sans tolérer de ``null``. L'omission est appliquée par
    la route (``response_model_exclude_none``) : pydantic 2.13 n'accepte
    plus ``exclude_none`` dans le ``ConfigDict`` du modèle.
    """

    kty: str
    kid: str
    use: str | None = "sig"
    alg: str | None = None
    crv: str | None = None
    n: str | None = None
    e: str | None = None
    x: str | None = None
    y: str | None = None

    @classmethod
    def from_key_pair(cls, key_pair: KeyPair) -> JWKKeyResponse:
        """Convertit une paire de clés (PEM) en JWK public."""
        public_key = load_pem_public_key(key_pair.public_key_pem.encode("ascii"))

        # Une clé de chiffrement sert plusieurs algorithmes de gestion de
        # clé (RSA-OAEP et RSA-OAEP-256 pour une même clé RSA) : le membre
        # ``use`` reste omis (RFC 7517 §4.2, optionnel) pour rester
        # compatible avec les validations JWKS de la suite de certification
        # (OIDFED-3 / OIDCD-3, qui n'acceptent que ``use: sig`` ou absent),
        # tandis que ``alg`` porte ``RSA-OAEP`` (OIDC Core 1.0 §10.1,
        # issue #204). La suite sélectionne la clé via ``kty`` + ``use``
        # (``{enc, null}``, cf. ``JWEUtil.selectAsymmetricKeyForEncryption``).
        encrypted = key_pair.use is KeyUse.ENC
        common = {
            "kty": key_pair.algorithm.key_type.value,
            "kid": key_pair.kid,
            "use": None if encrypted else "sig",
            "alg": (
                JWEKeyManagementAlgorithm.RSA_OAEP.value if encrypted else key_pair.algorithm.value
            ),
        }
        if isinstance(public_key, rsa.RSAPublicKey):
            common.update(
                n=_int_to_base64url(public_key.public_numbers().n),
                e=_int_to_base64url(public_key.public_numbers().e),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            number = public_key.public_numbers()
            common.update(
                crv=key_pair.algorithm.curve,
                x=_ec_coord_to_base64url(number.x, public_key.curve),
                y=_ec_coord_to_base64url(number.y, public_key.curve),
            )
        return cls(**common)


class JWKSetResponse(BaseModel):
    """Jeu de clés JWK (RFC 7517 §5)."""

    keys: list[JWKKeyResponse]


def _int_to_base64url(value: int) -> str:
    """Encode un entier non signé en base64url (RFC 7515 §6.1)."""
    byte_length = max(1, (value.bit_length() + 7) // 8)
    return _to_base64url(value.to_bytes(byte_length, "big"))


def _ec_coord_to_base64url(value: int, curve: ec.EllipticCurve) -> str:
    """Encode une coordonnée EC à longueur de champ fixe (RFC 7518 §6.2.1).

    Les coordonnées ``x``/``y`` font exactement la taille de la courbe
    arrondie au-dessus (P-256 : 32, P-521 : 66 octets) avec zéros de tête,
    sous peine de rejet à la lecture (``Coords should be N bytes for
    curve …``).
    """
    return _to_base64url(value.to_bytes((curve.key_size + 7) // 8, "big"))


def _to_base64url(value: bytes) -> str:
    """Encode des octets en base64url sans padding (RFC 7515 §6.1)."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
