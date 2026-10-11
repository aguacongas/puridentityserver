"""Invariant d'encodage des JWK EC du harness FAPI2 (RFC 7518 §6.2.1)."""

import base64

from fapi2_harness import DpopSigner, _b64url_int


def _decode(value: str) -> bytes:
    """Décode un base64url sans padding."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_b64url_int_keeps_leading_zero_bytes() -> None:
    """Coordonnée tête nulle conservée sur 32 octets, non tronquée (RFC 7518 §6.2.1)."""
    assert _decode(_b64url_int(1)) == b"\x00" * 31 + b"\x01"


def test_dpop_signer_jwk_uses_full_curve_field_length() -> None:
    """``x``/``y`` de la clé publique du signer font la pleine taille de P-256."""
    jwk = DpopSigner().jwk
    assert jwk["crv"] == "P-256"
    assert len(_decode(jwk["x"])) == 32
    assert len(_decode(jwk["y"])) == 32
