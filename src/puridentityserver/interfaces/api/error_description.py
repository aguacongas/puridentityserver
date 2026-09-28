"""Normalisation d'``error_description`` pour les réponses d'erreur OAuth 2.0.

Partagée par l'endpoint de jetons (corps JSON, RFC 6749 §5.2) et par les
redirections d'erreur d'``/authorize`` et de ``/consent`` (RFC 6749 §4.1.2.1
et §4.2.2.1) : la suite de certification OIDC valide le jeu de caractères de
``error_description`` (``%x20-21 / %x23-5B / %x5D-7E``) sur ces deux voies.
"""

from __future__ import annotations

import unicodedata


def ascii_error_description(value: str) -> str:
    """Réduit ``error_description`` à l'ensemble de caractères imposé par OAuth 2.0.

    La RFC 6749 limite ``error_description`` aux caractères
    ``%x20-21 / %x23-5B / %x5D-7E`` : les lettres accentuées y sont
    illégitimes. Les accents sont translittérés (NFKD) puis tout caractère
    restant hors jeu est retiré.
    """
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_flat = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return "".join(
        ch
        for ch in ascii_flat
        if 0x20 <= ord(ch) <= 0x21 or 0x23 <= ord(ch) <= 0x5B or 0x5D <= ord(ch) <= 0x7E
    )
