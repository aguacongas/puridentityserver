"""Normalisation d'``error_description`` au jeu de caractères OAuth 2.0 (RFC 6749).

``error_description`` est limité à ``%x20-21 / %x23-5B / %x5D-7E`` aussi bien
dans les réponses JSON (RFC 6749 §5.2) que dans les redirections d'erreur de
l'endpoint d'autorisation (RFC 6749 §4.1.2.1, §4.2.2.1) : la suite de
certification OIDC valide ce jeu sur les deux voies.
"""

from puridentityserver.interfaces.api.error_description import ascii_error_description


def test_strips_section_sign() -> None:
    assert ascii_error_description("nonce requis (OIDC Core 1.0 §3.2.2.10)") == (
        "nonce requis (OIDC Core 1.0 3.2.2.10)"
    )


def test_removes_accents() -> None:
    assert ascii_error_description("Paramètre 'token' manquant") == ("Parametre 'token' manquant")


def test_drops_disallowed_characters() -> None:
    assert ascii_error_description('guillemets " et antislash \\ gardés') == (
        "guillemets  et antislash  gardes"
    )


def test_keeps_allowed_ascii() -> None:
    value = "error=invalid_request&state=abc-123"
    assert ascii_error_description(value) == value
