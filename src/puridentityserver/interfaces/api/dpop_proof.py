"""Lecture de l'en-tête ``DPoP`` des requêtes entrantes (RFC 9449 §7.1)."""

from __future__ import annotations

from starlette.datastructures import Headers


def extract_dpop_proof(headers: Headers) -> tuple[str, str | None]:
    """Preuve ``DPoP`` portée par les en-têtes : valeur unique ou erreur.

    RFC 9449 §7.1 : chaque message ne doit porter qu'un seul en-tête
    ``DPoP`` — plusieurs occurrences valent ``invalid_request`` (message
    rendu par l'appelant). Retourne ``(preuve, None)`` ou
    ``(« », message d'erreur)`` ; aucune preuve rend ``("" , None)``.
    """
    values = headers.getlist("dpop")
    if len(values) > 1:
        return "", "La requête ne doit contenir qu'un en-tête DPoP (RFC 9449 §7.1)"
    return (values[0].strip() if values else ""), None
