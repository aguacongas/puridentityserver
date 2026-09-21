"""Entités des ApiResources (ressources protégées / scopes d'API) du serveur OIDC.

Modèle inspiré d'IdentityServer/Duende : une ``ApiResource`` regroupe un
nom d'audience (le resource server cible de l'access token) et les scopes
d'API qu'elle déclare (ex. ``api.read``). Leurs scopes viennent compléter
``scopes_supported`` du discovery, l'``aud`` d'un access token porte le nom
des resources dont des scopes ont été accordés, et toute demande portant
un scope non enregistré (standard ou API) est rejetée en ``invalid_scope``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ApiResource:
    """Ressource protégée et les scopes d'API qu'elle expose.

    ``name`` est l'audience de l'access token (ex. ``api``), ``display_name``
    le libellé humain, ``scopes`` l'ensemble des scopes d'API appartenant à
    cette resource (ex. ``api.read`` / ``api.write``), et
    ``allowed_access_token_signing_algos`` la liste restreinte des
    algorithmes de signature acceptables pour les access tokens destinés à
    cette resource (vide = tous les algorithmes configurés).
    """

    name: str
    display_name: str = ""
    scopes: frozenset[str] = frozenset()
    allowed_access_token_signing_algos: tuple[str, ...] = ()
