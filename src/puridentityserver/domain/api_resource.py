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
from urllib.parse import urlsplit


def is_resource_uri(value: str) -> bool:
    """Vérifie qu'une URI de resource indicator est absolue et sans fragment (RFC 8707 §2.1).

    Un schéma et une composante d'autorité (``scheme://host``) sont
    requis — cible HTTP(S) d'un resource server — et tout fragment est
    proscrit.
    """
    if not value:
        return False
    parts = urlsplit(value)
    return bool(parts.scheme and parts.netloc and not parts.fragment)


@dataclass(frozen=True, slots=True)
class ApiResource:
    """Ressource protégée et les scopes d'API qu'elle expose.

    ``name`` est l'audience de l'access token (ex. ``api``), ``display_name``
    le libellé humain, ``scopes`` l'ensemble des scopes d'API appartenant à
    cette resource (ex. ``api.read`` / ``api.write``),
    ``allowed_access_token_signing_algos`` la liste restreinte des
    algorithmes de signature acceptables pour les access tokens destinés à
    cette resource (vide = tous les algorithmes configurés), et
    ``indicator`` l'URI absolue reconnue comme ``resource`` au sens de
    RFC 8707 (vide = aucun resource indicator).
    """

    name: str
    display_name: str = ""
    scopes: frozenset[str] = frozenset()
    allowed_access_token_signing_algos: tuple[str, ...] = ()
    indicator: str = ""
