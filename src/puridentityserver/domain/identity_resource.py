"""Entités des IdentityResources (scopes identité) du serveur OIDC.

Modèle inspiré d'IdentityServer/Duende : une ``IdentityResource`` associe
un nom de scope à la liste des claims utilisateur exposés quand ce scope
est accordé. Les resources seedées par défaut servent de base à
``scopes_supported`` / ``claims_supported`` du discovery et au filtrage
des claims en ``/userinfo`` (OIDC Core 1.0 §5.4).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityResource:
    """Scope identité et les claims qu'il expose (modèle IdentityServer/Duende).

    ``name`` est le nom du scope (ex. ``profile``), ``display_name`` le
    libellé humain, ``user_claims`` l'ensemble des claims utilisateur
    rendus accessible quand le scope est accordé au jeton, et
    ``show_in_discovery_document`` contrôle sa présence dans
    ``scopes_supported`` du document de discovery.
    """

    name: str
    display_name: str = ""
    user_claims: frozenset[str] = frozenset()
    show_in_discovery_document: bool = True


DEFAULT_IDENTITY_RESOURCES: tuple[IdentityResource, ...] = (
    IdentityResource(name="openid", display_name="Votre identité", user_claims=frozenset({"sub"})),
    IdentityResource(
        name="profile",
        display_name="Votre profil",
        user_claims=frozenset(
            {
                "name",
                "family_name",
                "given_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
                "roles",
            }
        ),
    ),
    IdentityResource(
        name="email",
        display_name="Votre adresse e-mail",
        user_claims=frozenset({"email", "email_verified"}),
    ),
    IdentityResource(
        name="address",
        display_name="Votre adresse postale",
        user_claims=frozenset({"address"}),
    ),
    IdentityResource(
        name="phone",
        display_name="Votre numéro de téléphone",
        user_claims=frozenset({"phone_number", "phone_number_verified"}),
    ),
    IdentityResource(
        name="offline_access",
        display_name="Accès hors ligne (refresh token)",
        user_claims=frozenset(),
    ),
)


def default_claims_map() -> dict[str, frozenset[str]]:
    """Claims historisés par scope depuis les IdentityResources par défaut."""
    return {resource.name: resource.user_claims for resource in DEFAULT_IDENTITY_RESOURCES}
