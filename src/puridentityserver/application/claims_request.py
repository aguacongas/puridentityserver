"""Paramètre ``claims`` (OIDC Core 1.0 §5.5) et sélection des claims par scope.

Regroupe trois responsabilités partagées par les cas d'utilisation
``/authorize``, ``/token`` et ``/userinfo`` :

- ``parse_claims_parameter`` : validation du paramètre ``claims`` de la
  demande d'autorisation (objet JSON à membres ``userinfo``/``id_token``) ;
- ``allowed_scope_claims`` : dérivation scope → claims autorisés depuis les
  IdentityResources (le même filtrage que l'endpoint UserInfo) ;
- la résolution des valeurs demandées depuis le user store, pour compléter
  l'id_token (member ``id_token`` + claims des scopes en ``response_type=
  id_token``) et l'access_token (member ``userinfo``, lu par ``/userinfo``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.readers import IdentityResourceReader

_CLAIMS_MEMBERS = frozenset({"userinfo", "id_token"})


@dataclass(frozen=True, slots=True)
class ClaimsRequest:
    """Claims demandés par le paramètre ``claims`` (OIDC Core 1.0 §5.5.1).

    Seuls les **noms** de claims sont retenus : les contraintes
    (``essential``, ``value``/``values``) sont acceptées à la validation mais
    les valeurs rendues restent toujours celles du user store — l'OP ne
    fabrique aucune donnée de profil.
    """

    userinfo: tuple[str, ...] = ()
    id_token: tuple[str, ...] = ()


def parse_claims_parameter(value: str) -> ClaimsRequest | None:
    """Parse le paramètre ``claims`` ; ``None`` si le JSON est malformé.

    Structure attendue (OIDC Core 1.0 §5.5.1) : un objet JSON dont les
    membres ``userinfo`` et ``id_token`` sont des objets associant un nom de
    claim à un objet de contraintes. Les membres inconnus sont ignorés ;
    un membre connu de forme invalide — ou un JSON non objet — rend
    ``None``, que ``validate_authorization_request`` traduit en réponse
    ``invalid_request`` (OIDC Core 1.0 §3.1.2.1).
    """
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    members: dict[str, tuple[str, ...]] = {}
    for member in _CLAIMS_MEMBERS:
        if member not in parsed:
            continue
        claims_object = parsed[member]
        if not isinstance(claims_object, dict):
            return None
        names: list[str] = []
        for name, constraints in claims_object.items():
            if not isinstance(constraints, dict):
                return None
            names.append(str(name))
        members[member] = tuple(names)
    return ClaimsRequest(
        userinfo=members.get("userinfo", ()),
        id_token=members.get("id_token", ()),
    )


def requested_userinfo_payload(request: ClaimsRequest) -> dict[str, object]:
    """Payload complémentaire de l'access_token portant les claims userinfo.

    L'access_token est le seul lien entre l'autorisation et l'endpoint
    ``/userinfo`` (aucun store de grant intermédiaire) : les noms de claims
    du member ``userinfo`` voyagent dans le claim ``claims`` du jeton, au
    format du paramètre source, d'où ``/userinfo`` les relit pour élargir le
    filtrage par scopes.
    """
    if not request.userinfo:
        return {}
    return {"claims": {"userinfo": list(request.userinfo)}}


def requested_userinfo_claims(claims_parameter: object) -> set[str]:
    """Noms de claims userinfo demandés lus dans le payload d'un access_token.

    ``claims_parameter`` est la valeur du claim ``claims`` du jeton (dictionnaire
    au format du paramètre source) ; toute forme inattendue est ignorée et le
    filtrage par scopes seul s'applique.
    """
    if not isinstance(claims_parameter, dict):
        return set()
    names = claims_parameter.get("userinfo")
    if not isinstance(names, list):
        return set()
    return {str(name) for name in names}


async def allowed_scope_claims(
    scope: str,
    identity_resources: IdentityResourceReader | None = None,
) -> set[str]:
    """Claims autorisés par les scopes accordés (OIDC Core 1.0 §5.4).

    Chaque scope nommé dans ``scope`` (séparé par des espaces, RFC 6749
    §3.3) est mis en correspondance avec une IdentityResource : ses
    ``user_claims`` deviennent accessibles. ``sub`` est toujours autorisé
    (claim réservé d'OpenID Connect). Sans registre injecté, les resources
    par défaut s'appliquent.
    """
    resources = DEFAULT_IDENTITY_RESOURCES
    if identity_resources is not None:
        stored = await identity_resources.find_all()
        if stored:
            resources = tuple(stored)
    scope_names = set(scope.split())
    allowed: set[str] = {"sub"}
    for resource in resources:
        if resource.name in scope_names:
            allowed |= set(resource.user_claims)
    return allowed


async def resolve_requested_claims(
    names: tuple[str, ...],
    subject: str,
    claims_provider: ClaimsProvider | None,
) -> dict[str, object]:
    """Résout les valeurs des claims ``names`` depuis le user store.

    Les claims absents du profil sont simplement omis (OIDC Core 1.0 §5.5 :
    un claim demandé mais inconnu de l'OP ne peut être rendu). Sans ``subject``
    ni ``ClaimsProvider`` injecté, aucun claim n'est ajouté.
    """
    if not names or claims_provider is None or not subject:
        return {}
    user_claims = await claims_provider.get_claims(subject)
    return {name: value for name, value in user_claims.claims.items() if name in set(names)}


async def scope_claims_for_subject(
    scope: str,
    subject: str,
    claims_provider: ClaimsProvider | None,
    identity_resources: IdentityResourceReader | None = None,
) -> dict[str, object]:
    """Résout les claims des scopes accordés pour ``subject``.

    Utilisé pour compléter l'id_token émis par ``/authorize`` en
    ``response_type=id_token`` : sans access_token ni UserInfo possible,
    les claims des scopes y sont retournés directement (OIDC Core 1.0
    §5.4). Mêmes sources et même filtrage que l'endpoint ``/userinfo``.
    """
    if claims_provider is None or not subject:
        return {}
    allowed = await allowed_scope_claims(scope, identity_resources)
    user_claims = await claims_provider.get_claims(subject)
    return {name: value for name, value in user_claims.claims.items() if name in allowed}
