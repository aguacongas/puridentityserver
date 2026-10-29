"""Détails d'autorisation RFC 9396 pour l'émission de credentials OpenID4VCI 1.0 §5.1.1.

Le paramètre ``authorization_details`` (RFC 9396 §2) porte, dans un flow
OpenID4VCI, les configurations de credential demandées sous la forme du type
``openid_credential``. Ce module regroupe la validation, la canonicalisation
et la conversion vers la forme accordée (avec ``credential_identifiers``)
retournée par le token endpoint (OID4VCI 1.0 §6.2).
"""

from __future__ import annotations

import json
from typing import Any

#: Type de détail d'autorisation introduit par OpenID4VCI 1.0 §5.1.1.
OPENID_CREDENTIAL_TYPE = "openid_credential"

#: Configuration de credential publiée par l'OP (doit rester synchronisée
#: avec ``oid4vci.CREDENTIAL_CONFIGURATION_ID``).
CREDENTIAL_CONFIGURATION_ID = "puridentityserver-sdjwt-vc"

#: Configurations de credential reconnues par l'OP.
SUPPORTED_CREDENTIAL_CONFIGURATION_IDS = frozenset({CREDENTIAL_CONFIGURATION_ID})


class AuthorizationDetailsError(ValueError):
    """Détails d'autorisation mal formés ou non supportés."""


def parse_authorization_details(raw: str) -> tuple[dict[str, Any], ...]:
    """Valide et normalise le paramètre ``authorization_details``.

    Renvoie la liste des détails de type ``openid_credential`` reconnus
    (les types inconnus sont ignorés, RFC 9396 §5). Lève
    :class:`AuthorizationDetailsError` si la forme JSON est invalide ou si
    un détail ``openid_credential`` est mal formé ou désigne une
    configuration inconnue. Une chaîne vide donne le tuple vide.
    """
    if not raw:
        return ()
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise AuthorizationDetailsError(
            "authorization_details doit être un tableau JSON valide (RFC 9396 §2)"
        ) from exc
    if not isinstance(value, list):
        raise AuthorizationDetailsError(
            "authorization_details doit être un tableau JSON (RFC 9396 §2)"
        )
    details: list[dict[str, Any]] = []
    for item in value:
        parsed = _parse_detail(item)
        if parsed is not None:
            details.append(parsed)
    return tuple(details)


def _parse_detail(item: object) -> dict[str, Any] | None:
    """Valide un détail et renvoie le détail normalisé, ou ``None`` si ignoré."""
    if not isinstance(item, dict):
        raise AuthorizationDetailsError(
            "chaque détail d'autorisation doit être un objet JSON (RFC 9396 §2)"
        )
    detail_type = item.get("type")
    if not isinstance(detail_type, str) or not detail_type:
        raise AuthorizationDetailsError(
            "type manquant ou invalide dans un détail d'autorisation (RFC 9396 §2)"
        )
    if detail_type != OPENID_CREDENTIAL_TYPE:
        # Type inconnu pour l'OP : ignoré (RFC 9396 §5).
        return None
    config = item.get("credential_configuration_id")
    if not isinstance(config, str) or not config:
        raise AuthorizationDetailsError(
            "credential_configuration_id requis pour un détail openid_credential "
            "(OpenID4VCI 1.0 §5.1.1)"
        )
    if config not in SUPPORTED_CREDENTIAL_CONFIGURATION_IDS:
        raise AuthorizationDetailsError(f"credential_configuration_id inconnu : {config}")
    detail: dict[str, Any] = {
        "type": OPENID_CREDENTIAL_TYPE,
        "credential_configuration_id": config,
    }
    claims_value = item.get("claims")
    if claims_value is not None:
        if not isinstance(claims_value, dict):
            raise AuthorizationDetailsError(
                "claims doit être un objet JSON dans un détail openid_credential"
            )
        detail["claims"] = claims_value
    return detail


def encode_authorization_details(details: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> str:
    """Sérialise une liste de détails en chaîne JSON canonique."""
    return json.dumps([dict(d) for d in details], sort_keys=True, separators=(",", ":"))


def authorization_detail_keys(
    details: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> frozenset[str]:
    """Clés canoniques par détail, pour la persistance dans un consentement."""
    return frozenset(json.dumps(dict(d), sort_keys=True, separators=(",", ":")) for d in details)


def grant_authorization_details(
    details: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Ajoute ``credential_identifiers`` à chaque détail accordé (OID4VCI 1.0 §6.2)."""
    granted: list[dict[str, Any]] = []
    for detail in details:
        config = str(detail["credential_configuration_id"])
        granted.append(
            {
                **dict(detail),
                "credential_identifiers": [config],
            }
        )
    return granted


def credential_configuration_for_identifier(claim: object, identifier: str) -> str | None:
    """Résout la configuration associée à un ``credential_identifier`` du jeton.

    Renvoie l'identifiant de configuration quand ``identifier`` figure dans
    les ``credential_identifiers`` d'un détail accordé, ``None`` sinon.
    """
    if not isinstance(claim, list):
        return None
    for detail in claim:
        if not isinstance(detail, dict) or detail.get("type") != OPENID_CREDENTIAL_TYPE:
            continue
        ids = detail.get("credential_identifiers")
        if not isinstance(ids, list) or identifier not in ids:
            continue
        config = detail.get("credential_configuration_id")
        if isinstance(config, str) and config:
            return config
    return None


def has_authorization_details(claim: object) -> bool:
    """Indique si un claim ``authorization_details`` est présent et non vide."""
    return isinstance(claim, list) and bool(claim)
