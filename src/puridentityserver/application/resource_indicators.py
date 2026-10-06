"""Resource Indicators (RFC 8707) : lecture et contrôle du paramètre ``resource``.

Le paramètre ``resource`` désigne la (ou les) ressource(s) cible(s) d'un
access token : une ou plusieurs URI **absolues sans fragment** (RFC 8707
§2.1), répétées dans une requête form-urlencoded ou encodées en tableau
JSON compact dans un claim de request object (JAR). Chaque URI doit
correspondre à l'``indicator`` déclaré d'une ``ApiResource`` enregistrée,
sinon la demande est rejetée ``invalid_target`` (§2.2).
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from puridentityserver.domain.api_resource import is_resource_uri

__all__ = [
    "encode_resource_parameter",
    "is_resource_uri",
    "parse_resource_parameter",
    "resource_audience",
]


def parse_resource_parameter(value: str) -> tuple[str, ...]:
    """Décode la valeur brute du paramètre en tuple d'URI dédupliquées.

    L'ordre d'apparition est conservé. Une chaîne vide donne un tuple
    vide ; un tableau JSON compact (occurrences multiples repliées par la
    couche HTTP, ou claim JAR sérialisé) est décodé ; tout autre scalaire
    est traité comme une URI unique (au besoin rejetée ``invalid_target``
    par l'appelant).
    """
    raw = value.strip()
    if not raw:
        return ()
    candidates: list[object]
    if raw.startswith("["):
        try:
            decoded = json.loads(raw)
        except ValueError:
            candidates = [raw]
        else:
            candidates = decoded if isinstance(decoded, list) else [decoded]
    else:
        candidates = [raw]
    ordered: list[str] = []
    for candidate in candidates:
        text = candidate.strip() if isinstance(candidate, str) else str(candidate)
        if text and text not in ordered:
            ordered.append(text)
    return tuple(ordered)


def encode_resource_parameter(values: Sequence[str]) -> str:
    """Replie les occurrences multiples de ``resource`` en une chaîne unique.

    Les dictionnaires de paramètres HTTP (query, corps form, PAR) ne
    conservent qu'une valeur par clé : un seul ``resource`` voyage tel
    quel, plusieurs sont encodés en tableau JSON compact — forme
    que :func:`parse_resource_parameter` décode. L'ordre d'apparition est
    conservé et les doublons supprimés.
    """
    ordered = tuple(dict.fromkeys(value.strip() for value in values if value.strip()))
    if not ordered:
        return ""
    if len(ordered) == 1:
        return ordered[0]
    return json.dumps(list(ordered), ensure_ascii=False, separators=(",", ":"))


def resource_audience(resources: Sequence[str]) -> str | list[str]:
    """Convertit les resources ciblées en claim ``aud`` (RFC 7519 §4.1.3).

    Chaîne quand une seule ressource est ciblée, liste telle quelle sinon
    (l'ordre du client est préservé).
    """
    if len(resources) == 1:
        return resources[0]
    return list(resources)
