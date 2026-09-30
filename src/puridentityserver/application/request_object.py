"""Request objects (RFC 9101 §5) : ``request`` par valeur, ``request_uri`` par référence.

L'OP accepte les request objects **non signés** (``alg=none``) : c'est la
condition de saut ``skipTestIfNoneUnsupported`` des modules
``oidcc-unsigned-request-object-…``, ``oidcc-request-uri-unsigned-…`` et
``oidcc-ensure-request-object-with-redirect-uri`` (issue #76). Les claims du
jeton priment sur les paramètres de requête (OIDC Core 1.0 §6.1) : c'est ce
qui rend valide la ``redirect_uri`` portée par le request object quand la
query en porte une non enregistrée.

Une référence ``urn:ietf:params:oauth:request_uri:…`` est l'URN opaque d'une
demande poussée (RFC 9126 §6.2) : elle reste du ressort de la résolution PAR
du routeur ``/authorize`` et n'est jamais récupérée sur le réseau.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass

from puridentityserver.domain.authorization import PUSHED_REQUEST_URI_PREFIX
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.request_object import RequestObjectFetcher

#: Seul ``alg=none`` est accepté (JWA RFC 7519 §6) : c'est l'algorithme que la
#: suite de certification annonce pour rejouer les modules ``request``.
REQUEST_OBJECT_SIGNING_ALGORITHMS: tuple[str, ...] = (JWTAlgorithm.NONE.value,)

#: Paramètres du transport : ils n'existent que dans la query, jamais dans le jeton.
_EMBEDDED = frozenset(("request", "request_uri"))


@dataclass(frozen=True, slots=True)
class RequestObjectError:
    """Refus de traiter le request object (RFC 6749 §3.1.1, RFC 9101 §4)."""

    error: str
    error_description: str


@dataclass(frozen=True, slots=True)
class RequestObjectConfig:
    """Algorithmes de request object acceptés par l'OP."""

    signing_algorithms: tuple[str, ...] = REQUEST_OBJECT_SIGNING_ALGORITHMS


def is_pushed_request_uri(reference: str) -> bool:
    """True si ``reference`` est l'URN opaque d'une demande poussée (RFC 9126 §6.2)."""
    return reference.startswith(PUSHED_REQUEST_URI_PREFIX)


class RequestObjectResolver:
    """Incorpore le request object aux paramètres de ``/authorize``."""

    def __init__(self, config: RequestObjectConfig, fetcher: RequestObjectFetcher) -> None:
        """Injection de la configuration d'algorithmes et du port de lecture du document."""
        self._config = config
        self._fetcher = fetcher

    async def resolve(self, params: Mapping[str, str]) -> dict[str, str] | RequestObjectError:
        """Retourne les paramètres complétés par le request object, ou son refus.

        Sans ``request`` ni ``request_uri``, les paramètres sont renvoyés tels
        quels : l'appel peut donc être placé en tête du traitement d'une
        demande non poussée.
        """
        document, error = await self._document(params)
        if error is not None:
            return error
        if not document:
            return dict(params)
        claims, error = _claims(document, self._config.signing_algorithms)
        if error is not None:
            return error
        return _merge(params, claims)

    async def _document(self, params: Mapping[str, str]) -> tuple[str, RequestObjectError | None]:
        """Obtient le document du request object : par valeur, ou par référence."""
        by_value = params.get("request", "")
        reference = params.get("request_uri", "")
        if by_value and reference:
            return "", RequestObjectError(
                error="invalid_request",
                error_description="request et request_uri sont mutuellement exclusifs "
                "(RFC 9101 §4)",
            )
        if by_value:
            return by_value, None
        if not reference or is_pushed_request_uri(reference):
            return "", None
        document = await self._fetcher.fetch(reference)
        if document:
            return document, None
        return "", RequestObjectError(
            error="invalid_request_uri",
            error_description="request_uri injoignable ou refusée (RFC 9101 §5.2)",
        )


def _claims(
    document: str, allowed: tuple[str, ...]
) -> tuple[dict[str, str], RequestObjectError | None]:
    """Décode un JWT compact non signé et en extrait les claims de demande."""
    segments = document.split(".")
    if len(segments) not in (2, 3):
        return {}, _malformed("JWT compact attendu (trois segments séparés par un point)")
    if len(segments) == 3 and segments[2]:
        return {}, _malformed("alg=none ne porte aucune signature (JWA RFC 7519 §6)")
    header = _decode_segment(segments[0])
    payload = _decode_segment(segments[1])
    if header is None or payload is None:
        return {}, _malformed("en-tête ou claims illisibles (base64url JSON attendu)")
    algorithm = header.get("alg", JWTAlgorithm.NONE.value)
    if algorithm not in allowed:
        return {}, RequestObjectError(
            error="invalid_request_object",
            error_description=f"algorithme de request object non supporté : {algorithm!r}",
        )
    return {name: _stringify(value) for name, value in payload.items()}, None


def _malformed(reason: str) -> RequestObjectError:
    """Refus standard d'un request object illisible (RFC 9101 §6.1)."""
    return RequestObjectError(
        error="invalid_request_object",
        error_description=f"request object invalide : {reason}",
    )


def _decode_segment(segment: str) -> dict[str, object] | None:
    """Décode un segment base64url en objet JSON ; ``None`` si illisible."""
    try:
        padded = segment + "=" * (-len(segment) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    return {str(name): item for name, item in value.items()}


def _stringify(value: object) -> str:
    """Ramène un claim JSON à sa forme de paramètre d'URL (``true``, JSON compact)."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _merge(params: Mapping[str, str], claims: dict[str, str]) -> dict[str, str]:
    """Compose les paramètres : les claims du jeton priment (OIDC Core 1.0 §6.1)."""
    merged = {name: value for name, value in params.items() if name not in _EMBEDDED}
    merged.update({name: value for name, value in claims.items() if name not in _EMBEDDED})
    return merged
