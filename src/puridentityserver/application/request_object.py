"""Request objects (RFC 9101 §5) : ``request`` par valeur, ``request_uri`` par référence.

L'OP accepte les request objects **non signés** (``alg=none``) pour les
clients standards : c'est la condition de saut ``skipTestIfNoneSupported``
des modules ``oidcc-unsigned-request-object-…``, ``oidcc-request-uri-unsigned-…``
et ``oidcc-ensure-request-object-with-redirect-uri`` (issue #76). Les claims
du jeton priment sur les paramètres de requête (OIDC Core 1.0 §6.1) : c'est
ce qui rend valide la ``redirect_uri`` portée par le request object quand la
query en porte une non enregistrée.

Les clients standards peuvent aussi présenter un request object **signé
RS256** (OIDC Core 1.0 §10.1/§10.3 ; le profil « dynamic » de la suite de
certification l'exige — module ``oidcc-request-uri-signed-rs256``, issue
#188) : la signature est vérifiée contre leurs JWKS enregistrés (``jwks``
embarqués ou ``jwks_uri``) par le port ``SignedRequestObjectVerifier``, avec
les claims ``iss`` (client_id) et ``aud`` (issuer) exigés — ``exp``/``nbf``
sont contrôlés par la vérification s'ils sont présents (RFC 9101 §6.1), sans
les fenêtres FAPI/CIBA. Sans clé vérifiable (client inconnu, aucun JWKS),
le JAR est refusé ``invalid_request_object``.

Les clients marqués ``fapi_enabled`` (FAPI 1.0 Advanced Final) suivent au
contraire le profil signé : le request object est **obligatoire**, sa
signature doit être ``PS256``/``ES256`` (FAPI1-ADV-5.2.2-1), il doit porter
``iss``/``aud``/``exp``/``nbf``/``scope``/``nonce``/``redirect_uri`` dans
les bornes des 60 minutes (FAPI1-ADV-5.2.2-13 à -17), et seuls **ses**
claims sont retenus — les paramètres du transport sont ignorés, hormis les
clés d'authentification (FAPI1-ADV-5.2.3-8, ``state`` hors request object
ignoré).

Une référence ``urn:ietf:params:oauth:request_uri:…`` est l'URN opaque d'une
demande poussée (RFC 9126 §6.2) : elle reste du ressort de la résolution PAR
et n'est jamais récupérée sur le réseau.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass

from puridentityserver.domain.authorization import PUSHED_REQUEST_URI_PREFIX, Client
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.request_object import (
    RequestObjectFetcher,
    SignedRequestObjectVerifier,
)
from puridentityserver.interfaces.repositories.readers import ClientReader

#: Seul ``alg=none`` est lu **sans vérification de signature** pour les
#: clients standards (JWA RFC 7519 §6) : c'est l'algorithme que la suite de
#: certification annonce pour rejouer les modules ``request`` non FAPI.
REQUEST_OBJECT_SIGNING_ALGORITHMS: tuple[str, ...] = (JWTAlgorithm.NONE.value,)

#: Algorithmes de request object admis pour un client **standard** présentant
#: un JAR signé (OIDC Core 1.0 §10.1/§10.3 — RS256 recommandé, exigé par le
#: profil « dynamic » de la suite de certification, module
#: ``oidcc-request-uri-signed-rs256``) : la signature est vérifiée contre le
#: JWKS du client. ``none`` en est exclu — il emprunte le port non vérifié
#: ``REQUEST_OBJECT_SIGNING_ALGORITHMS``.
STANDARD_SIGNED_REQUEST_OBJECT_ALGORITHMS: tuple[str, ...] = (JWTAlgorithm.RS256.value,)

#: Claims exigés d'un request object signé par un client standard : ``iss``
#: (client_id) et ``aud`` (issuer). ``exp``/``nbf`` sont validés par la
#: vérification de signature s'ils sont présents (RFC 9101 §6.1) mais non
#: exigés — le module ``oidcc-request-uri-signed-rs256`` n'en émet pas.
STANDARD_SIGNED_REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "aud")

#: Algorithmes de request object publiés au discovery : ``none`` et ``RS256``
#: pour les clients standards (le profil « dynamic » exige la présence de
#: ``RS256`` — ``CheckDiscEndpointRequestObjectSigningAlgValuesSupported-
#: ContainsRS256``), ``PS256``/``ES256`` pour le profil FAPI 1.0 Advanced
#: (FAPI1-ADV-5.2.2-1 — au moins un des deux exigé par la suite). Le port
#: ``none`` n'en vérifie jamais la signature (aucun segment de signature
#: admis) ; ``RS256`` est vérifié contre le JWKS du client.
PUBLISHED_REQUEST_OBJECT_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.NONE.value,
    JWTAlgorithm.RS256.value,
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.ES256.value,
)

#: Algorithmes de signature exigés pour un request object FAPI 1.0
#: Advanced Final (FAPI1-ADV-5.2.2-1) : ``alg=none`` et ``RS256`` refusés.
FAPI_REQUEST_OBJECT_SIGNING_ALGORITHMS: tuple[str, ...] = (
    JWTAlgorithm.PS256.value,
    JWTAlgorithm.ES256.value,
)

#: Claims obligatoires d'un request object FAPI 1.0 Advanced Final
#: (FAPI1-ADV-5.2.2-13 à -18 ; ``iss``/``aud`` sont en plus contrôlés par
#: la vérification de signature PyJWT — ``aud`` doit contenir l'issuer).
FAPI_REQUIRED_CLAIMS: tuple[str, ...] = (
    "iss",
    "aud",
    "exp",
    "nbf",
    "scope",
    "nonce",
    "redirect_uri",
)

#: Claims exigés d'un request object présenté par un client fédéré
#: (OpenID Federation 1.1 §12.1.1.1) : ``exp`` et ``jti`` y sont
#: **obligatoires** — contrairement aux clients standards, dont le module
#: ``oidcc-request-uri-signed-rs256`` n'émet ni l'un ni l'autre. Le claim
#: ``sub`` est interdit dans le même § (il nommerait l'utilisateur, que le
#: RP ne connaît pas à ce stade).
FEDERATED_SIGNED_REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "aud", "exp", "jti")

#: Namespace anti-replay des request objects fédérés (§12.1.1.1) : distinct
#: du namespace CIBA pour que les deux familles ne se croisent pas dans le
#: store d'empreintes partagé. L'empreinte de session navigateur s'y
#: ajoute (``-`` si anonyme) : la re-présentation du même request object
#: après ``/login`` — parcours normal d'un OP — porte alors le namespace
#: de la session créée, tandis qu'une re-présentation anonyme reste un
#: replay refusé.
FEDERATED_JTI_NAMESPACE = "federation:"

#: Paramètres du transport : ils n'existent que dans la query/form, jamais dans le jeton.
_EMBEDDED = frozenset(("request", "request_uri"))

#: Clés du transport conservées pour un client FAPI : authentification du
#: push (RFC 9126 §2.1) et ``client_id`` dupliqué exigé par RFC 6749 §3.1
#: en dehors du request object — tout le reste n'existe qu'à l'intérieur.
_FAPI_TRANSPORT_KEYS = frozenset(
    ("client_id", "client_secret", "client_assertion", "client_assertion_type")
)


@dataclass(frozen=True, slots=True)
class RequestObjectError:
    """Refus de traiter le request object (RFC 6749 §3.1.1, RFC 9101 §4).

    ``state`` rétablit au mieux la valeur portée par le jeton refusé : elle
    doit être réaffichée dans la réponse d'erreur (RFC 6749 §4.1.2.1,
    §4.2.2.1) — lecture seule du payload, sans rapport de confiance.
    """

    error: str
    error_description: str
    state: str = ""


@dataclass(frozen=True, slots=True)
class RequestObjectConfig:
    """Algorithmes de request object et issuer du profil signé.

    ``signing_algorithms`` borne la lecture des request objects non signés
    (``alg=none``) ; ``issuer`` est la valeur d'``aud`` exigée pour la
    signature FAPI (obligatoire dès qu'un client ``fapi_enabled`` est
    servi — vérification inactive sans lui).
    """

    signing_algorithms: tuple[str, ...] = REQUEST_OBJECT_SIGNING_ALGORITHMS
    issuer: str = ""


def is_pushed_request_uri(reference: str) -> bool:
    """True si ``reference`` est l'URN opaque d'une demande poussée (RFC 9126 §6.2)."""
    return reference.startswith(PUSHED_REQUEST_URI_PREFIX)


class RequestObjectResolver:
    """Incorpore le request object aux paramètres de ``/authorize`` et de ``/par``."""

    def __init__(
        self,
        config: RequestObjectConfig,
        fetcher: RequestObjectFetcher,
        *,
        clients: ClientReader | None = None,
        signed: SignedRequestObjectVerifier | None = None,
    ) -> None:
        """Injection de la configuration, du port de lecture et de la vérification.

        ``clients`` résout le client émetteur (profil FAPI obligatoire, ou
        vérification d'un JAR RS256 standard — issue #188) ; ``signed``
        vérifie alors la signature contre ses JWKS. Sans ``issuer``, la
        vérification de signature est inactive (``aud`` non contrôlable).
        """
        self._config = config
        self._fetcher = fetcher
        self._clients = clients
        self._signed = signed

    async def resolve(
        self, params: Mapping[str, str], *, session_scope: str = ""
    ) -> dict[str, str] | RequestObjectError:
        """Retourne les paramètres complétés par le request object, ou son refus.

        Sans ``request`` ni ``request_uri``, les paramètres sont renvoyés
        tels quels — sauf pour un client FAPI, dont le request object est
        obligatoire (FAPI1-ADV-5.2.2-1). L'appel peut donc être placé en
        tête du traitement d'une demande non poussée comme d'un push PAR.
        ``session_scope`` (empreinte de la session navigateur, ``""`` si
        anonyme) cloisonne l'anti-replay ``jti`` du profil fédéré par
        session : la re-présentation du même request object après
        authentification — retour de ``/login`` vers ``/authorize``, parcours
        normal de n'importe quel OP — s'inscrit alors dans le namespace de
        la session créée, tandis qu'une re-présentation anonyme reste un
        replay refusé (§12.1.1.1).
        """
        document, error = await self._document(params)
        if error is not None:
            return _with_state(error, document or params.get("request", ""))
        if document:
            mismatch = _client_id_mismatch(params, document)
            if mismatch is not None:
                return _with_state(mismatch, document)
        client = await self._find_client(params.get("client_id", ""))
        if not document:
            if client is not None and client.fapi_enabled:
                return _with_state(
                    RequestObjectError(
                        error="invalid_request",
                        error_description="request object obligatoire pour un client "
                        "FAPI1 (FAPI1-ADV-5.2.2-1)",
                    ),
                    "",
                )
            return dict(params)
        if client is None:
            client = await self._find_client(_unverified_iss(document))
        if client is not None and client.fapi_enabled:
            resolved = await self._resolve_fapi(params, document, client)
            if isinstance(resolved, RequestObjectError):
                return _with_state(resolved, document)
            return resolved
        claims, error = await self._resolve_standard(document, client, session_scope)
        if error is not None:
            return _with_state(error, document)
        return _merge(params, claims)

    async def _resolve_standard(
        self, document: str, client: Client | None, session_scope: str = ""
    ) -> tuple[dict[str, str], RequestObjectError | None]:
        """Traite le request object d'un client standard : non signé ou RS256.

        ``alg=none`` est lu sans vérification (port configuré) ; un JAR
        ``RS256`` est vérifié contre le JWKS du client (embarqué ou
        ``jwks_uri``), avec les claims ``iss``/``aud`` exigés (OIDC Core
        1.0 §10.1/§10.3). Pour un client fédéré (``Client.federated``), le
        profil OpenID Federation 1.1 §12.1.1.1 s'ajoute : ``exp`` et
        ``jti`` sont exigés avec anti-replay, ``sub`` est interdit — le
        ``jti`` est scopé par ``session_scope`` (reprise post-login acceptée,
        replay anonyme refusé, cf. :meth:`resolve`). Refus
        (``invalid_request_object``) si le client est inconnu, si la
        vérification n'est pas configurée, ou si la signature et les
        claims échouent.
        """
        algorithm = _header_algorithm(document)
        if algorithm == "" or algorithm in self._config.signing_algorithms:
            return _claims(document, self._config.signing_algorithms)
        if algorithm not in STANDARD_SIGNED_REQUEST_OBJECT_ALGORITHMS:
            return {}, RequestObjectError(
                error="invalid_request_object",
                error_description=f"algorithme de request object non supporté : {algorithm!r}",
            )
        if client is None:
            return {}, _malformed(
                "client inconnu : la signature du request object n'est pas vérifiable"
            )
        if self._signed is None or not self._config.issuer:
            return {}, RequestObjectError(
                error="invalid_request",
                error_description="vérification du request object signé non configurée",
            )
        federated = client.federated
        result = await self._signed.verify(
            token=document,
            client=client,
            issuer=self._config.issuer,
            allowed_algorithms=STANDARD_SIGNED_REQUEST_OBJECT_ALGORITHMS,
            required_claims=(
                FEDERATED_SIGNED_REQUIRED_CLAIMS if federated else STANDARD_SIGNED_REQUIRED_CLAIMS
            ),
            enforce_jti=federated,
            jti_namespace=FEDERATED_JTI_NAMESPACE + (session_scope or "-"),
        )
        if result.claims is None:
            return {}, RequestObjectError(
                error="invalid_request_object",
                error_description=result.reason,
            )
        if federated and "sub" in result.claims:
            return {}, RequestObjectError(
                error="invalid_request_object",
                error_description=(
                    "claim 'sub' interdit dans un request object de client fédéré "
                    "(OpenID Federation 1.1 §12.1.1.1)"
                ),
            )
        return {name: _stringify(value) for name, value in result.claims.items()}, None

    async def _resolve_fapi(
        self, params: Mapping[str, str], document: str, client: Client
    ) -> dict[str, str] | RequestObjectError:
        """Vérifie le request object signé FAPI et n'en retient que ses claims.

        Refus (``invalid_request_object``) si la signature, les claims
        obligatoires ou les bornes temporelles échouent
        (FAPI1-ADV-5.2.3-8).
        """
        if self._signed is None or self._clients is None or not self._config.issuer:
            return RequestObjectError(
                error="invalid_request",
                error_description="vérification du request object FAPI non configurée",
            )
        result = await self._signed.verify(
            token=document,
            client=client,
            issuer=self._config.issuer,
            allowed_algorithms=FAPI_REQUEST_OBJECT_SIGNING_ALGORITHMS,
            required_claims=FAPI_REQUIRED_CLAIMS,
            enforce_jti=False,
        )
        if result.claims is None:
            return RequestObjectError(
                error="invalid_request_object",
                error_description=result.reason,
            )
        for forbidden in ("request", "request_uri"):
            if forbidden in result.claims:
                return RequestObjectError(
                    error="invalid_request_object",
                    error_description=(
                        f"claim {forbidden!r} interdit dans un request object "
                        "(RFC 9101 §4, PAR-2.1)"
                    ),
                )
        return _merge_fapi(params, result.claims)

    async def _find_client(self, client_id: str) -> Client | None:
        """Charge le client par son identifiant ; ``None`` si absent ou inconnu."""
        if not client_id or self._clients is None:
            return None
        return await self._clients.find_by_id(client_id)

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


def _header_algorithm(document: str) -> str:
    """Retourne le claim ``alg`` de l'en-tête, ``""`` si le document est illisible."""
    segments = document.split(".")
    if len(segments) not in (2, 3):
        return ""
    header = _decode_segment(segments[0])
    if header is None:
        return ""
    return str(header.get("alg", JWTAlgorithm.NONE.value))


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


def _merge_fapi(params: Mapping[str, str], claims: dict[str, object]) -> dict[str, str]:
    """Ne retient que les claims du request object FAPI (FAPI1-ADV-5.2.3-8).

    Les paramètres du transport sont ignorés — y compris un ``state`` ou un
    ``nonce`` passés à l'extérieur : seul ce qui est signé dans le request
    object fait foi. Seules les clés d'authentification du push et le
    ``client_id`` dupliqué (RFC 6749 §3.1) survivent à la purge.
    """
    merged = {name: value for name, value in params.items() if name in _FAPI_TRANSPORT_KEYS}
    merged.update(
        {name: _stringify(value) for name, value in claims.items() if name not in _EMBEDDED}
    )
    return merged


def _client_id_mismatch(params: Mapping[str, str], document: str) -> RequestObjectError | None:
    """Refuse un ``client_id`` de transport différent de celui du request object.

    OIDC Core 1.0 §6.1 : ``client_id`` (et ``response_type``) de la query
    doivent correspondre aux valeurs du request object quand il en porte —
    sans quoi la demande est ``invalid_request``. Le contrôle porte sur le
    payload non vérifié (lecture seule) : un document illisible emprunte le
    refus dédié ``invalid_request_object``. Module federation
    ``invalid-client-id-in-query-parameters`` (OIDFED §12.1.1.1).
    """
    transport = params.get("client_id", "")
    if not transport:
        return None
    embedded = _unverified_claim(document, "client_id") or _unverified_iss(document)
    if not embedded or embedded == transport:
        return None
    return RequestObjectError(
        error="invalid_request",
        error_description=(
            "client_id de la requête différent de celui du request object (OIDC Core 1.0 §6.1)"
        ),
    )


def _unverified_iss(document: str) -> str:
    """Retourne le claim ``iss`` non vérifié du document JWT, ``""`` s'il est illisible.

    Sert à identifier le client à partir du request object quand le
    ``client_id`` du transport est absent, avant toute vérification de
    signature (lecture seule du payload encodé).
    """
    return _unverified_claim(document, "iss")


def _with_state(error: RequestObjectError, document: str) -> RequestObjectError:
    """Rattache au refus le ``state`` lisible dans le jeton, s'il y en a un.

    L'écho du ``state`` dans la redirection d'erreur (RFC 6749 §4.1.2.1) ne
    fait porter aucune décision à ce claim non vérifié : il est renvoyé au
    seul client qui l'a émis, vers sa ``redirect_uri`` enregistrée.
    """
    state = _unverified_claim(document, "state")
    if not state or state == error.state:
        return error
    return RequestObjectError(
        error=error.error,
        error_description=error.error_description,
        state=state,
    )


def _unverified_claim(document: str, name: str) -> str:
    """Retourne un claim string non vérifié du payload JWT, ``""`` s'il est absent."""
    segments = document.split(".")
    if len(segments) not in (2, 3):
        return ""
    payload = _decode_segment(segments[1])
    if payload is None:
        return ""
    value = payload.get(name)
    return value if isinstance(value, str) else ""
