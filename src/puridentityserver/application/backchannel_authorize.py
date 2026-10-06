"""Cas d'utilisation : Backchannel Authentication Endpoint (OIDC CIBA 1.0 §7).

Le client appelle ``POST /bc-authorize`` avec un — et un seul — hint
(``login_hint``, ``login_hint_token`` ou ``id_token_hint``). Le hint est
validé puis résolu vers l'utilisateur cible (``subject``) : la demande est
persistée (empreinte SHA-256 de l'``auth_req_id``) et le client en reçoit
l'acquittement ``{auth_req_id, expires_in, interval}`` (§7.3). Le résultat
est ensuite recueilli via ``/token`` avec le grant
``urn:openid:params:grant-type:ciba`` (modes ``poll`` / ``ping``).

Le paramètre ``request`` (request object signé — JAR, RFC 9101) est
vérifié derrière le port ``SignedRequestObjectVerifier`` : signature contre
les JWKS du client nommé par ``iss``, claims temporels bornés et ``jti``
anti-replay (§7.1.1). Sa présence est **obligatoire** pour un client
enregistré avec ``backchannel_authentication_request_signing_alg`` — les
autres clients conservent le chemin non signé. ``request_uri`` reste
refusé. Tout échec du request object est rendu ``invalid_request`` (§13).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any

from puridentityserver.application.client_auth import (
    CLIENT_UNKNOWN_ERROR,
    authenticate_client,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import (
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationStatus,
    Client,
    ClientCertificate,
    Scope,
)
from puridentityserver.domain.jwks import CIBA_REQUEST_SIGNING_ALGORITHMS
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.backchannel import CibaPingNotifier
from puridentityserver.interfaces.domain.client_assertions import ClientAssertionVerifier
from puridentityserver.interfaces.domain.request_object import SignedRequestObjectVerifier
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.backchannel_authentication_repository import (
    BackchannelAuthenticationRepository,
)
from puridentityserver.interfaces.repositories.readers import ClientReader, UserReader

#: Longueur maximale du ``binding_message`` persisté (message d'inter-verrouillage court).
MAX_BINDING_MESSAGE_LENGTH = 512

#: Syntaxe ``token68`` du bearer ``client_notification_token`` (RFC 6750 §2.1).
_NOTIFICATION_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9\-._~+/]+=*\Z")

#: Claims pouvant porter l'identité d'un utilisateur dans un hint (CIBA §7.1).
_HINT_IDENTITY_CLAIMS = ("sub", "email", "preferred_username", "phone_number")

#: Paramètres de demande que les claims du request object peuvent porter et
#: faire primer sur le corps form (RFC 9101 §4, OIDC Core 1.0 §6.1).
_REQUEST_CLAIM_PARAMETERS = (
    "scope",
    "login_hint",
    "login_hint_token",
    "id_token_hint",
    "binding_message",
    "acr_values",
    "client_notification_token",
    "requested_expiry",
)


@dataclass(frozen=True, slots=True)
class BackchannelAuthenticationConfig:
    """Paramètres du backchannel authentication endpoint (CIBA §7).

    ``token_endpoint`` et ``bc_authorize_endpoint`` complètent l'issuer
    comme valeurs d'``aud`` admises des ``client_assertion`` (§7.1).
    ``request_signing_algorithms`` liste les algorithmes de ``request``
    signé admis pour un client sans algorithme enregistré (publiés au
    discovery sous ``backchannel_authentication_request_signing_alg_values_supported``).
    """

    issuer: str
    base_url: str = ""
    ttl_seconds: int = 600
    interval_seconds: int = 5
    token_endpoint: str = ""
    bc_authorize_endpoint: str = ""
    request_signing_algorithms: tuple[str, ...] = CIBA_REQUEST_SIGNING_ALGORITHMS


@dataclass(slots=True)
class BackchannelAuthenticationParams:
    """Paramètres fournis par le client à ``/bc-authorize`` (CIBA §7.1)."""

    client_id: str
    scope: str = ""
    login_hint: str = ""
    login_hint_token: str = ""
    id_token_hint: str = ""
    binding_message: str = ""
    acr_values: str = ""
    client_notification_token: str = ""
    requested_expiry: str = ""
    client_secret: str = ""
    client_assertion_type: str = ""
    client_assertion: str = ""
    request: str = ""
    request_uri: str = ""
    tls_certificate: ClientCertificate | None = None


@dataclass(frozen=True, slots=True)
class AuthenticationAck:
    """Acquittement réussi de ``/bc-authorize`` (CIBA §7.3)."""

    auth_req_id: str
    expires_in: int
    interval: int


@dataclass(frozen=True, slots=True)
class BackchannelAuthenticationError:
    """Erreur du backchannel authentication endpoint (CIBA §13).

    ``status_code`` porte le code HTTP exigé par la spécification :
    401 pour ``invalid_client``, 400 pour les autres erreurs de requête.
    """

    error: str
    error_description: str = ""
    status_code: int = 400


class BackchannelAuthenticationUseCase:
    """Valide la demande CIBA, résout le hint et persiste l'``auth_req_id``."""

    def __init__(
        self,
        config: BackchannelAuthenticationConfig,
        client_repository: ClientReader,
        users: UserReader,
        requests: BackchannelAuthenticationRepository,
        scope_registry: ScopeRegistry | None = None,
        *,
        client_assertions: ClientAssertionVerifier | None = None,
        token_manager: TokenManager | None = None,
        request_objects: SignedRequestObjectVerifier | None = None,
    ) -> None:
        """Injection de la configuration, des repositories et des vérificateurs.

        ``client_assertions`` décode les ``login_hint_token`` signés par le
        client, vérifie les ``client_assertion`` d'authentification et
        déduit le ``client_id`` de leur ``iss`` quand le corps form n'en
        porte pas ; ``token_manager`` valide la signature serveur des
        ``id_token_hint`` ; ``request_objects`` vérifie les ``request``
        signés (JWKS du client, bornes temporelles, ``jti`` anti-replay).
        Sans injection, les hints ou demandes signés concernés sont refusés
        (leur validité ne peut être établie).
        """
        self._config = config
        self._clients = client_repository
        self._users = users
        self._requests = requests
        self._scope_registry = scope_registry
        self._client_assertions = client_assertions
        self._token_manager = token_manager
        self._request_objects = request_objects

    async def execute(
        self, params: BackchannelAuthenticationParams
    ) -> AuthenticationAck | BackchannelAuthenticationError:
        """Authentifie le client, valide la demande et retourne l'acquittement."""
        client = await self._authenticate_client(params)
        if isinstance(client, BackchannelAuthenticationError):
            return client
        effective, error = await self._apply_request_object(client, params)
        if error is not None:
            return error
        return await self._accept(client, effective)

    async def _authenticate_client(
        self, params: BackchannelAuthenticationParams
    ) -> Client | BackchannelAuthenticationError:
        """Charge le client puis l'authentifie selon sa méthode déclarée (§7.2)."""
        client_id = params.client_id or self._deduced_client_id(params)
        client = await self._clients.find_by_id(client_id)
        if client is None or not client.is_active:
            return BackchannelAuthenticationError(
                "invalid_client", CLIENT_UNKNOWN_ERROR, status_code=401
            )
        detail = await authenticate_client(
            client,
            client_secret=params.client_secret,
            assertions=self._client_assertions,
            assertion_type=params.client_assertion_type,
            assertion=params.client_assertion,
            assertion_audience=self._assertion_audiences(),
            tls_certificate=params.tls_certificate,
        )
        if detail is not None:
            return BackchannelAuthenticationError("invalid_client", detail, status_code=401)
        return client

    def _deduced_client_id(self, params: BackchannelAuthenticationParams) -> str:
        """Déduit le ``client_id`` absent du corps form (formulaire private_key_jwt).

        Une demande authentifiée par assertion ne porte pas de ``client_id``
        explicite : il est lu dans l'``iss`` de l'assertion, puis dans
        l'``iss`` du request object — la signature reste vérifiée ensuite.
        """
        if params.client_assertion and self._client_assertions is not None:
            issuer = self._client_assertions.issuer_of(params.client_assertion)
            if issuer:
                return issuer
        if params.request and self._request_objects is not None:
            return self._request_objects.issuer_of(params.request)
        return ""

    async def _apply_request_object(
        self, client: Client, params: BackchannelAuthenticationParams
    ) -> tuple[BackchannelAuthenticationParams, BackchannelAuthenticationError | None]:
        """Contrôle le ``request`` (signé ou exigé) et en fusionne les claims (§7.1.1).

        Un client enregistré avec ``backchannel_authentication_request_signing_alg``
        doit présenter un ``request`` signé avec cet algorithme (FAPI-CIBA ¶6) ;
        pour les autres, ``request`` reste facultatif mais vérifié s'il est
        présent. Les claims du jeton priment sur le corps form (RFC 9101 §4).
        """
        if params.request_uri:
            return params, BackchannelAuthenticationError(
                "invalid_request",
                "request_uri non supporté au backchannel authentication endpoint",
            )
        if not params.request:
            if client.backchannel_authentication_request_signing_alg:
                return params, BackchannelAuthenticationError(
                    "invalid_request",
                    "request object signé requis pour ce client (CIBA §7.1.1)",
                )
            return params, None
        if self._request_objects is None:
            return params, BackchannelAuthenticationError(
                "invalid_request", "vérification de request object indisponible"
            )
        issuer_client = await self._issuer_client(params.request)
        if isinstance(issuer_client, BackchannelAuthenticationError):
            return params, issuer_client
        result = await self._request_objects.verify(
            token=params.request,
            client=issuer_client,
            issuer=self._config.issuer,
            allowed_algorithms=self._request_signing_algorithms(client),
        )
        if result.claims is None:
            return params, BackchannelAuthenticationError("invalid_request", result.reason)
        if issuer_client.client_id != client.client_id:
            return params, BackchannelAuthenticationError(
                "invalid_client",
                "request object émis pour un autre client",
                status_code=401,
            )
        return _merge_request_claims(params, result.claims), None

    async def _issuer_client(self, token: str) -> Client | BackchannelAuthenticationError:
        """Charge le client nommé par le ``iss`` non vérifié du request object."""
        issuer = self._request_objects.issuer_of(token) if self._request_objects else ""
        if not issuer:
            return BackchannelAuthenticationError(
                "invalid_request", "request object illisible (claim iss absent)"
            )
        issuer_client = await self._clients.find_by_id(issuer)
        if issuer_client is None or not issuer_client.is_active:
            return BackchannelAuthenticationError(
                "invalid_request", "request object signé par un client inconnu"
            )
        return issuer_client

    def _request_signing_algorithms(self, client: Client) -> tuple[str, ...]:
        """Algorithmes admis : l'algorithme enregistré du client, sinon la liste publiée."""
        registered = client.backchannel_authentication_request_signing_alg
        return (registered,) if registered else self._config.request_signing_algorithms

    async def _accept(
        self, client: Client, params: BackchannelAuthenticationParams
    ) -> AuthenticationAck | BackchannelAuthenticationError:
        """Valide les paramètres, résout le hint et persiste la demande (§7.2)."""
        mode = client.backchannel_token_delivery_mode
        if mode not in ("poll", "ping"):
            return BackchannelAuthenticationError(
                "unauthorized_client",
                "Ce client n'est pas enregistré pour CIBA "
                "(backchannel_token_delivery_mode poll ou ping attendu)",
            )
        scopes = await self._validate_scopes(client, params.scope)
        if isinstance(scopes, BackchannelAuthenticationError):
            return scopes
        subject = await self._resolve_subject(client, params)
        if isinstance(subject, BackchannelAuthenticationError):
            return subject
        notification_token = self._validate_notification_token(
            mode, params.client_notification_token
        )
        if isinstance(notification_token, BackchannelAuthenticationError):
            return notification_token
        if len(params.binding_message) > MAX_BINDING_MESSAGE_LENGTH:
            return BackchannelAuthenticationError(
                "invalid_binding_message",
                f"binding_message trop long (max {MAX_BINDING_MESSAGE_LENGTH} caractères)",
            )
        ttl = self._resolve_ttl(params.requested_expiry)
        if isinstance(ttl, BackchannelAuthenticationError):
            return ttl

        auth_req_id = token_urlsafe(32)
        now = datetime.now(timezone.utc)
        await self._requests.save(
            BackchannelAuthenticationRequest(
                auth_req_id_hash=token_hash(auth_req_id),
                client_id=client.client_id,
                scopes=scopes,
                subject=subject,
                delivery_mode=mode,
                client_notification_token=notification_token,
                client_notification_endpoint=client.backchannel_client_notification_endpoint,
                binding_message=params.binding_message,
                acr=params.acr_values.split()[0] if params.acr_values.split() else "",
                interval=self._config.interval_seconds,
                expires_at=now + timedelta(seconds=ttl),
            )
        )
        return AuthenticationAck(
            auth_req_id=auth_req_id,
            expires_in=ttl,
            interval=self._config.interval_seconds,
        )

    async def _validate_scopes(
        self, client: Client, scope: str
    ) -> frozenset[Scope] | BackchannelAuthenticationError:
        """Portée de la demande : ``scope`` requis portant ``openid`` (CIBA §7.1)."""
        if not scope:
            return BackchannelAuthenticationError("invalid_request", "Paramètre scope manquant")
        requested = Scope.from_space_separated(scope)
        if Scope.OPENID not in requested:
            return BackchannelAuthenticationError(
                "invalid_scope", "Le scope openid est requis (CIBA §7.1)"
            )
        if requested - client.scopes:
            return BackchannelAuthenticationError(
                "invalid_scope", "Portée jamais enregistrée pour le client"
            )
        if self._scope_registry is not None:
            unknown = await self._scope_registry.unknown_scopes(requested)
            if unknown:
                return BackchannelAuthenticationError(
                    "invalid_scope",
                    "Scope(s) non enregistré(s) : " + ", ".join(unknown),
                )
        return requested

    async def _resolve_subject(
        self, client: Client, params: BackchannelAuthenticationParams
    ) -> str | BackchannelAuthenticationError:
        """Retient un — et un seul — hint et le résout vers un utilisateur (§7.2)."""
        hints = [
            (name, value)
            for name, value in (
                ("login_hint", params.login_hint),
                ("login_hint_token", params.login_hint_token),
                ("id_token_hint", params.id_token_hint),
            )
            if value
        ]
        if len(hints) != 1:
            return BackchannelAuthenticationError(
                "invalid_request",
                "La demande doit porter un (et un seul) hint : "
                "login_hint, login_hint_token ou id_token_hint",
            )
        name, value = hints[0]
        resolved: str | BackchannelAuthenticationError
        if name == "login_hint":
            resolved = await self._match_user(value)
        elif name == "login_hint_token":
            resolved = await self._subject_from_login_hint_token(client, value)
        else:
            resolved = await self._subject_from_id_token_hint(client, value)
        if isinstance(resolved, BackchannelAuthenticationError):
            return resolved
        if not resolved:
            return BackchannelAuthenticationError(
                "unknown_user_id",
                "Le hint ne correspond à aucun utilisateur connu",
            )
        return resolved

    async def _subject_from_login_hint_token(
        self, client: Client, token: str
    ) -> str | BackchannelAuthenticationError:
        """Déchiffre le hint signé par le client et en résout le sujet (§7.1.1)."""
        if self._client_assertions is None:
            return BackchannelAuthenticationError(
                "unknown_user_id", "Décodage de login_hint_token indisponible"
            )
        result = await self._client_assertions.decode_login_hint_token(token=token, client=client)
        if result.expired:
            return BackchannelAuthenticationError(
                "expired_login_hint_token", "login_hint_token expiré"
            )
        if result.claims is None:
            return BackchannelAuthenticationError(
                "unknown_user_id",
                "login_hint_token illisible ou non signé par le client",
            )
        return await self._subject_from_claims(result.claims)

    async def _subject_from_id_token_hint(
        self, client: Client, token: str
    ) -> str | BackchannelAuthenticationError:
        """Valide l'``id_token_hint`` (issuer, audience) et en résout le sujet (§7.1)."""
        if self._token_manager is None:
            return BackchannelAuthenticationError(
                "unknown_user_id", "Validation d'id_token_hint indisponible"
            )
        claims = await self._token_manager.validate_id_token(
            token=token, issuer=self._config.issuer, allow_expired=True
        )
        if claims is None:
            return BackchannelAuthenticationError("invalid_request", "id_token_hint invalide")
        if not _audience_holds(claims.get("aud"), client.client_id):
            return BackchannelAuthenticationError(
                "invalid_request", "id_token_hint émis pour un autre client"
            )
        subject_value = claims.get("sub")
        subject = await self._match_user(str(subject_value)) if subject_value else ""
        return subject

    async def _subject_from_claims(self, claims: dict[str, object]) -> str:
        """Résout le sujet porté par les claims d'un ``login_hint_token``."""
        for name in _HINT_IDENTITY_CLAIMS:
            value = claims.get(name)
            if isinstance(value, str) and value:
                subject = await self._match_user(value)
                if subject:
                    return subject
        return ""

    async def _match_user(self, value: str) -> str:
        """Retourne le ``subject`` identifié par ``value`` (subject, email…), ou vide."""
        user = await self._users.find_by_subject(value)
        if user is not None:
            return user.subject
        lowered = value.lower()
        for candidate in await self._users.find_all():
            for name in _HINT_IDENTITY_CLAIMS[1:]:
                claim = candidate.claims.get(name)
                if isinstance(claim, str) and claim.lower() == lowered:
                    return candidate.subject
        return ""

    def _validate_notification_token(
        self, mode: str, token: str
    ) -> str | BackchannelAuthenticationError:
        """Vérifie le bearer de notification exigé en mode ``ping`` (§7.1, §9)."""
        if mode == "poll":
            return ""
        if not token:
            return BackchannelAuthenticationError(
                "invalid_request",
                "client_notification_token requis (mode ping)",
            )
        if len(token) > 1024 or not _NOTIFICATION_TOKEN_PATTERN.fullmatch(token):
            return BackchannelAuthenticationError(
                "invalid_request",
                "client_notification_token invalide (RFC 6750 §2.1, 1024 caractères max)",
            )
        return token

    def _resolve_ttl(self, requested_expiry: str) -> int | BackchannelAuthenticationError:
        """Durée de vie de l'``auth_req_id`` : ``requested_expiry`` bornée au défaut (§7.1)."""
        if not requested_expiry:
            return self._config.ttl_seconds
        try:
            requested = int(requested_expiry)
        except ValueError:
            return BackchannelAuthenticationError(
                "invalid_request", "requested_expiry doit être un entier positif"
            )
        if requested <= 0:
            return BackchannelAuthenticationError(
                "invalid_request", "requested_expiry doit être un entier positif"
            )
        return min(requested, self._config.ttl_seconds)

    def _assertion_audiences(self) -> tuple[str, ...]:
        """Valeurs d'``aud`` admises des assertions au backchannel endpoint (§7.1)."""
        issuer = self._config.issuer.rstrip("/")
        token_endpoint = (self._config.token_endpoint or f"{issuer}/token").rstrip("/")
        bc_endpoint = (self._config.bc_authorize_endpoint or f"{issuer}/bc-authorize").rstrip("/")
        return (issuer, token_endpoint, bc_endpoint)


class CibaApprovalUseCase:
    """Applique la décision de l'utilisateur sur une demande CIBA (§9, §10.2).

    L'endpoint ``POST /ciba/approve`` n'est qu'un adaptateur : le cas
    d'utilisation bascule le statut (``PENDING`` → ``APPROVED``/``DENIED``)
    puis, en mode ``ping``, notifie le client au ``notification endpoint``
    avec son ``client_notification_token``. Une décision déjà rendue est
    idempotente (jamais de double notification).
    """

    def __init__(
        self,
        requests: BackchannelAuthenticationRepository,
        *,
        ping_notifier: CibaPingNotifier | None = None,
    ) -> None:
        """Injection du repository des demandes et du notificateur ping facultatif."""
        self._requests = requests
        self._ping_notifier = ping_notifier

    async def execute(self, auth_req_id: str, *, allow: bool) -> bool:
        """Autorise (``allow``) ou refuse la demande identifiée par ``auth_req_id``.

        Retourne ``False`` si l'``auth_req_id`` est inconnu (404 côté route),
        ``True`` sinon — y compris si la décision avait déjà été rendue.
        """
        if not auth_req_id:
            return False
        auth_req_id_hash = token_hash(auth_req_id)
        stored = await self._requests.find_by_auth_req_id_hash(auth_req_id_hash)
        if stored is None:
            return False
        if stored.status is not BackchannelAuthenticationStatus.PENDING:
            return True
        if allow:
            await self._requests.approve(auth_req_id_hash)
        else:
            await self._requests.deny(auth_req_id_hash)
        await self._notify_ping(stored, auth_req_id)
        return True

    async def _notify_ping(
        self, stored: BackchannelAuthenticationRequest, auth_req_id: str
    ) -> None:
        """Notifie le client en mode ``ping`` (CIBA §10.2), best effort."""
        if (
            self._ping_notifier is None
            or stored.delivery_mode != "ping"
            or not stored.client_notification_endpoint
            or not stored.client_notification_token
        ):
            return
        await self._ping_notifier.notify_ping(
            url=stored.client_notification_endpoint,
            client_notification_token=stored.client_notification_token,
            auth_req_id=auth_req_id,
        )


def _merge_request_claims(
    params: BackchannelAuthenticationParams, claims: dict[str, object]
) -> BackchannelAuthenticationParams:
    """Compose la demande : les claims du request object priment (RFC 9101 §4).

    Seuls les paramètres de demande connus sont repris ; l'authentification
    du client (secret, assertion, certificat) reste exclusivement portée par
    le corps form, jamais par le jeton.
    """
    overrides: dict[str, Any] = {}
    for name in _REQUEST_CLAIM_PARAMETERS:
        value = claims.get(name)
        if value is None:
            continue
        if isinstance(value, str):
            overrides[name] = value
        else:
            overrides[name] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return replace(params, request="", **overrides)  # NOSONAR(S5886) — replace préserve le type


def _audience_holds(audience: object, client_id: str) -> bool:
    """Vrai si ``client_id`` figure dans le claim ``aud`` (chaîne ou liste)."""
    if isinstance(audience, str):
        return audience == client_id
    if isinstance(audience, (list, tuple)):
        return client_id in audience
    return False
