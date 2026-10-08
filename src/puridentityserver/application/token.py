"""Cas d'utilisation : endpoint de jetons (RFC 6749, RFC 7636, RFC 7523, RFC 8628, CIBA).

Traite six grant types :

- ``authorization_code`` (RFC 6749 §4.1.3 + RFC 7636) : échange le code
  d'autorisation reçu sur ``/authorize`` ; le client confidentiel doit
  présenter son ``client_secret``, le client public son ``code_verifier``
  PKCE. Un code déjà consommé est refusé (``invalid_grant``) **et** révoque
  les jetons émis lors du premier échange (RFC 6749 §4.1.2).
- ``refresh_token`` (RFC 6749 §6) : renouvelle l'access token à partir
  d'un refresh token opaque. Le jeton est **rotatif** : chaque usage
  consomme l'ancien (rejeté s'il est réutilisé) et en émet un nouveau.
  Le scope demandé doit rester un sous-ensemble de celui accordé.
- ``client_credentials`` (RFC 6749 §4.4) : le client lui-même devient le
  ``subject`` du jeton (pas d'utilisateur final). Réservé aux clients
  confidentiels ; aucun ``id_token`` ni ``refresh_token`` n'est émis.
- ``urn:ietf:params:oauth:grant-type:jwt-bearer`` (RFC 7523 §2.1) : une
  assertion JWT signée par le client délègue un ``sub`` (l'utilisateur)
  au nom duquel les jetons sont émis — signature vérifiée (HMAC secret
  partagé ou clé publique enregistrée), ``aud`` = token endpoint.
- ``urn:ietf:params:oauth:grant-type:device_code`` (RFC 8628 §3.4) :
  poll du client après autorisation de l'appareil. Tant que l'utilisateur
  n'a pas validé, la réponse est ``authorization_pending`` (ou
  ``slow_down`` si le client pole trop vite) ; une fois approuvée, la
  session est consommée et l'access token (id/refresh selon les scopes)
  est émis pour le ``subject`` de l'utilisateur.
- ``urn:openid:params:grant-type:ciba`` (OIDC CIBA 1.0 §10.1) : poll du
  client sur sa demande d'authentification backchannel — mêmes états
  ``authorization_pending`` / ``slow_down`` / ``access_denied`` /
  ``expired_token`` (§11), ``acr`` repris dans l'``id_token``.

L'authentification du client suit sa ``token_endpoint_auth_method`` :
``client_secret_basic`` / ``client_secret_post`` (secret en clair),
``client_secret_jwt`` / ``private_key_jwt`` (assertion JWT, RFC 7523 §2.2)
portée par le port ``client_assertions``, ou ``tls_client_auth`` /
``self_signed_tls_client_auth`` (certificat mTLS, RFC 8705).

Les resource indicators (RFC 8707 §2-§3) sont acceptés sur tous les
grants : le support lié (code, refresh token, demande CIBA) fixe le
périmètre ``aud`` de l'access token — toute déclaration hors périmètre
vaut ``invalid_target``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.application.claims_request import (
    ClaimsRequest,
    parse_claims_parameter,
    requested_userinfo_payload,
    resolve_requested_claims,
)
from puridentityserver.application.client_auth import (
    CLIENT_UNKNOWN_ERROR,
    authenticate_client,
)
from puridentityserver.application.dpop import (
    DpopBinding,
    DpopGrantGuard,
    DpopGuardError,
)
from puridentityserver.application.id_token_encryption import encrypt_id_token_for_client
from puridentityserver.application.id_token_material import resolve_id_token_material
from puridentityserver.application.resource_indicators import (
    is_resource_uri,
    parse_resource_parameter,
    resource_audience,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import (
    CIBA_GRANT_TYPE,
    AuthorizationCode,
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationStatus,
    Client,
    ClientCertificate,
    ClientType,
    DeviceAuthorization,
    DeviceAuthorizationStatus,
    RefreshToken,
    Scope,
    TokenEndpointAuthMethod,
    der_certificate_hash,
    resolve_lifetime_seconds,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.interfaces.domain.client_assertions import (
    JWT_BEARER_GRANT_TYPE_URN,
    ClientAssertionVerifier,
)
from puridentityserver.interfaces.domain.secrets import SecretCipher
from puridentityserver.interfaces.domain.tokens import (
    IdTokenEncrypter,
    JWEUnavailableError,
    TokenManager,
)
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.backchannel_authentication_repository import (
    BackchannelAuthenticationRepository,
)
from puridentityserver.interfaces.repositories.device_authorization_repository import (
    DeviceAuthorizationRepository,
)
from puridentityserver.interfaces.repositories.readers import ClientReader
from puridentityserver.interfaces.repositories.refresh_token_repository import (
    RefreshTokenRepository,
)
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """Paramètres de l'endpoint de jetons."""

    issuer: str
    signing_algorithm: JWTAlgorithm = JWTAlgorithm.RS256
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 2592000
    token_endpoint: str = ""
    secret_cipher: SecretCipher | None = None
    id_token_encrypter: IdTokenEncrypter | None = None


@dataclass(slots=True)
class TokenRequest:
    """Paramètres fournis par le client à l'endpoint ``/token``.

    ``resource`` porte les resource indicators RFC 8707 §2 (URI absolues
    sans fragment, encodées en tableau ou en JSON compact) ; le support
    qui a produit les jetons (code, refresh token, demande CIBA) en fixe
    le périmètre — la requête ne peut que le reprendre ou le restreindre.
    """

    grant_type: str
    code: str = ""
    redirect_uri: str = ""
    client_id: str = ""
    client_secret: str = ""
    code_verifier: str = ""
    refresh_token: str = ""
    device_code: str = ""
    auth_req_id: str = ""
    scope: str = ""
    resource: str = ""
    client_assertion_type: str = ""
    client_assertion: str = ""
    assertion: str = ""
    tls_certificate: ClientCertificate | None = None
    dpop_proof: str = ""


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Réponse OAuth 2.0 du token endpoint (RFC 6749 §5.1)."""

    access_token: str
    id_token: str
    token_type: str = "Bearer"  # ruff: ignore[hardcoded-password-string]  (valeur standard OAuth, pas un secret)
    expires_in: int = 3600
    scope: str = ""
    refresh_token: str = ""


@dataclass(frozen=True, slots=True)
class TokenError:
    """Erreur du token endpoint (RFC 6749 §5.2)."""

    error: str
    error_description: str = ""


class TokenUseCase:
    """Valide l'échange (code, refresh, jwt-bearer) et émet les jetons signés.

    L'authentification du client suit sa ``token_endpoint_auth_method``
    (RFC 6749 §2.3, RFC 7523 §2.2, RFC 8705) ; le port ``TokenManager``
    signe ``id_token`` et ``access_token`` avec la première clé active de
    l'algorithme. La preuve ``DPoP`` du client (RFC 9449), quand elle est
    présente — ou exigée par ``require_dpop`` —, est validée par le guard
    injecté : l'access token est alors lié (``cnf.jkt``, ``token_type=DPoP``).
    """

    def __init__(
        self,
        config: TokenConfig,
        client_repository: ClientReader,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
        refresh_tokens: RefreshTokenRepository,
        device_codes: DeviceAuthorizationRepository | None = None,
        backchannel_auth: BackchannelAuthenticationRepository | None = None,
        scope_registry: ScopeRegistry | None = None,
        client_assertions: ClientAssertionVerifier | None = None,
        *,
        claims_provider: ClaimsProvider | None = None,
        revoked_tokens: RevokedTokenRepository | None = None,
        dpop: DpopGrantGuard | None = None,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons.

        ``claims_provider`` résout les valeurs du member ``id_token`` du
        paramètre ``claims`` (OIDC Core 1.0 §5.5) pour compléter l'id_token
        émis à l'échange du code ; sans injection, seul le payload standard
        est signé. ``revoked_tokens`` est le denylist sur lequel un code
        réutilisé place l'access token du premier échange (RFC 6749 §4.1.2) ;
        sans injection, la révocation est simplement ignorée. ``dpop``
        applique les règles DPoP (RFC 9449) : sans injection, aucun proof
        n'est traité et ``require_dpop`` n'est honoré que pour le rejet de
        la requête dépourvue d'en-tête ``DPoP``.
        """
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._refresh_tokens = refresh_tokens
        self._device_codes = device_codes
        self._backchannel_auth = backchannel_auth
        self._scope_registry = scope_registry
        self._client_assertions = client_assertions
        self._claims_provider = claims_provider
        self._revoked_tokens = revoked_tokens
        self._dpop = dpop

    async def execute(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Traite le grant type demandé et retourne les jetons ou une erreur."""
        self._deduce_client_id(request)
        if request.grant_type == "authorization_code":
            return await self._exchange_code(request)
        if request.grant_type == "refresh_token":
            return await self._refresh(request)
        if request.grant_type == "client_credentials":
            return await self._client_credentials(request)
        if request.grant_type == JWT_BEARER_GRANT_TYPE_URN:
            return await self._jwt_bearer(request)
        if request.grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return await self._device_code(request)
        if request.grant_type == CIBA_GRANT_TYPE:
            return await self._ciba(request)
        return self._error("unsupported_grant_type")

    def _deduce_client_id(self, request: TokenRequest) -> None:
        """Localise le client par l'``iss`` non vérifié de la ``client_assertion``.

        RFC 7523 §2.2 : le corps form peut omettre ``client_id`` quand
        l'appelant s'authentifie par assertion (formulaire de la suite
        ``CreateTokenEndpointRequestForAuthorizationCodeGrant``) —
        l'assertion seule porte l'identité, exactement comme au endpoint
        PAR. Aucune décision de sécurité sur cette valeur non vérifiée :
        ``_authenticate_client`` valide ensuite signature, ``iss``/``sub``,
        ``aud`` et ``exp`` avant tout échange.
        """
        if request.client_id or not request.client_assertion or self._client_assertions is None:
            return
        issuer = self._client_assertions.issuer_of(request.client_assertion)
        if issuer:
            request.client_id = issuer

    async def _exchange_code(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Échange un code d'autorisation à usage unique contre des jetons."""
        auth_code = await self._codes.find_by_code(request.code)
        if auth_code is None:
            return self._error("invalid_grant", "Code d'autorisation invalide ou déjà consommé")
        if auth_code.is_consumed:
            await self._revoke_issued_tokens(auth_code)
            return self._error("invalid_grant", "Code d'autorisation invalide ou déjà consommé")

        now = datetime.now(timezone.utc)
        if auth_code.expires_at < now:
            return self._error("invalid_grant", "Code d'autorisation expiré")

        client = await self._validate_code_exchange(auth_code, request)
        if isinstance(client, TokenError):
            return client

        binding = await self._evaluate_dpop(client, request, bound_jkt=auth_code.dpop_jkt)
        if isinstance(binding, TokenError):
            return binding

        resources = await self._effective_resources(request, auth_code.resource_uris)
        if isinstance(resources, TokenError):
            return resources

        await self._codes.consume(auth_code.code)

        refresh_token = ""
        if Scope.OFFLINE_ACCESS in auth_code.scopes:
            refresh_token = await self._issue_refresh_token(
                client,
                auth_code.subject,
                auth_code.scopes,
                now,
                dpop_jkt=binding.jkt if binding.bound else "",
                resources=resources,
            )
        issued = await self._issue_tokens(
            client,
            auth_code.subject,
            auth_code.scopes,
            nonce=auth_code.nonce,
            now=now,
            session_id=auth_code.session_id,
            auth_time=auth_code.auth_time,
            acr=auth_code.acr,
            claims=auth_code.claims,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=_tls_certificate_bound_hash(client, request),
        )
        if isinstance(issued, TokenError):
            return issued
        id_token, access_token, token_ttl = issued
        await self._record_issued_tokens(
            auth_code,
            access_token=access_token,
            access_token_ttl=token_ttl,
            refresh_token=refresh_token,
            now=now,
        )
        return self._success(
            id_token,
            access_token,
            token_ttl,
            auth_code.scopes,
            refresh_token,
            dpop_bound=binding.bound,
        )

    async def _validate_code_exchange(
        self, auth_code: AuthorizationCode, request: TokenRequest
    ) -> Client | TokenError:
        """Contrôle client, ``redirect_uri`` et PKCE avant d'échanger le code.

        RFC 6749 §4.1.3 : le code n'est consommé qu'une fois ces contrôles
        passés ; un rejet le laisse intact. Le code est lié au client qui a
        initié la demande — un autre client authentifié reçoit
        ``invalid_grant``, au même titre qu'un ``redirect_uri`` discordant.
        """
        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        if auth_code.redirect_uri != request.redirect_uri:
            return self._error("invalid_grant", "redirect_uri ne correspond pas")

        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated
        if auth_code.client_id != client.client_id:
            return self._error("invalid_grant", "Code d'autorisation émis pour un autre client")
        if client.client_type == ClientType.PUBLIC and not auth_code.code_challenge:
            return self._error("invalid_grant", "Les clients publics doivent utiliser PKCE")
        if auth_code.code_challenge and not self._verify_pkce(auth_code, request.code_verifier):
            return self._error("invalid_grant", "Échec de la vérification PKCE")
        return client

    async def _revoke_issued_tokens(self, auth_code: AuthorizationCode) -> None:
        """Révoque les jetons issus du premier échange d'un code réutilisé.

        RFC 6749 §4.1.2 : un code d'autorisation utilisé plus d'une fois doit
        être refusé et, « quand c'est possible », les jetons déjà émis à partir
        de ce code révoqués. L'access token part au denylist (``/userinfo`` et
        ``/introspect`` le refuseront, RFC 6750 §3.1) et le refresh token est
        consommé dans le store de rotation. Seules les empreintes SHA-256
        persistées sur le code sont manipulées, jamais le jeton en clair.
        """
        if auth_code.access_token_hash and self._revoked_tokens is not None:
            expires_at = auth_code.access_token_expires_at or auth_code.expires_at
            await self._revoked_tokens.save(
                RevokedToken(token_hash=auth_code.access_token_hash, expires_at=expires_at)
            )
        if auth_code.refresh_token_hash:
            await self._refresh_tokens.consume(auth_code.refresh_token_hash)

    async def _record_issued_tokens(
        self,
        auth_code: AuthorizationCode,
        *,
        access_token: str,
        access_token_ttl: int,
        refresh_token: str,
        now: datetime,
    ) -> None:
        """Consigne sur le code l'empreinte des jetons venant d'être émis.

        La persistance se fait **après** ``consume`` : le code reste marqué
        consommé (aucune réouverture d'usage) tout en portant les références
        que ``_revoke_issued_tokens`` lira si le code est rejoué.
        """
        await self._codes.save(
            replace(
                auth_code,
                is_consumed=True,
                access_token_hash=token_hash(access_token),
                access_token_expires_at=now + timedelta(seconds=access_token_ttl),
                refresh_token_hash=token_hash(refresh_token) if refresh_token else "",
            )
        )

    async def _refresh(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Renouvelle les jetons à partir d'un refresh token opque (rotation)."""
        if not request.refresh_token:
            return self._error("invalid_grant", "Paramètre refresh_token manquant")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        resolved = await self._resolve_refresh_grant(request)
        if isinstance(resolved, TokenError):
            return resolved
        stored, scopes = resolved

        now = datetime.now(timezone.utc)
        binding = await self._evaluate_dpop(client, request, bound_jkt=stored.dpop_jkt)
        if isinstance(binding, TokenError):
            return binding

        resources = await self._effective_resources(request, stored.resource_uris)
        if isinstance(resources, TokenError):
            return resources

        await self._refresh_tokens.consume(stored.token_hash)
        refresh_token = await self._issue_refresh_token(
            client,
            stored.subject,
            scopes,
            now,
            dpop_jkt=self._refresh_dpop_jkt(client, stored, binding),
            resources=resources,
        )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            scopes,
            nonce="",
            now=now,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=_tls_certificate_bound_hash(client, request),
        )
        if isinstance(issued, TokenError):
            return issued
        id_token, access_token, token_ttl = issued
        return self._success(
            id_token,
            access_token,
            token_ttl,
            scopes,
            refresh_token,
            dpop_bound=binding.bound,
        )

    async def _resolve_refresh_grant(
        self, request: TokenRequest
    ) -> tuple[RefreshToken, frozenset[Scope]] | TokenError:
        """Charge et contrôle le refresh token, puis réduit éventuellement sa portée.

        Le token doit appartenir au client, ne pas avoir été consommé
        (rotation, RFC 6749 §6) ni expirer ; ``scope`` ne peut que
        restreindre la portée initialement accordée (§6).
        """
        stored = await self._refresh_tokens.find_by_token_hash(token_hash(request.refresh_token))
        if stored is None or stored.client_id != request.client_id:
            return self._error("invalid_grant", "Refresh token invalide ou d'un autre client")
        if stored.is_consumed:
            return self._error("invalid_grant", "Refresh token déjà utilisé (rotation)")
        if stored.expires_at < datetime.now(timezone.utc):
            return self._error("invalid_grant", "Refresh token expiré")
        scopes = stored.scopes
        if request.scope:
            requested = Scope.from_space_separated(request.scope)
            if requested - stored.scopes:
                return self._error("invalid_scope", "Portée demandée jamais accordée au jeton")
            scopes = requested
        return stored, scopes

    async def _client_credentials(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Émet un access token au nom du client lui-même (RFC 6749 §4.4).

        Le client est à la fois présentateur et ``subject`` du jeton :
        aucun utilisateur final, donc ni ``id_token`` ni ``refresh_token``.
        Seuls les clients confidentiels (authentifiés selon leur
        ``token_endpoint_auth_method``) peuvent utiliser ce grant ; le
        scope demandé reste limité à celui enregistré pour le client.
        """
        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)
        if client.client_type != ClientType.CONFIDENTIAL:
            return self._error(
                "invalid_client", "Le grant client_credentials exige un client confidentiel"
            )
        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        scopes = await self._effective_scope(client, request.scope, default=client.scopes)
        if isinstance(scopes, TokenError):
            return scopes

        binding = await self._evaluate_dpop(client, request)
        if isinstance(binding, TokenError):
            return binding

        resources = await self._effective_resources(request, ())
        if isinstance(resources, TokenError):
            return resources

        now = datetime.now(timezone.utc)
        access_token, token_ttl = await self._issue_access_token(
            client,
            subject=client.client_id,
            scopes=scopes,
            now=now,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=_tls_certificate_bound_hash(client, request),
        )
        return self._success("", access_token, token_ttl, scopes, dpop_bound=binding.bound)

    async def _jwt_bearer(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Émet un access token au nom du sujet d'une assertion JWT (RFC 7523 §2.1).

        L'assertion est validée par :meth:`_jwt_bearer_subject` ; la
        portée, la preuve DPoP et les resources (RFC 8707) complètent
        ensuite le jeton émis pour le ``sub`` délégué.
        """
        resolved = await self._jwt_bearer_subject(request)
        if isinstance(resolved, TokenError):
            return resolved
        client, subject = resolved

        scopes = await self._effective_scope(client, request.scope, default=client.scopes)
        if isinstance(scopes, TokenError):
            return scopes

        binding = await self._evaluate_dpop(client, request)
        if isinstance(binding, TokenError):
            return binding

        resources = await self._effective_resources(request, ())
        if isinstance(resources, TokenError):
            return resources

        now = datetime.now(timezone.utc)
        access_token, token_ttl = await self._issue_access_token(
            client,
            subject=subject,
            scopes=scopes,
            now=now,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=_tls_certificate_bound_hash(client, request),
        )
        return self._success("", access_token, token_ttl, scopes, dpop_bound=binding.bound)

    async def _jwt_bearer_subject(self, request: TokenRequest) -> tuple[Client, str] | TokenError:
        """Localise le client et vérifie l'assertion JWT déléguée (RFC 7523 §2.1).

        L'assertion est signée par le client (HMAC secret partagé ou clé
        publique enregistrée), ``aud`` doit désigner le token endpoint et
        ``exp`` rester valide. Le ``sub`` vérifié devient le subject du
        jeton ; le client est identifié par ``client_id`` ou, à défaut,
        par le ``iss`` de l'assertion (claims pré-vérification réservés à
        la localisation du candidat, toute la suite étant validée).
        """
        if self._client_assertions is None:
            return self._error("unsupported_grant_type")
        if not request.assertion:
            return self._error("invalid_grant", "Paramètre assertion manquant")

        preliminary = _unverified_assertion_claims(request.assertion)
        if preliminary is None:
            return self._error("invalid_grant", "Assertion jwt-bearer malformée")
        client_id = request.client_id or preliminary.get("iss")
        if not isinstance(client_id, str) or not client_id:
            return self._error("invalid_grant", "Assertion sans émetteur (iss)")

        client = await self._clients.find_by_id(client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        verified = await self._client_assertions.verify(
            token=request.assertion,
            client=client,
            audience=self._token_endpoint(),
            require_iss_eq_sub=False,
        )
        if verified is None:
            return self._error("invalid_grant", "Assertion jwt-bearer invalide")
        subject = verified["sub"]
        if not isinstance(subject, str):
            return self._error("invalid_grant", "Assertion jwt-bearer sans sujet (sub)")
        return client, subject

    async def _device_code(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Poll l'état de la session appareil et émet les jetons une fois approuvée.

        Tant que l'utilisateur n'a pas validé l'appareil sur la page de
        vérification, la réponse est ``authorization_pending`` (RFC 8628
        §3.4). Un poll plus rapide que l'``interval`` retourne
        ``slow_down`` et augmente l'intervalle. Une fois ``APPROVED``, la
        session est consommée et les jetons sont émis pour le ``subject``
        de l'utilisateur ; ``DENIED`` et l'expiration produisent
        respectivement ``access_denied`` et ``expired_token``.
        """
        if self._device_codes is None:
            return self._error("unsupported_grant_type")
        if not request.device_code:
            return self._error("invalid_grant", "Paramètre device_code manquant")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        binding = await self._evaluate_dpop(client, request)
        if isinstance(binding, TokenError):
            return binding

        stored = await self._load_device_session(request)
        if isinstance(stored, TokenError):
            return stored

        resources = await self._effective_resources(request, ())
        if isinstance(resources, TokenError):
            return resources

        now = datetime.now(timezone.utc)
        if stored.status == DeviceAuthorizationStatus.APPROVED:
            return await self._device_approved_flow(
                client,
                stored,
                now,
                binding,
                resources,
                _tls_certificate_bound_hash(client, request),
            )
        return await self._device_pending_response(stored, now)

    async def _load_device_session(self, request: TokenRequest) -> DeviceAuthorization | TokenError:
        """Charge la session appareil : inconnue/autre client, expirée ou refusée.

        L'expiration détruit la session (RFC 8628 §3.5) et le refus de
        l'utilisateur vaut ``access_denied``.
        """
        if self._device_codes is None:
            return self._error("unsupported_grant_type")
        stored = await self._device_codes.find_by_device_code_hash(token_hash(request.device_code))
        if stored is None or stored.client_id != request.client_id:
            return self._error("invalid_grant", "Device code invalide ou d'un autre client")
        if stored.expires_at < datetime.now(timezone.utc):
            await self._device_codes.delete(stored.device_code_hash)
            return self._error("expired_token", "Device code expiré")
        if stored.status == DeviceAuthorizationStatus.DENIED:
            return self._error("access_denied", "Appareil refusé par l'utilisateur")
        return stored

    async def _device_pending_response(
        self, stored: DeviceAuthorization, now: datetime
    ) -> TokenResponse | TokenError:
        """Réponse d'un poll tant que l'autorisation n'est pas tranchée (RFC 8628 §3.4)."""
        if self._device_codes is None:
            return self._error("unsupported_grant_type")
        if (
            stored.last_polled_at is not None
            and (now - stored.last_polled_at).total_seconds() < stored.interval
        ):
            await self._device_codes.save(
                replace(stored, interval=stored.interval + 5, last_polled_at=now)
            )
            return self._error("slow_down", "Polling trop rapide : augmentez l'intervalle")
        await self._device_codes.save(replace(stored, last_polled_at=now))
        return self._error("authorization_pending", "En attente de l'autorisation de l'utilisateur")

    async def _device_approved_flow(
        self,
        client: Client,
        stored: DeviceAuthorization,
        now: datetime,
        binding: DpopBinding,
        resources: tuple[str, ...],
        tls_cert_hash: str = "",
    ) -> TokenResponse | TokenError:
        """Consomme la session appareil approuvée et émet ses jetons (RFC 8628 §3.5)."""
        if self._device_codes is None:
            return self._error("unsupported_grant_type")
        await self._device_codes.delete(stored.device_code_hash)
        dpop_jkt = binding.jkt if binding.bound else ""
        refresh_token = ""
        if Scope.OFFLINE_ACCESS in stored.scopes:
            refresh_token = await self._issue_refresh_token(
                client,
                stored.subject,
                stored.scopes,
                now,
                dpop_jkt=dpop_jkt,
                resources=resources,
            )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            stored.scopes,
            nonce="",
            now=now,
            dpop_jkt=dpop_jkt,
            resources=resources,
            tls_cert_hash=tls_cert_hash,
        )
        if isinstance(issued, TokenError):
            return issued
        id_token, access_token, token_ttl = issued
        return self._success(
            id_token,
            access_token,
            token_ttl,
            stored.scopes,
            refresh_token,
            dpop_bound=binding.bound,
        )

    async def _ciba(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Poll la demande CIBA et émet les jetons une fois approuvée (CIBA §10.1).

        Tant que l'utilisateur n'a pas tranché, la réponse est
        ``authorization_pending`` ; un poll plus rapide que l'``interval``
        retourne ``slow_down`` et augmente l'intervalle. Une fois
        ``APPROVED``, la demande est consommée et les jetons sont émis pour
        le ``subject`` résolu à l'acceptation — ``DENIED``, expiration et
        ``auth_req_id`` inconnu/d'autre client produisent respectivement
        ``access_denied``, ``expired_token`` et ``invalid_grant`` (§11).
        """
        if self._backchannel_auth is None:
            return self._error("unsupported_grant_type")
        if not request.auth_req_id:
            return self._error("invalid_grant", "Paramètre auth_req_id manquant")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        binding = await self._evaluate_dpop(client, request)
        if isinstance(binding, TokenError):
            return binding

        stored = await self._load_ciba_session(request)
        if isinstance(stored, TokenError):
            return stored

        resources = await self._effective_resources(request, stored.resource_uris)
        if isinstance(resources, TokenError):
            return resources

        now = datetime.now(timezone.utc)
        if stored.status == BackchannelAuthenticationStatus.APPROVED:
            return await self._ciba_approved_flow(
                client,
                stored,
                now,
                binding,
                resources,
                _tls_certificate_bound_hash(client, request),
            )
        return await self._ciba_pending_response(stored, now)

    async def _load_ciba_session(
        self, request: TokenRequest
    ) -> BackchannelAuthenticationRequest | TokenError:
        """Charge la demande CIBA : inconnue/autre client, expirée, refusée ou push.

        L'expiration détruit la demande (CIBA §11), le refus de
        l'utilisateur vaut ``access_denied`` et un client enregistré en
        mode push ne peut rien retirer du token endpoint (``unauthorized_client``).
        """
        if self._backchannel_auth is None:
            return self._error("unsupported_grant_type")
        stored = await self._backchannel_auth.find_by_auth_req_id_hash(
            token_hash(request.auth_req_id)
        )
        if stored is None or stored.client_id != request.client_id:
            return self._error("invalid_grant", "auth_req_id invalide ou d'un autre client")
        if stored.expires_at < datetime.now(timezone.utc):
            await self._backchannel_auth.delete(stored.auth_req_id_hash)
            return self._error("expired_token", "auth_req_id expiré")
        if stored.delivery_mode == "push":
            return self._error(
                "unauthorized_client",
                "Client enregistré en mode push : résultat non délivré sur /token (CIBA §11)",
            )
        if stored.status == BackchannelAuthenticationStatus.DENIED:
            return self._error("access_denied", "Demande refusée par l'utilisateur")
        return stored

    async def _ciba_pending_response(
        self, stored: BackchannelAuthenticationRequest, now: datetime
    ) -> TokenResponse | TokenError:
        """Réponse d'un poll tant que l'utilisateur n'a pas tranché (CIBA §11)."""
        if self._backchannel_auth is None:
            return self._error("unsupported_grant_type")
        if (
            stored.last_polled_at is not None
            and (now - stored.last_polled_at).total_seconds() < stored.interval
        ):
            await self._backchannel_auth.save(
                replace(stored, interval=stored.interval + 5, last_polled_at=now)
            )
            return self._error("slow_down", "Polling trop rapide : augmentez l'intervalle")
        await self._backchannel_auth.save(replace(stored, last_polled_at=now))
        return self._error("authorization_pending", "En attente de l'utilisateur")

    async def _ciba_approved_flow(
        self,
        client: Client,
        stored: BackchannelAuthenticationRequest,
        now: datetime,
        binding: DpopBinding,
        resources: tuple[str, ...],
        tls_cert_hash: str = "",
    ) -> TokenResponse | TokenError:
        """Consomme la demande CIBA approuvée et émet ses jetons (CIBA §10.1.1)."""
        if self._backchannel_auth is None:
            return self._error("unsupported_grant_type")
        await self._backchannel_auth.delete(stored.auth_req_id_hash)
        dpop_jkt = binding.jkt if binding.bound else ""
        refresh_token = ""
        if Scope.OFFLINE_ACCESS in stored.scopes:
            refresh_token = await self._issue_refresh_token(
                client,
                stored.subject,
                stored.scopes,
                now,
                dpop_jkt=dpop_jkt,
                resources=resources,
            )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            stored.scopes,
            nonce="",
            now=now,
            acr=stored.acr,
            dpop_jkt=dpop_jkt,
            resources=resources,
            tls_cert_hash=tls_cert_hash,
        )
        if isinstance(issued, TokenError):
            return issued
        id_token, access_token, token_ttl = issued
        return self._success(
            id_token,
            access_token,
            token_ttl,
            stored.scopes,
            refresh_token,
            dpop_bound=binding.bound,
        )

    async def _effective_scope(
        self, client: Client, requested: str, *, default: frozenset[Scope]
    ) -> frozenset[Scope] | TokenError:
        """Portée effective : demandée (bornée au client) sinon celle du client."""
        scopes = default
        if requested:
            wanted = Scope.from_space_separated(requested)
            if wanted - client.scopes:
                return self._error("invalid_scope", "Portée jamais enregistrée pour le client")
            scopes = wanted
        if self._scope_registry is not None:
            unknown = await self._scope_registry.unknown_scopes(scopes)
            if unknown:
                return self._error(
                    "invalid_scope", "Scope(s) non enregistré(s) : " + ", ".join(unknown)
                )
        return scopes

    async def _effective_resources(
        self, request: TokenRequest, bound: tuple[str, ...]
    ) -> tuple[str, ...] | TokenError:
        """Resources effectives du grant ou ``invalid_target`` (RFC 8707 §4).

        ``bound`` porte les resource indicators persistés avec le support
        (code d'autorisation, refresh token, demande CIBA) : les resources
        de la requête doivent en être un sous-ensemble ; à défaut, les
        resources déclarées sont contrôlées contre le registre des
        ``ApiResource.indicator``. ``bound`` vide restitué tel quel quand
        la requête n'en déclare aucune (périmètre du support).
        """
        resources = parse_resource_parameter(request.resource)
        if not resources:
            return bound
        if bound:
            outside = [uri for uri in resources if uri not in bound]
            if outside:
                return self._error(
                    "invalid_target",
                    "resource hors des ressources liées au grant (RFC 8707 §4) : "
                    + ", ".join(outside),
                )
            return resources
        malformed = [uri for uri in resources if not is_resource_uri(uri)]
        if malformed:
            return self._error(
                "invalid_target",
                "resource doit être une URI absolue sans fragment (RFC 8707 §2.1) : "
                + ", ".join(malformed),
            )
        if self._scope_registry is not None:
            unknown = await self._scope_registry.unknown_resources(resources)
            if unknown:
                return self._error(
                    "invalid_target",
                    "Resource non enregistrée (RFC 8707 §2.2) : " + ", ".join(unknown),
                )
        return resources

    async def _evaluate_dpop(
        self, client: Client, request: TokenRequest, *, bound_jkt: str = ""
    ) -> DpopBinding | TokenError:
        """Valide la preuve DPoP du client et décide du lien du token (RFC 9449).

        Sans guard injecté, seul ``require_dpop`` est honoré : la requête
        dépourvue d'en-tête ``DPoP`` est refusée, aucun proof n'étant
        traitable sans validateur. ``bound_jkt`` porte l'empreinte exigée
        par le support en cours (code ou refresh token lié, §10).
        """
        if self._dpop is None:
            if client.require_dpop and not request.dpop_proof:
                return self._error(
                    "invalid_request",
                    "Ce client exige une preuve DPoP (RFC 9449 §5.2)",
                )
            return DpopBinding()
        result = await self._dpop.evaluate(
            client=client,
            proof=request.dpop_proof,
            htu=self._token_endpoint(),
            bound_jkt=bound_jkt,
        )
        if isinstance(result, DpopGuardError):
            return self._error(result.error, result.error_description)
        return result

    @staticmethod
    def _refresh_dpop_jkt(client: Client, stored: RefreshToken, binding: DpopBinding) -> str:
        """Empreinte liant le refresh token émis (RFC 9449 §5).

        La liaison d'un refresh token existant est conservée telle quelle
        (sa clé vient d'être revalidée) ; à défaut, un client **public**
        ayant prouvé sa clé voit son nouveau refresh token lié — les
        clients confidentiels gardent un refresh token porteur (§5).
        """
        if stored.dpop_jkt:
            return stored.dpop_jkt
        if client.client_type is ClientType.CONFIDENTIAL:
            return ""
        return binding.jkt if binding.bound else ""

    async def _authenticate_client(
        self, client: Client, request: TokenRequest
    ) -> TokenError | None:
        """Authentifie le client selon sa ``token_endpoint_auth_method`` (RFC 6749 §2.3).

        L'``aud`` admise pour la ``client_assertion`` couvre l'issuer et le
        token endpoint (RFC 7523 §3) : la suite FAPI1 signe avec l'issuer
        (module ``EnsureClientAssertionWithIssAudSucceeds``).
        """
        detail = await authenticate_client(
            client,
            client_secret=request.client_secret,
            assertions=self._client_assertions,
            assertion_type=request.client_assertion_type,
            assertion=request.client_assertion,
            assertion_audience=(self._config.issuer.rstrip("/"), self._token_endpoint()),
            tls_certificate=request.tls_certificate,
        )
        if detail is None:
            return None
        return self._error("invalid_client", detail)

    def _token_endpoint(self) -> str:
        """URL du token endpoint, valeur de ``aud`` attendue des assertions."""
        if self._config.token_endpoint:
            return self._config.token_endpoint
        return f"{self._config.issuer.rstrip('/')}/token"

    async def _issue_tokens(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        *,
        nonce: str,
        now: datetime,
        session_id: str = "",
        auth_time: int = 0,
        acr: str = "",
        claims: str = "",
        dpop_jkt: str = "",
        resources: tuple[str, ...] = (),
        tls_cert_hash: str = "",
    ) -> tuple[str, str, int] | TokenError:
        """Émet et retourne l'``id_token``, l'``access_token`` et la TTL effective.

        ``acr`` (première valeur ``acr_values`` conservée sur le code,
        OIDC Core 1.0 §3.1.2.1) complète l'id_token du claim ``acr`` ;
        ``claims`` porte le paramètre ``claims`` (§5.5) : son member
        ``id_token`` est résolu dans l'id_token et son member ``userinfo``
        voyage dans l'access_token, relu par ``/userinfo``. ``dpop_jkt``
        (RFC 9449 §5) lie l'access token à la clé prouvée via le claim
        ``cnf`` — chaîne vide = jeton porteur classique. ``resources``
        (RFC 8707 §3) porte l'``aud`` du jeton quand il est renseigné.
        ``tls_cert_hash`` (RFC 8705 §3.3) porte l'empreinte du certificat
        client mTLS qui doit lier l'access token — chaîne vide sans lien.
        """
        claims_request = parse_claims_parameter(claims) if claims else None
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        expires_at = now + timedelta(seconds=token_ttl)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())

        material = await self._id_token_material(client)
        if isinstance(material, TokenError):
            return material
        id_token_algorithm, shared_secret = material
        additional: dict[str, object] = {}
        if acr:
            additional["acr"] = acr
        if claims_request is not None:
            additional.update(
                await resolve_requested_claims(
                    claims_request.id_token, subject, self._claims_provider
                )
            )
        id_token = await self._token_manager.create_id_token(
            algorithm=id_token_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=client.client_id,
            nonce=nonce,
            session_id=session_id,
            expires_at=expires_epoch,
            issued_at=issued_at,
            auth_time=auth_time,
            shared_secret=shared_secret,
            additional_claims=additional or None,
        )
        try:
            id_token = await encrypt_id_token_for_client(
                id_token=id_token,
                client=client,
                secret_cipher=self._config.secret_cipher,
                encrypter=self._config.id_token_encrypter,
            )
        except JWEUnavailableError:
            return self._error("invalid_client", "Matériel de chiffrement d'id_token indisponible")
        audience = await self._resolve_audience(client, scopes, resources)
        access_token = await self._token_manager.create_access_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=audience,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=scopes,
            additional_claims=_access_token_additional_claims(
                claims_request, dpop_jkt, tls_cert_hash
            ),
        )
        return id_token, access_token, token_ttl

    async def _id_token_material(self, client: Client) -> tuple[JWTAlgorithm, str] | TokenError:
        """Résout algorithme et matériel de signature d'``id_token`` du client."""
        material = await resolve_id_token_material(
            client, self._config.signing_algorithm, self._config.secret_cipher
        )
        if material is None:
            return self._error(
                "invalid_client", "Secret du client indisponible pour la signature HS*"
            )
        return material

    async def _issue_access_token(
        self,
        client: Client,
        *,
        subject: str,
        scopes: frozenset[Scope],
        now: datetime,
        dpop_jkt: str = "",
        resources: tuple[str, ...] = (),
        tls_cert_hash: str = "",
    ) -> tuple[str, int]:
        """Émet et retourne un ``access_token`` et sa TTL effective.

        ``dpop_jkt`` non vide lie le jeton à la clé DPoP prouvée (claim
        ``cnf``, RFC 9449 §5.1) ; ``resources`` (RFC 8707 §3) porte
        l'``aud`` du jeton quand il est renseigné ; ``tls_cert_hash``
        non vide lie le jeton au certificat client mTLS présenté (claim
        ``cnf.x5t#S256``, RFC 8705 §3.3).
        """
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        expires_at = now + timedelta(seconds=token_ttl)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())
        audience = await self._resolve_audience(client, scopes, resources)
        access_token = await self._token_manager.create_access_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=audience,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=scopes,
            additional_claims=_access_token_additional_claims(None, dpop_jkt, tls_cert_hash),
        )
        return access_token, token_ttl

    async def _resolve_audience(
        self, client: Client, scopes: frozenset[Scope], resources: tuple[str, ...] = ()
    ) -> str | list[str]:
        """Audience du jeton : resources RFC 8707, sinon resources accordées, sinon client."""
        if resources:
            return resource_audience(resources)
        if self._scope_registry is None:
            return client.client_id
        return await self._scope_registry.audiences_for(client.client_id, scopes)

    async def _issue_refresh_token(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        now: datetime,
        *,
        dpop_jkt: str = "",
        resources: tuple[str, ...] = (),
    ) -> str:
        """Génère, persiste (empreinte) et retourne un nouveau refresh token opque.

        ``dpop_jkt`` non vide lie le refresh token à la clé DPoP (RFC
        9449 §5) : chaque renouvellement devra then présenter une preuve
        signée par cette même clé. ``resources`` fixe les resource
        indicators (RFC 8707) que tout renouvellement devra reprendre.
        """
        ttl = resolve_lifetime_seconds(
            client.refresh_token_lifetime_seconds, self._config.refresh_token_ttl_seconds
        )
        value = token_urlsafe(48)
        await self._refresh_tokens.save(
            RefreshToken(
                token_hash=token_hash(value),
                client_id=client.client_id,
                subject=subject,
                scopes=scopes,
                expires_at=now + timedelta(seconds=ttl),
                dpop_jkt=dpop_jkt,
                resource_uris=resources,
            )
        )
        return value

    def _success(
        self,
        id_token: str,
        access_token: str,
        token_ttl: int,
        scopes: frozenset[Scope],
        refresh_token: str = "",
        *,
        dpop_bound: bool = False,
    ) -> TokenResponse:
        """Construit une réponse de succès (avec ou sans id_token/refresh token).

        Un access token lié à une clé DPoP est annoncé ``token_type=DPoP``
        (RFC 9449 §5.1) — ``Bearer`` reste la valeur porteur classique.
        """
        return TokenResponse(
            access_token=access_token,
            id_token=id_token,
            token_type="DPoP" if dpop_bound else "Bearer",
            expires_in=token_ttl,
            scope=" ".join(sorted(scope.value for scope in scopes)),
            refresh_token=refresh_token,
        )

    @staticmethod
    def _verify_pkce(auth_code: AuthorizationCode, code_verifier: str) -> bool:
        """Vérifie le ``code_verifier`` contre le ``code_challenge`` du code.

        ``S256``:  ``base64url(sha256(code_verifier)) == code_challenge``
        ``plain``: ``code_verifier == code_challenge``
        """
        if not code_verifier:
            return False
        if auth_code.code_challenge_method.upper() == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return expected == auth_code.code_challenge
        return code_verifier == auth_code.code_challenge

    def _error(self, error: str, description: str = "") -> TokenError:
        """Construit une réponse d'erreur du token endpoint (RFC 6749 §5.2)."""
        return TokenError(error=error, error_description=description)


def _unverified_assertion_claims(assertion: str) -> dict[str, object] | None:
    """Claims **non vérifiés** d'une assertion, réservés à la localisation du client.

    Aucune décision de sécurité n'est prise sur ces valeurs : elles ne
    servent qu'à retrouver le candidat dans le registre, l'étant
    ensuite intégralement vérifiée (signature, ``iss``, ``aud``, ``exp``)
    avant tout échange.
    """
    try:
        _, payload, _ = assertion.split(".")
        padded = payload + "=" * (-len(payload) % 4)  # NOSONAR(S5659) — localisation seule
        data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _access_token_additional_claims(
    claims_request: ClaimsRequest | None, dpop_jkt: str, tls_cert_hash: str = ""
) -> dict[str, object] | None:
    """Claims additionnels de l'access token : member ``userinfo`` + liens du jeton.

    Le member ``userinfo`` du paramètre ``claims`` (OIDC Core 1.0 §5.5)
    est relu par ``/userinfo`` ; ``cnf.jkt`` (RFC 9449 §5.1) lie le jeton
    à la clé DPoP dont la preuve a été validée et ``cnf.x5t#S256``
    (RFC 8705 §3.3) au certificat client mTLS présenté au token
    endpoint. ``None`` sans rien à ajouter, pour ne pas altérer le
    payload standard.
    """
    additional: dict[str, object] = {}
    payload = requested_userinfo_payload(claims_request) if claims_request else None
    if payload:
        additional.update(payload)
    confirmation: dict[str, object] = {}
    if dpop_jkt:
        confirmation["jkt"] = dpop_jkt
    if tls_cert_hash:
        confirmation["x5t#S256"] = tls_cert_hash
    if confirmation:
        additional["cnf"] = confirmation
    return additional or None


def _tls_certificate_bound_hash(client: Client, request: TokenRequest) -> str:
    """Empreinte du certificat client liant l'access token émis (RFC 8705 §3.3).

    Le jeton n'est lié que si le client s'authentifie par certificat
    mTLS (``tls_client_auth`` / ``self_signed_tls_client_auth``) et si
    la requête porte réellement ce certificat : ``cnf.x5t#S256`` reprend
    l'empreinte base64url(SHA-256(DER)). Chaîne vide = jeton porteur
    classique (aucune autre méthode d'authentification ne voit son jeton
    lié, y compris derrière un proxy qui poserait des en-têtes TLS).
    """
    if client.token_endpoint_auth_method not in (
        TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
        TokenEndpointAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
    ):
        return ""
    certificate = request.tls_certificate
    if certificate is None or certificate.der is None:
        return ""
    return der_certificate_hash(certificate.der)
