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
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.application.authorization_details import (
    AuthorizationDetailsError,
    grant_authorization_details,
    parse_authorization_details,
)
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
from puridentityserver.application.identity_assurance import (
    ID_TOKEN_LOCATION,
    VERIFIED_CLAIMS_MEMBER,
    IdentityAssuranceUseCase,
    verified_claims_payload,
    verified_claims_request,
)
from puridentityserver.application.openid20_migration import OpenID20MigrationUseCase
from puridentityserver.application.resource_indicators import (
    is_resource_uri,
    parse_resource_parameter,
    resource_audience,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import (
    CIBA_GRANT_TYPE,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
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
from puridentityserver.domain.openid20 import OPENID20_ID_CLAIM
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.domain.subjects import access_token_subject_claims, display_subject
from puridentityserver.interfaces.domain.client_assertions import (
    JWT_BEARER_GRANT_TYPE_URN,
    ClientAssertionVerifier,
)
from puridentityserver.interfaces.domain.secrets import SecretCipher
from puridentityserver.interfaces.domain.tokens import (
    IdTokenConditionalClaims,
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
    subject_seed: str = ""


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
    pre_authorized_code: str = ""
    tx_code: str = ""
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
    authorization_details: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class IdTokenContext:
    """Contexte d'émission de l'``id_token`` (claims conditionnels).

    Regroupe les éléments qui décrivent le contenu de l'``id_token`` :
    ``nonce`` (OIDC Core 1.0 §3.1.2.1), ``session_id`` (claim ``sid``),
    ``auth_time``, ``acr`` (§3.1.2.1), le paramètre ``claims`` brut (§5.5)
    et le ``openid2_realm`` de la spec « OpenID 2.0 to OpenID Connect
    Migration 1.0 » (§2).
    """

    nonce: str = ""
    session_id: str = ""
    auth_time: int = 0
    acr: str = ""
    claims: str = ""
    openid2_realm: str = ""


@dataclass(frozen=True, slots=True)
class TokenDependencies:
    """Dépendances optionnelles du token endpoint.

    Regroupées dans un conteneur unique : le constructeur du cas d'usage
    reste lisible et la complexité du signature sous le seuil du quality
    gate (SonarCloud ``python:S107``). Toutes sont facultatives — sans
    elles, le comportement du token endpoint est celui d'un OP OIDC
    standard.
    """

    claims_provider: ClaimsProvider | None = None
    revoked_tokens: RevokedTokenRepository | None = None
    dpop: DpopGrantGuard | None = None
    openid20_migration: OpenID20MigrationUseCase | None = None
    identity_assurance: IdentityAssuranceUseCase | None = None


#: Dépendances optionnelles par défaut : aucune feature activée.
_NO_TOKEN_DEPENDENCIES = TokenDependencies()


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
        dependencies: TokenDependencies = _NO_TOKEN_DEPENDENCIES,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons.

        ``dependencies`` regroupe les dépendances optionnelles (claims du
        profil, denylist, DPoP et extensions de spécification) : sans elles,
        le comportement du token endpoint est celui d'un OP OIDC standard.
        ``dependencies.claims_provider`` résout les valeurs du member
        ``id_token`` du paramètre ``claims`` (OIDC Core 1.0 §5.5) pour
        compléter l'id_token émis à l'échange du code ; sans injection, seul
        le payload standard est signé. ``dependencies.revoked_tokens`` est le
        denylist sur lequel un code réutilisé place l'access token du premier
        échange (RFC 6749 §4.1.2) ; sans injection, la révocation est
        simplement ignorée. ``dependencies.dpop`` applique les règles DPoP
        (RFC 9449) : sans injection, aucun proof n'est traité et
        ``require_dpop`` n'est honoré que pour le rejet de la requête
        dépourvue d'en-tête ``DPoP``.
        ``dependencies.openid20_migration`` porte les associations OpenID 2.0
        (spec « OpenID 2.0 to OpenID Connect Migration 1.0 ») : sans
        injection — ou lorsque le support est désactivé — aucun claim
        ``openid2_id`` n'est émis. ``dependencies.identity_assurance`` résout
        les ``verified_claims`` (OpenID Identity Assurance 1.0) : sans
        injection, aucun membre ``verified_claims`` n'est émis.
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
        self._dependencies = dependencies

    @property
    def _claims_provider(self) -> ClaimsProvider | None:
        """Fournisseur de claims du profil (facultatif)."""
        return self._dependencies.claims_provider

    @property
    def _revoked_tokens(self) -> RevokedTokenRepository | None:
        """Denylist des jetons révoqués (facultatif)."""
        return self._dependencies.revoked_tokens

    @property
    def _dpop(self) -> DpopGrantGuard | None:
        """Garde DPoP appliqué aux preuves (facultatif)."""
        return self._dependencies.dpop

    @property
    def _openid20_migration(self) -> OpenID20MigrationUseCase | None:
        """Cas d'usage de la migration OpenID 2.0 (facultatif)."""
        return self._dependencies.openid20_migration

    @property
    def _identity_assurance(self) -> IdentityAssuranceUseCase | None:
        """Cas d'usage de l'identité assurance (facultatif)."""
        return self._dependencies.identity_assurance

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
        if request.grant_type == PRE_AUTHORIZED_CODE_GRANT_TYPE:
            return await self._pre_authorized_code(request)
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

        tls_cert_hash = _tls_certificate_bound_hash(client, request)
        refresh_token = ""
        if Scope.OFFLINE_ACCESS in auth_code.scopes:
            refresh_token = await self._issue_refresh_token(
                client,
                auth_code.subject,
                auth_code.scopes,
                now,
                dpop_jkt=binding.jkt if binding.bound else "",
                resources=resources,
                tls_cert_hash=tls_cert_hash,
                subject_material=auth_code.subject_material,
            )
        try:
            parsed_details = parse_authorization_details(auth_code.authorization_details)
        except AuthorizationDetailsError:
            parsed_details = ()
        granted_details = tuple(grant_authorization_details(parsed_details))
        issued = await self._issue_tokens(
            client,
            auth_code.subject,
            auth_code.scopes,
            now=now,
            context=IdTokenContext(
                nonce=auth_code.nonce,
                session_id=auth_code.session_id,
                auth_time=auth_code.auth_time,
                acr=auth_code.acr,
                claims=auth_code.claims,
                openid2_realm=auth_code.openid2_realm,
            ),
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=tls_cert_hash,
            subject_material=auth_code.subject_material,
            authorization_details=granted_details,
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
            authorization_details=granted_details,
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
        """Renouvelle les jetons à partir d'un refresh token opaque.

        Sauf profil FAPI2, le refresh token est **tourné** : l'ancien est
        consommé et un nouveau est émis (RFC 6749 §6 + rotation). En
        profil FAPI2 la rotation est sautée : l'accès/id_token changent,
        le refresh token n'est pas renouvelé et le champ ``refresh_token``
        est omis de la réponse (l'ancien demeure valide), comportement
        admis par ``FAPI2SPFinalRefreshToken`` qui conserve le jeton pour
        ses contrôles ultérieurs.
        """
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

        tls_cert_hash = _tls_certificate_bound_hash(client, request)
        if stored.tls_cert_hash and tls_cert_hash != stored.tls_cert_hash:
            return self._error(
                "invalid_grant",
                "Refresh token lié au certificat client mTLS (RFC 8705 §3.3) : "
                "certificat absent ou différent de celui d'émission",
            )

        now = datetime.now(timezone.utc)
        binding = await self._evaluate_dpop(client, request, bound_jkt=stored.dpop_jkt)
        if isinstance(binding, TokenError):
            return binding

        resources = await self._effective_resources(request, stored.resource_uris)
        if isinstance(resources, TokenError):
            return resources

        if client.fapi2_enabled:
            refresh_token = ""
        else:
            await self._refresh_tokens.consume(stored.token_hash)
            refresh_token = await self._issue_refresh_token(
                client,
                stored.subject,
                scopes,
                now,
                dpop_jkt=self._refresh_dpop_jkt(client, stored, binding),
                resources=resources,
                tls_cert_hash=tls_cert_hash,
                subject_material=stored.subject_material,
            )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            scopes,
            now=now,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources,
            tls_cert_hash=tls_cert_hash,
            subject_material=stored.subject_material,
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
                tls_cert_hash=tls_cert_hash,
                subject_material=stored.device_code_hash,
            )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            stored.scopes,
            now=now,
            dpop_jkt=dpop_jkt,
            resources=resources,
            tls_cert_hash=tls_cert_hash,
            subject_material=stored.device_code_hash,
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
                tls_cert_hash=tls_cert_hash,
                subject_material=stored.auth_req_id_hash,
            )
        issued = await self._issue_tokens(
            client,
            stored.subject,
            stored.scopes,
            now=now,
            context=IdTokenContext(acr=stored.acr),
            dpop_jkt=dpop_jkt,
            resources=resources,
            tls_cert_hash=tls_cert_hash,
            subject_material=stored.auth_req_id_hash,
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

    async def issue_ciba_push_tokens(
        self, stored: BackchannelAuthenticationRequest
    ) -> TokenResponse | TokenError:
        """Emet les jetons d'une demande CIBA approuvee en mode push (CIBA §7.1.1)."""
        if self._backchannel_auth is None:
            return self._error("unsupported_grant_type")  # pragma: no cover
        client = await self._clients.find_by_id(stored.client_id)
        if client is None:
            return self._error("invalid_client", "Client inconnu")  # pragma: no cover
        now = datetime.now(timezone.utc)
        binding = DpopBinding(jkt="", bound=False)
        resources = stored.resource_uris if stored.resource_uris else ()
        return await self._ciba_approved_flow(client, stored, now, binding, resources)

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

        L'``aud`` admise pour la ``client_assertion`` est l'issuer seul
        pour un client FAPI2 (FAPI2-SP-FINAL-5.3.2.1-8 : le plan Final
        signe avec ``CreateClientAuthenticationAssertionClaimsWithIss-
        Audience``), l'issuer et le token endpoint sinon (RFC 7523 §3) —
        la suite FAPI1 signe aussi avec l'issuer (module
        ``EnsureClientAssertionWithIssAudSucceeds``).

        Un client ``tls_client_certificate_bound_access_tokens`` (RFC 8705
        §3.1) doit en plus présenter un certificat client à chaque appel,
        au-delà de sa méthode d'authentification : sans certificat, la
        demande est refusée ``invalid_client`` (FAPI1-ADV-5.2.2-6).
        """
        if client.tls_client_certificate_bound_access_tokens and (
            request.tls_certificate is None or request.tls_certificate.der is None
        ):
            return self._error(
                "invalid_client",
                "Certificat client mTLS requis (RFC 8705 §3.1, "
                "tls_client_certificate_bound_access_tokens)",
            )
        detail = await authenticate_client(
            client,
            client_secret=request.client_secret,
            assertions=self._client_assertions,
            assertion_type=request.client_assertion_type,
            assertion=request.client_assertion,
            assertion_audience=self._assertion_audiences(client),
            tls_certificate=request.tls_certificate,
        )
        if detail is None:
            return None
        return self._error("invalid_client", detail)

    def _assertion_audiences(self, client: Client) -> tuple[str, ...]:
        """Audiences admises de la ``client_assertion`` du token endpoint.

        Issuer seul pour un client FAPI2, issuer et URL du token endpoint
        sinon (sans doublon ni barre finale).
        """
        if client.fapi2_enabled:
            issuer = self._config.issuer.rstrip("/")
            return (issuer,) if issuer else ()
        return (self._config.issuer.rstrip("/"), self._token_endpoint())

    def _token_endpoint(self) -> str:
        """URL du token endpoint, valeur de ``aud`` attendue des assertions."""
        if self._config.token_endpoint:
            return self._config.token_endpoint
        return f"{self._config.issuer.rstrip('/')}/token"

    async def _verified_claims(
        self, claims_request: ClaimsRequest, location: str, subject: str
    ) -> dict[str, object] | None:
        """Membre `verified_claims` résolu (identité assurance, spec IDA 1.0).

        ``None`` quand aucune claim vérifiée ne peut être servie : le membre
        est alors omis de l'`id_token` plutôt que servi incomplet.
        """
        if self._identity_assurance is None:
            return None
        request = verified_claims_request(claims_request, location)
        if request is None:
            return None
        resolved = await self._identity_assurance.resolve(request, subject)
        return resolved

    async def _openid20_identifier(self, scopes: frozenset[Scope], subject: str, realm: str) -> str:
        """Identifiant OpenID 2.0 associé au compte (spec de migration, §4).

        Le claim ``openid2_id`` n'est produit que si le RP a demandé le scope
        ``openid2`` **et** qu'un identifiant OpenID 2.0 est associé au
        compte : sinon l'identifiant est vide et le claim est omis.
        """
        if self._openid20_migration is None or not self._openid20_migration.enabled:
            return ""
        if Scope.OPENID20 not in scopes:
            return ""
        return await self._openid20_migration.identifier_for(subject, realm)

    async def _issue_tokens(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        *,
        now: datetime,
        context: IdTokenContext | None = None,
        dpop_jkt: str = "",
        resources: tuple[str, ...] = (),
        tls_cert_hash: str = "",
        subject_material: str = "",
        authorization_details: tuple[dict[str, object], ...] = (),
    ) -> tuple[str, str, int] | TokenError:
        """Émet et retourne l'``id_token``, l'``access_token`` et la TTL effective.

        ``context`` porte les claims conditionnels de l'id_token : ``acr``
        (première valeur ``acr_values`` conservée sur le code, OIDC Core
        1.0 §3.1.2.1), le paramètre ``claims`` (§5.5) — son member
        ``id_token`` est résolu dans l'id_token et son member ``userinfo``
        voyage dans l'access_token, relu par ``/userinfo`` — et le
        ``openid2_realm`` de la spec de migration OpenID 2.0. ``dpop_jkt``
        (RFC 9449 §5) lie l'access token à la clé prouvée via le claim
        ``cnf`` — chaîne vide = jeton porteur classique. ``resources``
        (RFC 8707 §3) porte l'``aud`` du jeton quand il est renseigné.
        ``tls_cert_hash`` (RFC 8705 §3.3) porte l'empreinte du certificat
        client mTLS qui doit lier l'access token — chaîne vide sans lien.
        ``subject_material`` est la matière de dérivation de la ``sub``
        non publique (ESID 1.0 §4) : l'id_token expose la ``sub`` dérivée
        et l'access token embarque les claims permettant à ``/userinfo``
        de la reproduire.
        """
        if Scope.OPENID not in scopes:
            # Requête OAuth 2.0 sans ``openid`` (OIDC Core 1.0 §3.1.2.1) :
            # aucun id_token n'est émis — cas des flux OpenID4VCI, dont la
            # demande d'autorisation ne porte que le scope du credential.
            access_token, token_ttl = await self._issue_access_token(
                client,
                subject=subject,
                scopes=scopes,
                now=now,
                dpop_jkt=dpop_jkt,
                resources=resources,
                tls_cert_hash=tls_cert_hash,
                subject_material=subject_material,
                authorization_details=authorization_details,
            )
            return "", access_token, token_ttl
        id_token_context = context or IdTokenContext()
        claims_request = (
            parse_claims_parameter(id_token_context.claims) if id_token_context.claims else None
        )
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        expires_at = now + timedelta(seconds=token_ttl)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())
        subject_claims = access_token_subject_claims(client, subject, material=subject_material)

        material = await self._id_token_material(client)
        if isinstance(material, TokenError):
            return material
        id_token_algorithm, shared_secret = material
        additional: dict[str, object] = {}
        if id_token_context.acr:
            additional["acr"] = id_token_context.acr
        if claims_request is not None:
            additional.update(
                await resolve_requested_claims(
                    claims_request.id_token, subject, self._claims_provider
                )
            )
            # Le membre `verified_claims` est résolu par le cas d'usage
            # d'identité assurance (contraintes de la demande appliquées) :
            # le profil brut du user store ne doit jamais être servi.
            additional.pop(VERIFIED_CLAIMS_MEMBER, None)
            verified_claims = await self._verified_claims(
                claims_request, ID_TOKEN_LOCATION, subject
            )
            if verified_claims is not None:
                additional[VERIFIED_CLAIMS_MEMBER] = verified_claims
        openid20_id = await self._openid20_identifier(
            scopes, subject, id_token_context.openid2_realm
        )
        if openid20_id:
            additional[OPENID20_ID_CLAIM] = openid20_id
        id_token = await self._token_manager.create_id_token(
            algorithm=id_token_algorithm,
            issuer=self._config.issuer,
            subject=display_subject(
                client,
                subject,
                material=subject_material,
                seed=self._config.subject_seed,
            ),
            audience=client.client_id,
            expires_at=expires_epoch,
            issued_at=issued_at,
            conditional_claims=IdTokenConditionalClaims(
                nonce=id_token_context.nonce,
                session_id=id_token_context.session_id,
                auth_time=id_token_context.auth_time,
            ),
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
                claims_request,
                dpop_jkt,
                tls_cert_hash,
                subject_claims,
                authorization_details=authorization_details,
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
        subject_material: str = "",
        authorization_details: tuple[dict[str, object], ...] = (),
    ) -> tuple[str, int]:
        """Émet et retourne un ``access_token`` et sa TTL effective.

        ``dpop_jkt`` non vide lie le jeton à la clé DPoP prouvée (claim
        ``cnf``, RFC 9449 §5.1) ; ``resources`` (RFC 8707 §3) porte
        l'``aud`` du jeton quand il est renseigné ; ``tls_cert_hash``
        non vide lie le jeton au certificat client mTLS présenté (claim
        ``cnf.x5t#S256``, RFC 8705 §3.3). ``subject_material`` porte la
        matière de dérivation de la ``sub`` non publique (ESID 1.0 §4),
        ``""`` pour les flux sans session d'authentification.
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
            additional_claims=_access_token_additional_claims(
                None,
                dpop_jkt,
                tls_cert_hash,
                access_token_subject_claims(client, subject, material=subject_material),
                authorization_details=authorization_details,
            ),
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
        tls_cert_hash: str = "",
        subject_material: str = "",
    ) -> str:
        """Génère, persiste (empreinte) et retourne un nouveau refresh token opaque.

        ``dpop_jkt`` non vide lie le refresh token à la clé DPoP (RFC
        9449 §5) : chaque renouvellement devra alors présenter une preuve
        signée par cette même clé. ``resources`` fixe les resource
        indicators (RFC 8707) que tout renouvellement devra reprendre.
        ``tls_cert_hash`` non vide lie le refresh token au certificat
        client mTLS présenté (RFC 8705 §3.3) : tout renouvellement devra
        présenter le même certificat. ``subject_material`` reprend la
        matière de dérivation de la ``sub`` non publique (ESID 1.0 §4)
        afin que les renouvellements reproduisent la même ``sub``.

        Un client **confidentiel** ne porte jamais la liaison DPoP : il
        s'authentifie par ``private_key_jwt`` (ou mTLS) et la suite
        Certification FAPI2 renouvelle la preuve DPoP avec une **nouvelle
        clé** à chaque appel du refresh grant (``RefreshTokenRequestSteps``)
        — seuls les clients publics, dont le refresh token est le unique
        facteur de possession, restent liés à la clé prouvée.
        """
        if client.client_type is ClientType.CONFIDENTIAL:
            dpop_jkt = ""
        ttl = resolve_lifetime_seconds(
            client.refresh_token_lifetime_seconds, self._config.refresh_token_ttl_seconds
        )
        value = token_urlsafe(48)
        await self._refresh_tokens.save(
            RefreshToken(
                token_hash=token_hash(value),
                client_id=client.client_id,
                subject=subject,
                subject_material=subject_material,
                scopes=scopes,
                expires_at=now + timedelta(seconds=ttl),
                dpop_jkt=dpop_jkt,
                resource_uris=resources,
                tls_cert_hash=tls_cert_hash,
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
        authorization_details: tuple[dict[str, object], ...] = (),
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
            authorization_details=authorization_details,
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

    async def _resolve_pre_authorized_code(
        self, code_value: str, now: datetime
    ) -> AuthorizationCode | TokenError:
        auth_code = await self._codes.find_by_code(code_value)
        if auth_code is None or not auth_code.pre_authorized:
            return self._error("invalid_grant", "Code pre-autorise invalide")
        if auth_code.is_consumed:
            await self._revoke_issued_tokens(auth_code)
            return self._error("invalid_grant", "Code pre-autorise deja consomme")
        if auth_code.expires_at < now:
            return self._error("invalid_grant", "Code pre-autorise expire")
        return auth_code

    async def _pre_authorized_code(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Echange un code pre-autorise contre un access token (OID4VCI)."""
        now = datetime.now(timezone.utc)
        auth_code = await self._resolve_pre_authorized_code(request.pre_authorized_code, now)
        if isinstance(auth_code, TokenError):
            return auth_code

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", "Client inconnu ou inactif")
        authenticated = await self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated
        if auth_code.client_id and auth_code.client_id != client.client_id:
            return self._error("invalid_grant", "Code emis pour un autre client")

        if auth_code.tx_code_hash and (
            not request.tx_code
            or hashlib.sha256(request.tx_code.encode()).hexdigest() != auth_code.tx_code_hash
        ):
            return self._error("invalid_grant", "tx_code invalide")

        binding = await self._evaluate_dpop(client, request, bound_jkt=auth_code.dpop_jkt)
        if isinstance(binding, TokenError):
            return binding
        resources = await self._effective_resources(request, auth_code.resource_uris)
        if isinstance(resources, TokenError):
            return resources

        await self._codes.consume(auth_code.code)

        tls_cert_hash = _tls_certificate_bound_hash(client, request)
        access_token, expires_in = await self._issue_access_token(
            client,
            subject=auth_code.subject,
            scopes=auth_code.scopes,
            now=now,
            dpop_jkt=binding.jkt if binding.bound else "",
            resources=resources or (),
            tls_cert_hash=tls_cert_hash,
            subject_material=auth_code.subject_material,
        )
        return self._success(
            id_token="",
            access_token=access_token,
            token_ttl=expires_in,
            scopes=auth_code.scopes,
            refresh_token="",
            dpop_bound=binding.bound,
        )

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
    claims_request: ClaimsRequest | None,
    dpop_jkt: str,
    tls_cert_hash: str = "",
    subject_claims: Mapping[str, str] | None = None,
    authorization_details: tuple[dict[str, object], ...] = (),
) -> dict[str, object] | None:
    """Claims additionnels de l'access token : member ``userinfo`` + liens du jeton.

    Le member ``userinfo`` du paramètre ``claims`` (OIDC Core 1.0 §5.5)
    est relu par ``/userinfo`` ; ``cnf.jkt`` (RFC 9449 §5.1) lie le jeton
    à la clé DPoP dont la preuve a été validée et ``cnf.x5t#S256``
    (RFC 8705 §3.3) au certificat client mTLS présenté au token
    endpoint. ``subject_claims`` porte les claims privés de dérivation
    (``client_id``, ``subject_material``) posés en dernier : aucun autre
    payload ne peut les écraser. ``None`` sans rien à ajouter, pour ne
    pas altérer le payload standard.
    """
    additional: dict[str, object] = {}
    payload = requested_userinfo_payload(claims_request) if claims_request else None
    if payload:
        additional.update(payload)
    ekyc = verified_claims_payload(claims_request)
    if ekyc:
        claims_payload = additional.setdefault("claims", {})
        if isinstance(claims_payload, dict):
            claims_payload.update(ekyc)
    confirmation: dict[str, object] = {}
    if dpop_jkt:
        confirmation["jkt"] = dpop_jkt
    if tls_cert_hash:
        confirmation["x5t#S256"] = tls_cert_hash
    if confirmation:
        additional["cnf"] = confirmation
    if subject_claims:
        additional.update(subject_claims)
    if authorization_details:
        additional["authorization_details"] = [dict(d) for d in authorization_details]
    return additional or None


def _tls_certificate_bound_hash(client: Client, request: TokenRequest) -> str:
    """Empreinte du certificat client liant l'access token émis (RFC 8705 §3.3).

    Le jeton est lié si le client s'authentifie par certificat mTLS
    (``tls_client_auth`` / ``self_signed_tls_client_auth``) ou s'il est
    enregistré ``tls_client_certificate_bound_access_tokens`` (RFC 8705
    §3.1) — auquel cas la présence du certificat est déjà exigée par
    ``_authenticate_client`` — et si la requête porte réellement ce
    certificat : ``cnf.x5t#S256`` reprend l'empreinte
    base64url(SHA-256(DER)). Chaîne vide = jeton porteur classique
    (aucune autre méthode d'authentification ne voit son jeton lié, y
    compris derrière un proxy qui poserait des en-têtes TLS).
    """
    if not client.tls_client_certificate_bound_access_tokens and (
        client.token_endpoint_auth_method
        not in (
            TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
            TokenEndpointAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
        )
    ):
        return ""
    certificate = request.tls_certificate
    if certificate is None or certificate.der is None:
        return ""
    return der_certificate_hash(certificate.der)
