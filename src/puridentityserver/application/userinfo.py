"""Cas d'utilisation : endpoint UserInfo (OIDC Core 1.0 §5.3, RFC 6750 §2).

Valide l'access token Bearer, récupère les claims de l'utilisateur via le
``ClaimsProvider`` injecté et filtre ces claims selon les scopes accordés
au jeton (OIDC Core 1.0 §5.4) élargis des claims du member ``userinfo``
du paramètre ``claims`` porté par l'access_token (OIDC Core 1.0 §5.5).

Un access token lié à une clé DPoP (RFC 9449 §5.1, claim ``cnf.jkt``)
n'est accepté que via le scheme ``DPoP`` avec une preuve dont l'empreinte
correspond, liée au jeton par ``ath`` (§7.2) — le scheme ``Bearer`` est
alors rejeté avec un challenge ``DPoP``.

Un access token lié à un certificat client mTLS (RFC 8705 §3.3, claim
``cnf.x5t#S256``) n'est accepté que présenté avec ce certificat, lu par
le resource server depuis le contexte TLS ou les en-têtes du proxy de
terminaison.

Quand le client émetteur a enregistré ``userinfo_signed_response_alg``
(OIDC Core 1.0 §5.3.1), la réponse réussie est un JWT signé RS256 servi
en ``application/jwt`` (§5.3.2) portant ``iss`` / ``aud`` / ``iat`` —
sinon elle reste un JSON ``application/json`` non signé.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.application.claims_request import (
    allowed_scope_claims,
    requested_userinfo_claims,
)
from puridentityserver.application.identity_assurance import (
    VERIFIED_CLAIMS_MEMBER,
    IdentityAssuranceUseCase,
    verified_claims_request_from_payload,
)
from puridentityserver.application.tls_binding import certificate_binding_error
from puridentityserver.domain.authorization import Client, ClientCertificate
from puridentityserver.domain.dpop import access_token_hash
from puridentityserver.domain.jwks import USERINFO_SIGNING_ALGORITHMS, JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.domain.subjects import display_subject
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.readers import (
    ClientReader,
    IdentityResourceReader,
)
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)

_DPOP_CHALLENGE_INVALID = 'DPoP error="invalid_token"'


@dataclass(frozen=True, slots=True)
class UserInfoConfig:
    """Paramètres de l'endpoint UserInfo."""

    issuer: str
    userinfo_endpoint: str = ""
    subject_seed: str = ""


@dataclass(frozen=True, slots=True)
class UserInfoRequest:
    """Requête UserInfo : jeton présenté via ``Authorization`` (ou corps form).

    ``auth_scheme`` reprend le scheme employé (``bearer``/``dpop``) ;
    ``dpop_proof``, ``htu`` et ``htm`` portent la preuve RFC 9449 et le
    contexte HTTP qu'elle doit autoriser (§7.1) ; ``tls_certificate``
    porte le certificat client mTLS présenté (RFC 8705 §3.3), lu par le
    routeur depuis le contexte TLS ou les en-têtes du proxy.
    """

    access_token: str
    auth_scheme: str = "bearer"
    dpop_proof: str = ""
    htu: str = ""
    htm: str = "GET"
    tls_certificate: ClientCertificate | None = None


@dataclass(frozen=True, slots=True)
class UserInfoResponse:
    """Claims utilisateur renvoyés au client, filtrés par scopes accordés.

    ``signed_jwt`` porte la réponse sérialisée en JWT signé
    (``application/jwt``, OIDC Core 1.0 §5.3.2) quand le client émetteur
    a enregistré ``userinfo_signed_response_alg`` ; ``""`` = réponse
    JSON classique.
    """

    claims: dict[str, object]
    signed_jwt: str = ""


@dataclass(frozen=True, slots=True)
class UserInfoError:
    """Erreur UserInfo (RFC 6750 §3).

    ``challenge`` porte la valeur complète de l'en-tête
    ``WWW-Authenticate`` quand elle s'écarte du ``Bearer`` par défaut
    (challenge ``DPoP`` pour un jeton lié, RFC 9449 §7.2).
    """

    error: str
    error_description: str = ""
    challenge: str = ""


class UserInfoUseCase:
    """Valide le token puis résout et filtre les claims de l'utilisateur.

    Le claim ``sub`` est toujours renvoyé ; les autres claims ne sont
    exposés que si le scope correspondant a été accordé au jeton
    (``profile`` → nom/prénom…, ``email`` → email, ``phone`` →
    téléphone, ``address`` → adresse).
    """

    def __init__(
        self,
        config: UserInfoConfig,
        token_manager: TokenManager,
        claims_provider: ClaimsProvider,
        revoked_token_repository: RevokedTokenRepository,
        identity_resources: IdentityResourceReader | None = None,
        *,
        dpop: DpopProofValidator | None = None,
        clients: ClientReader | None = None,
        identity_assurance: IdentityAssuranceUseCase | None = None,
    ) -> None:
        """Injection config, validateur, fournisseur, denylist, registre et DPoP.

        ``dpop`` (RFC 9449) vérifie les preuves présentées au userinfo ;
        sans injection, un access token lié (``cnf.jkt``) est toujours
        rejeté — aucun lien ne pouvant être prouvé sans validateur.
        ``clients`` recharge le client émetteur du jeton (claim privé
        ``client_id``) pour dériver la ``sub`` affichée (OIDC Core 1.0
        §8.1, ESID 1.0 §4) et résoudre sa ``userinfo_signed_response_alg``
        (§5.3.1) : sans injection, la ``sub`` du jeton est rendue telle
        quelle (client ``public``) et la réponse jamais signée.
        ``identity_assurance`` résout les ``verified_claims`` (OpenID
        Identity Assurance 1.0) : sans injection, le membre n'est jamais
        rendu.
        """
        self._config = config
        self._token_manager = token_manager
        self._claims_provider = claims_provider
        self._blacklist = revoked_token_repository
        self._identity_resources = identity_resources
        self._dpop = dpop
        self._clients = clients
        self._identity_assurance = identity_assurance

    async def execute(self, request: UserInfoRequest) -> UserInfoResponse | UserInfoError:
        """Traite la requête et retourne les claims (signés si demandés) ou une erreur."""
        claims = await self._token_manager.validate_access_token(
            token=request.access_token, issuer=self._config.issuer
        )
        if claims is None:
            return UserInfoError(
                error="invalid_token",
                error_description="Access token invalide, expiré ou de l'émetteur inattendu",
            )

        if await self._blacklist.is_revoked(token_hash(request.access_token)):
            return UserInfoError(error="invalid_token", error_description="Access token révoqué")

        certificate_error = certificate_binding_error(claims, request.tls_certificate)
        if certificate_error:
            return UserInfoError(error="invalid_token", error_description=certificate_error)

        binding_error = await self._validate_dpop_binding(request, claims)
        if binding_error is not None:
            return binding_error

        subject = claims.get("sub")
        if subject is None:
            return UserInfoError(error="invalid_token", error_description="Claim 'sub' manquante")

        allowed = await self._allowed_claims(str(claims.get("scope", "")))
        allowed |= requested_userinfo_claims(claims.get("claims"))
        user_claims = await self._claims_provider.get_claims(str(subject))
        client = await self._emitting_client(claims)
        rendered = {name: value for name, value in user_claims.claims.items() if name in allowed}
        # Le membre `verified_claims` est rendu depuis sa version résolue
        # (identité assurance) : le profil brut du user store ne doit jamais
        # être servi tel quel.
        rendered.pop(VERIFIED_CLAIMS_MEMBER, None)
        verified_claims = await self._verified_claims(claims, str(subject))
        if verified_claims is not None:
            rendered[VERIFIED_CLAIMS_MEMBER] = verified_claims
        response = UserInfoResponse(
            claims={
                "sub": self._displayed_sub(client, str(subject), claims),
                **rendered,
            }
        )
        return await self._sign_response(client, response)

    async def _verified_claims(
        self, claims: dict[str, object], subject: str
    ) -> dict[str, object] | None:
        """Membre `verified_claims` résolu (identité assurance, spec IDA 1.0).

        La demande rejouée est celle mémorisée dans l'access_token (le
        ``/userinfo`` n'a pas accès au paramètre ``claims`` d'origine).
        """
        if self._identity_assurance is None:
            return None
        request = verified_claims_request_from_payload(claims.get("claims"))
        if request is None:
            return None
        return await self._identity_assurance.resolve(request, subject)

    async def _emitting_client(self, claims: dict[str, object]) -> Client | None:
        """Client émetteur du jeton lu dans le claim privé ``client_id``.

        ``None`` sans ``client_id`` ou sans registre injecté : le sujet
        est alors rendu tel quel et la réponse jamais signée.
        """
        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id or self._clients is None:
            return None
        return await self._clients.find_by_id(client_id)

    def _displayed_sub(self, client: Client | None, subject: str, claims: dict[str, object]) -> str:
        """``sub`` à rendre : dérivée pour le client émetteur (§8.1), telle quelle sinon.

        ``subject_material`` (claim privé ephemeral) reprend la matière
        posée à l'émission pour reproduire exactement la ``sub`` de
        l'``id_token`` — le profil, lui, est toujours résolu sur le
        sujet réel.
        """
        if client is None:
            return subject
        material = claims.get("subject_material")
        return display_subject(
            client,
            subject,
            material=material if isinstance(material, str) else "",
            seed=self._config.subject_seed,
        )

    async def _sign_response(
        self, client: Client | None, response: UserInfoResponse
    ) -> UserInfoResponse:
        """Signe la réponse en JWT ``application/jwt`` si le client l'a enregistrée (§5.3.2).

        :func:`userinfo_signing_alg` n'oppose qu'un algorithme publié par
        l'OP (``userinfo_signing_alg_values_supported``) : sans
        déclaration, la réponse reste le JSON sérialisé. Sinon elle
        devient un JWT portant ``iss``, ``aud`` (``client_id``) et
        ``iat`` en plus des claims, vérifiable sur le ``jwks_uri``.
        """
        if client is None:
            return response
        algorithm = userinfo_signing_alg(client)
        if not algorithm:
            return response
        signed_jwt = await self._token_manager.create_userinfo_jwt(
            issuer=self._config.issuer,
            audience=client.client_id,
            algorithm=JWTAlgorithm(algorithm),
            claims=response.claims,
        )
        return UserInfoResponse(claims=response.claims, signed_jwt=signed_jwt)

    async def _validate_dpop_binding(
        self, request: UserInfoRequest, claims: dict[str, object]
    ) -> UserInfoError | None:
        """Contrôle le scheme employé pour un access token lié (RFC 9449 §7.1-7.2).

        Un jeton lié (``cnf.jkt``) exige le scheme ``DPoP`` et une preuve
        dont l'empreinte correspond au lien, liée au jeton présenté par
        ``ath`` — le scheme ``Bearer`` est rejeté (§7.2). Un jeton non lié
        reste un jeton porteur : son usage n'est pas restreint. ``None`` :
        la requête peut continuer.
        """
        bound_jkt = _bound_jkt(claims)
        if not bound_jkt:
            return None
        if request.auth_scheme != "dpop":
            return UserInfoError(
                error="invalid_token",
                error_description="Jeton lié à une clé DPoP : scheme 'DPoP' exigé (RFC 9449 §7.2)",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        if self._dpop is None:
            return UserInfoError(
                error="invalid_token",
                error_description="Validation DPoP indisponible : jeton lié refusé",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        if not request.dpop_proof:
            return UserInfoError(
                error="invalid_token",
                error_description="Preuve DPoP requise pour ce jeton (RFC 9449 §7.1)",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        proof = await self._dpop.validate(
            proof=request.dpop_proof,
            htu=request.htu,
            method=request.htm,
            ath=access_token_hash(request.access_token),
        )
        if isinstance(proof, DpopValidationError):
            return UserInfoError(
                error="invalid_dpop_proof",
                error_description=proof.error_description,
                challenge='DPoP error="invalid_dpop_proof"',
            )
        if proof.jkt != bound_jkt:
            return UserInfoError(
                error="invalid_dpop_proof",
                error_description="Preuve DPoP sans la clé liée au jeton (RFC 9449 §7.2)",
                challenge='DPoP error="invalid_dpop_proof"',
            )
        return None

    async def _allowed_claims(self, scope: str) -> set[str]:
        """Claims autorisés par le scope accordé, dérivés des IdentityResources.

        Délégué à ``allowed_scope_claims`` (source partagée avec l'id_token
        de ``/authorize``) : chaque scope nommé dans ``scope`` (séparé par
        des espaces, RFC 6749 §3.3) est mis en correspondance avec une
        resource du registre — ses claims deviennent accessibles. ``sub``
        est toujours autorisé (claim réservé d'OpenID Connect). Les claims
        du member ``userinfo`` du paramètre ``claims`` (OIDC Core 1.0 §5.5),
        lus dans le payload de l'access_token, élargissent ensuite cet
        ensemble.
        """
        return await allowed_scope_claims(scope, self._identity_resources)


def userinfo_signing_alg(client: Client) -> str:
    """Algorithme de signature de la réponse UserInfo du client, sinon ``""``.

    Le ``userinfo_signed_response_alg`` déclaré à l'enregistrement n'est
    retenu que s'il figure parmi ``userinfo_signing_alg_values_supported``
    (OIDC Core 1.0 §5.3.1, OIDC Registration 1.0 §2.1) ; toute autre
    valeur rend ``""`` — la réponse reste un JSON non signé.
    """
    if client.userinfo_signed_response_alg not in USERINFO_SIGNING_ALGORITHMS:
        return ""
    return client.userinfo_signed_response_alg


def _bound_jkt(claims: dict[str, object]) -> str:
    """Empreinte liant le jeton à une clé DPoP (claim ``cnf``, RFC 9449 §5.1).

    Retourne la chaîne vide quand le jeton n'est pas lié (claim absente
    ou forme inattendue : un payload corrompu ne peut être un lien valide).
    """
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return ""
    jkt = cnf.get("jkt")
    return jkt if isinstance(jkt, str) else ""
