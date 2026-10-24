"""Cas d'usage : Fédération (OpenID Federation 1.1).

Quatre opérations :

- **publier** l'entity statement de l'OP (``/.well-known/openid-federation``) ;
- **résoudre** la chaîne de confiance d'une entité (le RP fédéré) jusqu'à une
  ancre de confiance configurée, en vérifiant chaque statement au fil de
  l'eau (spec §10.1, §10.2) ;
- **enregistrer** un RP par enregistrement explicite (§12.2) : l'entity
  configuration reçue est validée, ancrée, et la réponse signée ;
- **attester ses subordonnés** (fetch, §8.1 ; list, §8.2) et **résoudre une
  chaîne à la demande** (resolve, §8.3) : l'OP joue le supérieur des entités
  fédérées qu'il a enregistrées.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from puridentityserver.application.discovery import DiscoveryUseCase
from puridentityserver.domain.authorization import Client, TokenEndpointAuthMethod
from puridentityserver.domain.federation import (
    EXPLICIT_REGISTRATION_RESPONSE_TYP,
    RESOLVE_RESPONSE_TYP,
    EntityStatement,
    FederationError,
    FederationRegistrationError,
    TrustChain,
    derive_client,
    parse_entity_statement,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.federation import (
    FederationEntityFetcher,
    FederationKeyProvider,
    FederationMetadataProvider,
    FederationSubordinateSource,
    FederationTokenManager,
)

#: Suffixe de découverte de l'entity configuration (spec §9.1).
ENTITY_CONFIGURATION_PATH = "/.well-known/openid-federation"

#: Chemin du endpoint de subordinate statement (spec §8.1).
FETCH_PATH = "/federation/fetch"

#: Chemin du endpoint de liste des subordonnés immédiats (spec §8.2).
LIST_PATH = "/federation/list"

#: Chemin du endpoint de résolution de chaîne (spec §8.3).
RESOLVE_PATH = "/federation/resolve"

#: Tolérance d'horloge sur ``iat``/``exp`` (spec §3.2, étapes 7 et 8).
_CLOCK_SKEW_SECONDS = 300


@dataclass(frozen=True, slots=True)
class FederationConfig:
    """Configuration de la Fédération côté OP.

    ``entity_identifier`` est l'Entity Identifier de l'OP : il doit être une
    URL ``https`` sans query ni fragment (spec §1.2). ``trust_anchors``
    liste les ancres de confiance acceptées : une liste vide autorise la
    résolution vers n'importe quelle ancre (développement uniquement).
    """

    entity_identifier: str
    trust_anchors: tuple[str, ...] = ()
    statement_ttl_seconds: int = 3600
    algorithm: JWTAlgorithm = JWTAlgorithm.ES256
    registration_types: tuple[str, ...] = ("automatic", "explicit")


class DiscoveryFederationMetadataProvider:
    """Metadata de l'OP publiées dans l'entity statement (spec §5.2).

    L'entity statement porte les metadata de l'OP sous le type d'entité
    ``openid_provider`` — les metadata de discovery, telles que publiées par
    l'OP (§5.1) — et les endpoints de la fédération sous ``federation_entity``
    (§5.1.1) : publiés dans l'entity configuration, ils sont disponibles avant
    toute résolution de chaîne (§8.1, §8.2, §8.3).
    """

    def __init__(self, discovery: DiscoveryUseCase, base_url: str) -> None:
        """Injection du cas d'usage de discovery et de l'URL de base de l'OP."""
        self._discovery = discovery
        self._base_url = base_url.rstrip("/")

    async def federation_metadata(self) -> Mapping[str, Any]:
        """Retourne les metadata de l'OP par type d'entité."""
        return {
            "openid_provider": await self._discovery.execute(),
            "federation_entity": {
                "federation_fetch_endpoint": f"{self._base_url}{FETCH_PATH}",
                "federation_list_endpoint": f"{self._base_url}{LIST_PATH}",
                "federation_resolve_endpoint": f"{self._base_url}{RESOLVE_PATH}",
            },
        }


@dataclass(slots=True)
class FederationUseCase:
    """Publie l'entity statement de l'OP et résout les chaînes de confiance."""

    config: FederationConfig
    token_manager: FederationTokenManager
    key_provider: FederationKeyProvider
    fetcher: FederationEntityFetcher
    metadata_provider: FederationMetadataProvider | None = None
    subordinate_source: FederationSubordinateSource | None = None

    async def entity_statement(self) -> str:
        """Construit et signe l'entity statement de l'OP (spec §9.2).

        Le statement est **auto-signé** : ``iss`` et ``sub`` valent l'Entity
        Identifier de l'OP et le claim ``jwks`` porte ses propres clés de
        signature (spec §3.1.1).
        """
        metadata = await self._metadata()
        claims: dict[str, Any] = {
            "iss": self.config.entity_identifier,
            "sub": self.config.entity_identifier,
            "iat": _now_timestamp(),
            "exp": int(
                (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=self.config.statement_ttl_seconds)
                ).timestamp()
            ),
            "jwks": await self.key_provider.public_jwks(),
        }
        if metadata:
            claims["metadata"] = metadata
        if self.config.trust_anchors:
            claims["authority_hints"] = list(self.config.trust_anchors)
        return await self.token_manager.sign_entity_statement(
            algorithm=self.config.algorithm,
            claims=claims,
            key_id="",
        )

    async def resolve_trust_chain(self, subject: str, trust_anchor: str) -> TrustChain | None:
        """Résout la chaîne de confiance de ``subject`` jusqu'à l'ancre (spec §10.1).

        La résolution part de l'entity configuration du sujet et remonte ses
        ``authority_hints`` ; chaque supérieur est validé (signature contre
        ses propres clés) et fournit le *subordinate statement* attestant
        l'entité. Retourne ``None`` si la chaîne est incomplète, expirée,
        mal signée ou menant à une ancre non configurée.
        """
        fetched = await self._fetch_configuration(subject)
        if fetched is None:
            return None
        entity_configuration, token = fetched
        return await self.resolve_chain_from(entity_configuration, trust_anchor, token)

    async def resolve_chain_from(
        self, statement: EntityStatement, trust_anchor: str, statement_token: str
    ) -> TrustChain | None:
        """Résout la chaîne à partir d'un entity configuration déjà validé.

        ``statement_token`` est le JWT de cet entity configuration (reçu du
        RP pour l'enregistrement explicite, spec §12.2.2 étape 3, ou fetché
        pour la résolution standard) : sa signature est re-vérifiée contre les
        clés attestées du sujet (§10.2, étape 6). Retourne ``None`` si la
        chaîne est incomplète, expirée, mal signée ou si son ancre échappe à
        ``config.trust_anchors``.
        """
        subject = statement.subject
        chain: list[EntityStatement] = [statement]
        tokens: list[str] = [statement_token]
        current = statement
        seen = {subject}
        while not self._is_trust_anchor(current, trust_anchor):
            superior = await self._next_superior(current, seen)
            if superior is None:
                return None
            subordinate = await self._fetch_subordinate_statement(superior, subject)
            if subordinate is None:
                return None
            chain.append(subordinate[0])
            tokens.append(subordinate[1])
            current = superior
        # Sans ancre explicite, l'ancre est le supérieur atteint (spec §10.1) :
        # son entity configuration couronne déjà la chaîne. La liste
        # `trust_anchors` est le périmètre de confiance de l'OP (vide =
        # n'importe quelle ancre, réservé au développement) : contrôle avant
        # le re-fetch, inutile si l'ancre est rejetée.
        anchor_identifier = trust_anchor or current.issuer
        if self.config.trust_anchors and anchor_identifier not in self.config.trust_anchors:
            return None
        fetched = await self._fetch_configuration(anchor_identifier)
        if fetched is None:
            return None
        # Étape 6 (§10.2) : l'EC du sujet doit être signé par une des clés que
        # son supérieur lui a attestées dans le subordinate statement — c'est
        # ce lien qui interdit à un tiers de se substituer au sujet.
        if len(chain) >= 2 and not self._subject_attested_keys(statement_token, chain):
            return None
        chain.append(fetched[0])
        tokens.append(fetched[1])
        return TrustChain(statements=tuple(chain), tokens=tuple(tokens))

    def _subject_attested_keys(self, token: str, chain: list[EntityStatement]) -> bool:
        """Vérifie la liaison EC du sujet → subordinate statement (§10.2, étape 6).

        La signature de l'entity configuration du sujet (``chain[0]``) doit
        être vérifiable avec les clés que son supérieur a publiées sur lui
        dans le *subordinate statement* (``chain[1]``, claim ``jwks``).
        """
        subject = chain[0]
        attested = self.token_manager.verify_entity_statement(
            token=token,
            jwks=chain[1].jwks,
            issuer=subject.issuer,
            subject=subject.subject,
        )
        return attested is not None

    async def explicit_register(self, entity_configuration: str) -> str:
        """Traite une demande d'enregistrement explicite (spec §12.2).

        Le RP soumet son entity configuration (§12.2.1) : l'OP vérifie le JWT
        (``typ``, signature, ``aud`` = son Entity Identifier), résout la chaîne
        de confiance à partir des ``authority_hints`` reçus, dérive le client
        de ses metadata résolues puis renvoie la réponse signée (§12.2.3,
        ``typ = explicit-registration-response+jwt``). Le client n'est **pas**
        persisté : il est re-dérivé à chaque demande, la durée de vie étant
        bornée par l'expiration de la chaîne (§12.3).

        Lève:
            FederationRegistrationError: si la demande est refusée avec le
                code ``invalid_client``, ``invalid_trust_chain`` ou
                ``invalid_client_metadata`` (§12.2.4).
        """
        statement = self._validated_registration_statement(entity_configuration)
        chain = await self.resolve_chain_from(statement, "", entity_configuration)
        if chain is None:
            raise FederationRegistrationError(
                "invalid_trust_chain", "Chaîne de confiance du RP non résolue"
            )
        resolved = chain.resolved_metadata()
        client = derive_client(statement.subject, resolved)
        if client is None:
            raise FederationRegistrationError(
                "invalid_client_metadata",
                "metadata openid_relying_party incomplètes (redirect_uris et clés "
                "requises : jwks inline ou jwks_uri)",
            )
        claims = self._registration_claims(statement, chain, resolved, client)
        return await self.token_manager.sign_entity_statement(
            algorithm=self.config.algorithm,
            claims=claims,
            key_id="",
            typ=EXPLICIT_REGISTRATION_RESPONSE_TYP,
        )

    def _validated_registration_statement(self, token: str) -> EntityStatement:
        """Valide l'entity configuration soumise en enregistrement explicite.

        Toutes les règles de validation d'entity statement s'appliquent
        (§3.2), plus l'``aud`` qui doit nommer exclusivement l'Entity
        Identifier de l'OP (§12.2.1) et les claims exigés de la demande
        (``jwks`` et ``authority_hints``).
        """
        unverified = self.token_manager.unverified_claims(token)
        if unverified is None:
            raise FederationRegistrationError("invalid_client", "Entity configuration illisible")
        issuer = unverified.get("iss")
        subject = unverified.get("sub")
        if not isinstance(issuer, str) or not issuer or issuer != subject:
            raise FederationRegistrationError(
                "invalid_client", "'iss' et 'sub' doivent valoir l'Entity Identifier du RP"
            )
        jwks = unverified.get("jwks")
        if not isinstance(jwks, Mapping):
            raise FederationRegistrationError("invalid_client", "'jwks' du RP requis (§12.2.1)")
        verified = self.token_manager.verify_entity_statement(
            token=token, jwks=jwks, issuer=issuer, subject=subject
        )
        if verified is None:
            raise FederationRegistrationError(
                "invalid_client",
                "Signature, typ ou expiration de l'entity configuration invalides",
            )
        if not _is_single_audience(verified.get("aud"), self.config.entity_identifier):
            raise FederationRegistrationError(
                "invalid_client", "'aud' doit valoir l'Entity Identifier de l'OP (§12.2.1)"
            )
        hints = verified.get("authority_hints")
        if not isinstance(hints, list) or not hints:
            raise FederationRegistrationError(
                "invalid_trust_chain",
                "'authority_hints' requis pour résoudre la chaîne (§12.2.1)",
            )
        try:
            return parse_entity_statement(verified)
        except FederationError as error:
            raise FederationRegistrationError("invalid_client", str(error)) from error

    def _registration_claims(
        self,
        statement: EntityStatement,
        chain: TrustChain,
        resolved: Mapping[str, Any],
        client: Client,
    ) -> dict[str, Any]:
        """Claims de la réponse d'enregistrement explicite (spec §12.2.3).

        ``exp`` ne dépasse jamais l'expiration de la chaîne (§12.3),
        ``trust_anchor`` nomme l'ancre sélectionnée, ``authority_hints``
        l'immédiat supérieur du RP, et les metadata enregistrées portent le
        ``client_id`` provisionné et la méthode d'authentification effective.
        """
        metadata = resolved.get("openid_relying_party")
        registered: dict[str, Any] = dict(metadata) if isinstance(metadata, Mapping) else {}
        registered["client_id"] = client.client_id
        # Fédération : les clés du RP servent à l'authentification client
        # (§12.1.4), donc `private_key_jwt` — la méthode déclarée par le RP
        # n'est pas retenue.
        method = client.token_endpoint_auth_method or TokenEndpointAuthMethod.PRIVATE_KEY_JWT
        registered["token_endpoint_auth_method"] = method.value
        return {
            "iss": self.config.entity_identifier,
            "sub": statement.subject,
            "iat": _now_timestamp(),
            "exp": _chain_expiration(chain),
            "aud": statement.subject,
            "trust_anchor": chain.trust_anchor.issuer,
            "authority_hints": [_immediate_superior(chain)],
            "metadata": {"openid_relying_party": registered},
            # Copie verbatim du `jwks` de l'EC reçu (§12.2.3).
            "jwks": dict(statement.jwks),
        }

    async def subordinate_statement(self, sub: str) -> str | None:
        """Émet le subordinate statement de l'entité ``sub`` (spec §8.1).

        L'OP atteste ses clients enregistrés qui sont des entités fédérées
        (``client_id`` = Entity Identifier, ``jwks`` inline) : le statement
        porte leurs clés et les metadata ``openid_relying_party`` qu'il vaut
        (redirect URI et clés). Retourne ``None`` si ``sub`` n'est pas un
        subordonné immédiat.
        """
        if self.subordinate_source is None:
            return None
        for client in await self.subordinate_source.subordinates():
            if client.client_id == sub and _is_federated_subordinate(client):
                return await self._sign_subordinate(client)
        return None

    async def subordinate_identifiers(self) -> list[str]:
        """Entity Identifier des subordonnés immédiats de l'OP (spec §8.2)."""
        if self.subordinate_source is None:
            return []
        clients = await self.subordinate_source.subordinates()
        return sorted(client.client_id for client in clients if _is_federated_subordinate(client))

    async def resolve_entity(self, subject: str, trust_anchor: str) -> str | None:
        """Signe la réponse de résolution de la chaîne de ``subject`` (§8.3).

        La réponse porte les metadata résolues du sujet et les JWT de sa
        chaîne de confiance (claim ``trust_chain``) ; ``exp`` ne dépasse
        jamais l'expiration de la chaîne (§8.3.2). Retourne ``None`` si la
        chaîne n'est pas résoluble ou si ``trust_anchor`` échappe au
        périmètre configuré (``config.trust_anchors``).
        """
        chain = await self.resolve_trust_chain(subject, trust_anchor)
        if chain is None or not chain.tokens:
            return None
        claims: dict[str, Any] = {
            "iss": self.config.entity_identifier,
            "sub": subject,
            "iat": _now_timestamp(),
            "exp": _chain_expiration(chain),
            "metadata": chain.resolved_metadata(),
            "trust_chain": list(chain.tokens),
        }
        return await self.token_manager.sign_entity_statement(
            algorithm=self.config.algorithm,
            claims=claims,
            key_id="",
            typ=RESOLVE_RESPONSE_TYP,
        )

    async def _sign_subordinate(self, client: Client) -> str:
        """Signe le subordinate statement d'un client-entité (spec §3.1.2).

        Le ``jwks`` porte les clés du sujet (attestées) et la metadata
        ``openid_relying_party`` les répète pour les résolveurs ; le
        statement n'a pas d'``authority_hints`` (§3.1.2).
        """
        issued_at = _now_timestamp()
        jwks = {"keys": [dict(key) for key in client.jwks]}
        claims: dict[str, Any] = {
            "iss": self.config.entity_identifier,
            "sub": client.client_id,
            "iat": issued_at,
            "exp": issued_at + self.config.statement_ttl_seconds,
            "jwks": jwks,
            "metadata": {
                "openid_relying_party": {
                    "redirect_uris": sorted(client.redirect_uris),
                    "jwks": jwks,
                }
            },
        }
        return await self.token_manager.sign_entity_statement(
            algorithm=self.config.algorithm, claims=claims, key_id=""
        )

    async def _metadata(self) -> dict[str, Any]:
        """Metadata de l'OP publiées dans l'entity statement."""
        if self.metadata_provider is None:
            return {}
        metadata = await self.metadata_provider.federation_metadata()
        return dict(metadata)

    def _is_trust_anchor(self, statement: EntityStatement, trust_anchor: str) -> bool:
        """Indique si le statement est l'ancre de confiance visée.

        Sans ancre explicite, la résolution s'arrête sur une ancre configurée
        (``config.trust_anchors``) ou sur une entité auto-racine — cette
        dernière n'est acceptée que si aucune ancre n'est configurée
        (développement), le contrôle final de ``resolve_trust_chain`` rejettant
        sinon la chaîne.
        """
        if not statement.is_self_signed:
            return False
        if trust_anchor:
            return statement.issuer == trust_anchor
        if statement.issuer in self.config.trust_anchors:
            return True
        return not statement.authority_hints

    async def _next_superior(
        self, statement: EntityStatement, seen: set[str]
    ) -> EntityStatement | None:
        """Entity configuration du supérieur (premier `authority_hints` valide)."""
        for hint in statement.authority_hints:
            if hint in seen:
                continue
            fetched = await self._fetch_configuration(hint)
            if fetched is not None:
                seen.add(hint)
                return fetched[0]
        return None

    async def _fetch_configuration(
        self, entity_identifier: str
    ) -> tuple[EntityStatement, str] | None:
        """Lit et valide l'entity configuration d'une entité (spec §9, §10.2).

        L'entity configuration est **auto-signée** : sa signature se vérifie
        contre le claim ``jwks`` qu'elle porte elle-même (spec §3.2, étape 10).
        Le JWT brut est retourné avec le statement : il sert à la liaison de
        la chaîne (§10.2, étape 6 — signature de l'EC vérifiée contre les clés
        attestées par le supérieur).
        """
        token = await self.fetcher.fetch_entity_statement(
            f"{entity_identifier.rstrip('/')}{ENTITY_CONFIGURATION_PATH}"
        )
        if token is None:
            return None
        unverified = self.token_manager.unverified_claims(token)
        if unverified is None:
            return None
        jwks = unverified.get("jwks")
        if not isinstance(jwks, Mapping):
            return None
        claims = self.token_manager.verify_entity_statement(
            token=token,
            jwks=jwks,
            issuer=entity_identifier,
            subject=entity_identifier,
        )
        if claims is None:
            return None
        try:
            return parse_entity_statement(claims), token
        except FederationError:
            return None

    async def _fetch_subordinate_statement(
        self, superior: EntityStatement, subject: str
    ) -> tuple[EntityStatement, str] | None:
        """Lit le subordinate statement émis par le supérieur (spec §8.1).

        Le supérieur publie un endpoint ``federation_fetch_endpoint`` : il
        renvoie le statement attestant l'entité subordonnée, signé par le
        supérieur. Le JWT brut est retourné avec le statement (§10.2,
        étape 6 — liaison du statement au token de l'EC du sujet).
        """
        endpoint = _federation_endpoint(superior, "federation_fetch_endpoint")
        if not endpoint:
            return None
        separator = "&" if "?" in endpoint else "?"
        token = await self.fetcher.fetch_entity_statement(f"{endpoint}{separator}sub={subject}")
        if token is None:
            return None
        claims = self.token_manager.verify_entity_statement(
            token=token,
            jwks=superior.jwks,
            issuer=superior.issuer,
            subject=subject,
        )
        if claims is None:
            return None
        try:
            return parse_entity_statement(claims), token
        except FederationError:
            return None


def _federation_endpoint(statement: EntityStatement, name: str) -> str:
    """URL d'un endpoint de l'entité `federation_entity` (spec §5.2.2)."""
    metadata = statement.metadata.get("federation_entity")
    if not isinstance(metadata, Mapping):
        return ""
    value = metadata.get(name)
    return value if isinstance(value, str) else ""


def _chain_expiration(chain: TrustChain) -> int:
    """Expiration d'une chaîne de confiance, en secondes (spec §10.4, §12.3).

    Une registration ne peut jamais excéder la durée de vie du statement le
    plus court de la chaîne.
    """
    return min(int(statement.expires_at.timestamp()) for statement in chain.statements)


def _now_timestamp() -> int:
    """Horodatage courant en secondes depuis l'époque (RFC 7519)."""
    return int(datetime.now(timezone.utc).timestamp())


def _is_federated_subordinate(client: Client) -> bool:
    """Indique si un client enregistré est attestable comme entité fédérée.

    Un client devient subordonné immédiat de l'OP (spec §8.1) s'il est
    identifié par un Entity Identifier (URL ``https`` sans query ni fragment,
    §1.2) et porte ses clés de fédération (``jwks`` inline).
    """
    return _is_entity_identifier(client.client_id) and bool(client.jwks)


def _is_entity_identifier(value: str) -> bool:
    """Indique si ``value`` est une URL https sans query ni fragment (§1.2)."""
    return value.startswith("https://") and "?" not in value and "#" not in value


def _immediate_superior(chain: TrustChain) -> str:
    """Entity Identifier de l'immédiat supérieur du RP dans la chaîne (§12.2.3)."""
    if len(chain.statements) >= 2:
        return chain.statements[1].issuer
    return chain.trust_anchor.issuer


def _is_single_audience(audience: object, expected: str) -> bool:
    """Indique si ``aud`` nomme exclusivement l'Entity Identifier ``expected``.

    La spec §12.2.1 n'admet aucune autre valeur dans l'audience.
    """
    if isinstance(audience, str):
        return audience == expected
    if isinstance(audience, list):
        return len(audience) == 1 and audience[0] == expected
    return False
