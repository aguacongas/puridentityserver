"""Tests des request objects (RFC 9101) et de l'id_token non signé (JWA §6).

Couvre le resolver (priorité des claims, refus, ``request_uri`` poussé,
déchiffrement JWE — OIDC Core 1.0 §10.1, issue #204), le fetcher du
document (destinations filtrées, type MIME, redirections) et
l'observabilité HTTP de ``/authorize`` : pages d'erreur 400 et émission
d'un code pour une demande portée par un request object.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.request_object import (
    RequestObjectConfig,
    RequestObjectError,
    RequestObjectResolver,
    is_pushed_request_uri,
)
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.jwe import JWEEncryptionMethod, JWEKeyManagementAlgorithm
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.infrastructure.jwe import JWERequestObjectDecrypter, encrypt_compact
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.persistence.memory.dpop_replays import (
    InMemoryDpopReplayRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.request_object import (
    HTTPRequestObjectFetcher,
    loopback_bind,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.signed_request_object import (
    PyJWTSignedRequestObjectVerifier,
)
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_CLIENT = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}
_UNSIGNED_CLIENT = {
    **_CLIENT,
    "client_id": "unsigned-app",
    "id_token_signed_response_alg": "none",
}


@dataclass
class _DocumentState:
    """État partagé du serveur local de documents ``request_uri``."""

    paths: list[str] = field(default_factory=list)
    document: str = ""
    status: int = 200
    content_type: str = "application/jwt"
    location: str = ""


class _StubFetcher:
    """Port ``RequestObjectFetcher`` de test : renvoie un document fixe."""

    def __init__(self, document: str | None) -> None:
        """Prépare la réponse du fetch et enregistre les URL appelées."""
        self.document = document
        self.urls: list[str] = []

    async def fetch(self, url: str) -> str | None:
        """Retourne le document prédéfini en mémorisant l'URL demandée."""
        self.urls.append(url)
        return self.document


def _segment(value: object) -> str:
    """Encode un objet JSON en segment base64url non padding (RFC 7515 §2)."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _request_object(claims: dict[str, object], header: object = None) -> str:
    """Construit un JWT compact non signé (``header.payload.``)."""
    head = {"alg": "none"} if header is None else header
    return f"{_segment(head)}.{_segment(claims)}."


def _resolver(document: str | None) -> tuple[RequestObjectResolver, _StubFetcher]:
    """Resolver de test monté sur un fetcher factice."""
    fetcher = _StubFetcher(document)
    return RequestObjectResolver(RequestObjectConfig(), fetcher), fetcher


_JAR_KID = "standard-jar-test-key"


def _jar_key(algorithm: str = "RS256") -> tuple[RSAPrivateKey, tuple[dict[str, object], ...]]:
    """Paire RSA de test et JWKS embarqué (``kid``/``alg``) pour un JAR."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    jwks = (
        {
            "kty": "RSA",
            "use": "sig",
            "kid": _JAR_KID,
            "alg": algorithm,
            "n": n.rstrip(b"=").decode("ascii"),
            "e": e.rstrip(b"=").decode("ascii"),
        },
    )
    return private, jwks


def _signed_jar(
    private_key: RSAPrivateKey,
    *,
    claims: dict[str, object] | None = None,
    algorithm: str = "RS256",
) -> str:
    """Signe un request object (paramètres de demande + ``iss``/``aud``, §10.1)."""
    payload: dict[str, object] = {"iss": "web-app", "aud": _ISSUER, **_base_params()}
    if claims is not None:
        payload.update(claims)
    return str(pyjwt.encode(payload, private_key, algorithm=algorithm, headers={"kid": _JAR_KID}))


def _standard_client(jwks: tuple[dict[str, object], ...]) -> Client:
    """Client standard (non-FAPI) de ``web-app``, avec JWKS embarqués."""
    return Client(
        client_id="web-app",
        redirect_uris=frozenset({"https://app.example/callback"}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        client_type=ClientType.CONFIDENTIAL,
        jwks=jwks,
    )


def _federated_client(jwks: tuple[dict[str, object], ...]) -> Client:
    """Client fédéré de ``web-app`` (marque ``federated``, OpenID Federation §12.1)."""
    return Client(
        client_id="web-app",
        redirect_uris=frozenset({"https://app.example/callback"}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        client_type=ClientType.CONFIDENTIAL,
        jwks=jwks,
        federated=True,
    )


def _jar_resolver(client: Client | None, *, configured: bool = True) -> RequestObjectResolver:
    """Resolver standard avec issuer, registre clients et vérification JWKS."""
    fetcher = _StubFetcher(None)
    clients = InMemoryClientRepository()
    if client is not None:
        asyncio.run(clients.save(client))
    signed = PyJWTSignedRequestObjectVerifier(InMemoryDpopReplayRepository())
    return RequestObjectResolver(
        RequestObjectConfig(issuer=_ISSUER),
        fetcher,
        clients=clients,
        signed=signed if configured else None,
    )


_JAR_KEY, _JAR_JWKS = _jar_key()
_SIGNED_CLIENT = {
    **_CLIENT,
    "client_id": "signed-app",
    "jwks": [dict(key) for key in _JAR_JWKS],
}


def _base_params(**extra: str) -> dict[str, str]:
    """Paramètres d'une demande ``response_type=code`` de référence."""
    params = {
        "response_type": "code",
        "client_id": "web-app",
        "redirect_uri": "https://app.example/callback",
        "scope": "openid profile",
        "state": "state-1",
        "nonce": "nonce-1",
    }
    params.update(extra)
    return params


def run(resolver: RequestObjectResolver, *, session_scope: str = "", **params: str) -> object:
    """Exécute ``resolve`` sur des paramètres donnés, ``session_scope`` cloisonnant le ``jti``."""
    return asyncio.run(resolver.resolve(params, session_scope=session_scope))


def _app() -> FastAPI:
    """Application de test alignée sur la configuration des tests d'autorisation."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT, _UNSIGNED_CLIENT, _SIGNED_CLIENT),
        )
    )


def _s256_challenge(verifier: str) -> str:
    """Défi PKCE S256 d'un ``code_verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
# Resolver : priorité des claims et refus
# --------------------------------------------------------------------------- #


def test_resolve_without_request_object_returns_params_unchanged() -> None:
    resolver, fetcher = _resolver(None)
    params = _base_params()

    resolved = run(resolver, **params)

    assert resolved == params
    assert fetcher.urls == []


def test_request_object_claims_take_precedence_over_query() -> None:
    """Les claims du jeton priment sur la query (OIDC Core 1.0 §6.1).

    C'est le cœur du module ``oidcc-ensure-request-object-with-redirect-uri`` :
    la ``redirect_uri`` du jeton reste valide alors que la query en porte une
    non enregistrée.
    """
    resolver, _fetcher = _resolver(None)
    claims = _base_params(
        redirect_uri="https://app.example/callback",
        state="state-from-jwt",
        nonce="nonce-from-jwt",
    )

    resolved = run(
        resolver,
        **_base_params(redirect_uri="https://app.example/callback_invalid"),
        request=_request_object(claims),
    )

    assert isinstance(resolved, dict)
    assert resolved["redirect_uri"] == "https://app.example/callback"
    assert resolved["state"] == "state-from-jwt"
    assert resolved["nonce"] == "nonce-from-jwt"
    assert "request" not in resolved


def test_client_id_of_query_must_match_the_request_object() -> None:
    """OIDC Core 1.0 §6.1 : ``client_id`` de la query et du jeton doivent coïncider.

    Module federation ``invalid-client-id-in-query-parameters`` (OIDFED
    §12.1.1.1) : un ``client_id`` de transport altéré est ``invalid_request``.
    """
    resolver, _fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(client_id="web-appINVALID"),
        request=_request_object(_base_params()),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request"


def test_request_and_request_uri_are_exclusive() -> None:
    resolver, fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params()),
        request_uri="https://rp.example/requesturi/abc",
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request"
    assert fetcher.urls == []


def test_missing_alg_header_is_accepted_as_unsigned() -> None:
    """Un en-tête sans ``alg`` est un JWT non signé (aucune clé n'y figure)."""
    resolver, _fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params(nonce="nonce-without-alg"), header={}),
    )

    assert isinstance(resolved, dict)
    assert resolved["nonce"] == "nonce-without-alg"


def test_signed_request_object_is_refused_without_client_keys() -> None:
    """Sans registre clients, la signature RS256 n'est pas vérifiable (§10.3)."""
    resolver, _fetcher = _resolver(None)

    resolved = run(
        resolver,
        **_base_params(),
        request=_request_object(_base_params(), header={"alg": "RS256"}),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"
    assert "client inconnu" in resolved.error_description


class TestSignedRequestObjectStandard:
    """Request objects RS256 signés par des clients standards (issue #188)."""

    def test_rs256_request_object_is_verified_and_merged(self) -> None:
        """OIDC Core 1.0 §10.3 : signature vérifiée aux JWKS, claims du jeton primés."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(
            resolver,
            **_base_params(nonce="nonce-transport"),
            request=_signed_jar(key, claims={"nonce": "nonce-from-jar"}),
        )

        assert isinstance(resolved, dict)
        assert resolved["nonce"] == "nonce-from-jar"
        assert resolved["state"] == "state-1"
        assert "request" not in resolved

    def test_rs256_request_object_signed_by_another_key_is_refused(self) -> None:
        """OIDC Core 1.0 §10.3 : signature non vérifiable -> invalid_request_object."""
        _registered, jwks = _jar_key()
        foreign, _foreign_jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(resolver, **_base_params(), request=_signed_jar(foreign))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"

    def test_rs256_request_object_for_unknown_client_is_refused(self) -> None:
        """OIDC Core 1.0 §10.3 : client inconnu, aucune clé à confronter."""
        key, _jwks = _jar_key()
        resolver = _jar_resolver(None)

        resolved = run(resolver, **_base_params(), request=_signed_jar(key))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "client inconnu" in resolved.error_description

    def test_rs256_request_object_with_wrong_iss_is_refused(self) -> None:
        """OIDC Core 1.0 §10.1 : ``iss`` doit valoir le client_id émetteur."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(key, claims={"iss": "intruder"}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "claim iss" in resolved.error_description

    def test_rs256_request_object_with_wrong_aud_is_refused(self) -> None:
        """OIDC Core 1.0 §10.1 : ``aud`` doit valoir l'issuer."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(key, claims={"aud": "https://other.example"}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "claim aud" in resolved.error_description

    def test_rs256_request_object_with_expired_exp_is_refused(self) -> None:
        """RFC 9101 §6.1 : ``exp`` passé, borné nativement sans fenêtre FAPI."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))
        past = int(datetime.now(timezone.utc).timestamp()) - 3600

        resolved = run(resolver, **_base_params(), request=_signed_jar(key, claims={"exp": past}))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "expiré" in resolved.error_description

    def test_unsupported_algorithm_is_refused(self) -> None:
        """Seuls ``none`` et ``RS256`` sont admis pour un client standard."""
        _key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(
            resolver,
            **_base_params(),
            request=_request_object(_base_params(), header={"alg": "HS256"}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "non supporté" in resolved.error_description

    def test_verification_not_configured_is_refused(self) -> None:
        """Sans port de vérification, le JAR RS256 n'est pas servable (invalid_request)."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks), configured=False)

        resolved = run(resolver, **_base_params(), request=_signed_jar(key))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request"
        assert "non configurée" in resolved.error_description

    def test_fapi_client_still_refuses_rs256(self) -> None:
        """FAPI inchangé : seule PS256/ES256 admise (FAPI1-ADV-5.2.2-1)."""
        key, jwks = _jar_key()
        fapi_client = Client(
            client_id="web-app",
            redirect_uris=frozenset({"https://app.example/callback"}),
            scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
            client_type=ClientType.CONFIDENTIAL,
            jwks=jwks,
            fapi_enabled=True,
        )
        resolver = _jar_resolver(fapi_client)

        resolved = run(resolver, **_base_params(), request=_signed_jar(key))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "non admis" in resolved.error_description


class TestFederatedRequestObject:
    """Request objects de clients fédérés (OpenID Federation 1.1 §12.1.1.1)."""

    def test_valid_request_object_with_jti_and_exp_is_accepted(self) -> None:
        """§12.1.1.1 : le profil n'ajoute rien à un request object conforme."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(
                key, claims={"jti": "jti-1", "exp": future, "nonce": "nonce-federation"}
            ),
        )

        assert isinstance(resolved, dict)
        assert resolved["nonce"] == "nonce-federation"

    def test_missing_jti_is_refused(self) -> None:
        """§12.1.1.1 : ``jti`` obligatoire (module invalid-missing-request-object-jti).

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2) et non ``invalid_request_object``.
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(key, claims={"exp": future}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request"
        assert "jti" in resolved.error_description

    def test_missing_exp_is_refused(self) -> None:
        """§12.1.1.1 : ``exp`` obligatoire (module invalid-missing-request-object-exp).

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2).
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(key, claims={"jti": "jti-1"}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request"
        assert "exp" in resolved.error_description

    def test_sub_is_refused(self) -> None:
        """§12.1.1.1 : ``sub`` interdit (module invalid-request-object-sub).

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2).
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300

        resolved = run(
            resolver,
            **_base_params(),
            request=_signed_jar(key, claims={"jti": "jti-1", "exp": future, "sub": "alice"}),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request"
        assert "sub" in resolved.error_description

    def test_replayed_jti_is_refused(self) -> None:
        """§12.1.1.1 : ``jti`` anti-replay (module invalid-duplicate-request-object-jti).

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2).
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300
        document = _signed_jar(key, claims={"jti": "jti-replay", "exp": future})

        first = run(resolver, **_base_params(), request=document)
        second = run(resolver, **_base_params(), request=document)

        assert isinstance(first, dict)
        assert isinstance(second, RequestObjectError)
        assert second.error == "invalid_request"
        assert "déjà présenté" in second.error_description

    def test_same_jti_after_login_in_another_session_is_accepted(self) -> None:
        """Retour de ``/login`` : la re-présentation sous la session créée passe.

        Parcours normal d'un OP : ``/authorize`` → 302 ``/login`` → POST →
        302 vers ``/authorize`` avec le même request object — le ``jti``
        s'inscrit alors sous le namespace de la session créée (§12.1.1.1).
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300
        document = _signed_jar(key, claims={"jti": "jti-login", "exp": future})

        before = run(resolver, **_base_params(), request=document)
        after_login = run(resolver, session_scope="sid-1", **_base_params(), request=document)

        assert isinstance(before, dict)
        assert isinstance(after_login, dict)

    def test_same_jti_replayed_under_the_same_session_is_refused(self) -> None:
        """Le replay reste refusé quand la session navigateur est inchangée.

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2).
        """
        key, jwks = _jar_key()
        resolver = _jar_resolver(_federated_client(jwks))
        future = int(datetime.now(timezone.utc).timestamp()) + 300
        document = _signed_jar(key, claims={"jti": "jti-same-sid", "exp": future})

        first = run(resolver, session_scope="sid-1", **_base_params(), request=document)
        second = run(resolver, session_scope="sid-1", **_base_params(), request=document)

        assert isinstance(first, dict)
        assert isinstance(second, RequestObjectError)
        assert second.error == "invalid_request"

    def test_standard_client_keeps_accepting_a_jar_without_jti(self) -> None:
        """Le profil fédéré ne s'applique qu'aux clients ``federated`` (issue #170)."""
        key, jwks = _jar_key()
        resolver = _jar_resolver(_standard_client(jwks))

        resolved = run(
            resolver,
            **_base_params(nonce="nonce-standard"),
            request=_signed_jar(key, claims={"nonce": "nonce-from-jar"}),
        )

        assert isinstance(resolved, dict)
        assert resolved["nonce"] == "nonce-from-jar"


@pytest.mark.parametrize(
    "document",
    [
        "no-segment-here",
        "only.upto",
        "header.payload.signature",
        "not-base64!.payload.",
        "e30.notjson.",
    ],
    ids=[
        "sans-point",
        "deux-segments-incomplets",
        "signe",
        "en-tete-illisible",
        "claims-illisible",
    ],
)
def test_malformed_request_object_is_refused(document: str) -> None:
    resolver, _fetcher = _resolver(None)

    resolved = run(resolver, **_base_params(), request=document)

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_non_string_claims_are_stringified() -> None:
    """Les claims booléens/nombres/objets passent en paramètres d'URL."""
    resolver, _fetcher = _resolver(None)
    claims: dict[str, object] = {
        **_base_params(),
        "max_age": 86400,
        "prompt": True,
        "claims": {"userinfo": {"name": True}},
    }

    resolved = run(resolver, **_base_params(), request=_request_object(claims))

    assert isinstance(resolved, dict)
    assert resolved["max_age"] == "86400"
    assert resolved["prompt"] == "true"
    assert resolved["claims"] == '{"userinfo":{"name":true}}'


def test_embedded_params_are_never_taken_from_claims() -> None:
    """``request``/``request_uri`` du jeton sont ignorés (RFC 9101 §5)."""
    resolver, fetcher = _resolver(None)
    claims = {**_base_params(), "request_uri": "https://evil.example/x"}

    resolved = run(resolver, **_base_params(), request=_request_object(claims))

    assert isinstance(resolved, dict)
    assert "request_uri" not in resolved
    assert fetcher.urls == []


def test_document_is_fetched_by_reference() -> None:
    resolver, fetcher = _resolver(_request_object(_base_params(nonce="nonce-from-url")))

    resolved = run(resolver, **_base_params(), request_uri="https://rp.example/requesturi/abc")

    assert isinstance(resolved, dict)
    assert resolved["nonce"] == "nonce-from-url"
    assert fetcher.urls == ["https://rp.example/requesturi/abc"]


def test_unreachable_request_uri_returns_invalid_request_uri() -> None:
    resolver, fetcher = _resolver(None)

    resolved = run(resolver, **_base_params(), request_uri="https://rp.example/requesturi/abc")

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_uri"
    assert fetcher.urls == ["https://rp.example/requesturi/abc"]


def test_pushed_request_uri_is_left_to_par() -> None:
    """L'URN opaque de PAR n'est jamais lu sur le réseau (RFC 9126 §6.2)."""
    resolver, fetcher = _resolver(_request_object(_base_params()))
    params = _base_params(request_uri="urn:ietf:params:oauth:request_uri:reference")

    resolved = run(resolver, **params)

    assert resolved == params
    assert fetcher.urls == []


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("urn:ietf:params:oauth:request_uri:abc", True),
        ("https://rp.example/requesturi/abc", False),
        ("", False),
    ],
)
def test_is_pushed_request_uri(reference: str, expected: bool) -> None:
    assert is_pushed_request_uri(reference) is expected


def _op_encryption_key() -> tuple[JWERequestObjectDecrypter, RSAPublicKey]:
    """Déchiffreur de test monté sur une clé ``KeyUse.ENC`` et sa publique."""
    manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.ENC)
    asyncio.run(manager.ensure_active_key(2048, JWTAlgorithm.RS256))
    key_pair = asyncio.run(manager.get_active_keys())[0]
    public = load_pem_public_key(key_pair.public_key_pem.encode("ascii"))
    assert isinstance(public, RSAPublicKey)
    return JWERequestObjectDecrypter(manager), public


def _jwe(plaintext: str, public_key: RSAPublicKey) -> str:
    """Chiffre ``plaintext`` en JWE compact (RSA-OAEP + A256GCM, idem suite)."""
    return encrypt_compact(
        algorithm=JWEKeyManagementAlgorithm.RSA_OAEP,
        method=JWEEncryptionMethod.A256GCM,
        plaintext=plaintext.encode("utf-8"),
        rsa_public_key=public_key,
    )


def _encrypted_resolver(
    client: Client | None, decrypter: JWERequestObjectDecrypter | None
) -> RequestObjectResolver:
    """Resolver standard ouvert au chiffrement (port de déchiffrement optionnel)."""
    clients = InMemoryClientRepository()
    if client is not None:
        asyncio.run(clients.save(client))
    return RequestObjectResolver(
        RequestObjectConfig(issuer=_ISSUER),
        _StubFetcher(None),
        clients=clients,
        signed=PyJWTSignedRequestObjectVerifier(InMemoryDpopReplayRepository()),
        decryption=decrypter,
    )


def _jwe_envelope(header: dict[str, str]) -> str:
    """Enveloppe JWE à cinq segments portant ``header`` (refusée avant déchiffrement)."""
    return f"{_segment(header)}.e2k.iv.cipher.tag"


class TestEncryptedRequestObject:
    """Request objects chiffrés (OIDC Core 1.0 §10.1, issue #204)."""

    def test_encrypted_signed_jar_is_decrypted_and_merged(self) -> None:
        """Un JAR RS256 chiffré (RSA-OAEP + A256GCM) est déchiffré puis traité."""
        decrypter, public_key = _op_encryption_key()
        key, jwks = _jar_key()
        resolver = _encrypted_resolver(_standard_client(jwks), decrypter)

        resolved = run(
            resolver,
            **_base_params(nonce="nonce-transport"),
            request=_jwe(_signed_jar(key, claims={"nonce": "nonce-from-jar"}), public_key),
        )

        assert isinstance(resolved, dict)
        assert resolved["nonce"] == "nonce-from-jar"
        assert "request" not in resolved

    def test_encrypted_document_with_foreign_key_is_refused(self) -> None:
        """Le déchiffrement à une clé étrangère échoue (integrite ou OAEP)."""
        decrypter, _public_key = _op_encryption_key()
        foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        resolver = _encrypted_resolver(None, decrypter)

        resolved = run(
            resolver,
            **_base_params(),
            request=_jwe(_request_object(_base_params()), foreign.public_key()),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "déchiffrement impossible" in resolved.error_description

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ({"alg": "RSA1_5", "enc": "A256GCM"}, "algorithme de chiffrement non publié"),
            ({"alg": "RSA-OAEP", "enc": "A192CBC-HS384"}, "méthode de chiffrement non publiée"),
        ],
    )
    def test_unpublished_jwe_algorithms_are_refused(
        self, header: dict[str, str], expected: str
    ) -> None:
        """Seuls les ``alg``/``enc`` publiés au discovery sont admis."""
        decrypter, _public_key = _op_encryption_key()
        resolver = _encrypted_resolver(None, decrypter)

        resolved = run(resolver, **_base_params(), request=_jwe_envelope(header))

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert expected in resolved.error_description

    def test_encrypted_document_without_decryption_port_is_refused(self) -> None:
        """Sans port de déchiffrement, tout document JWE est refusé."""
        _key, jwks = _jar_key()
        resolver = _encrypted_resolver(_standard_client(jwks), None)

        resolved = run(
            resolver, **_base_params(), request=_jwe_envelope({"alg": "RSA-OAEP", "enc": "A256GCM"})
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "non supporté" in resolved.error_description

    def test_encrypted_document_with_closed_configuration_is_refused(self) -> None:
        """Deux listes vides ferment la porte, même port injecté (issue #204)."""
        decrypter, public_key = _op_encryption_key()
        clients = InMemoryClientRepository()
        resolver = RequestObjectResolver(
            RequestObjectConfig(issuer=_ISSUER, encryption_algorithms=(), encryption_methods=()),
            _StubFetcher(None),
            clients=clients,
            decryption=decrypter,
        )

        resolved = run(
            resolver, **_base_params(), request=_jwe(_request_object(_base_params()), public_key)
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request_object"
        assert "non supporté" in resolved.error_description

    def test_encrypted_federated_jar_keeps_section_12_requirements(self) -> None:
        """Le déchiffrement ne contourne pas le profil fédéré (§12.1.1.1).

        Pour un client fédéré (enregistrement auto), le refus renvoie
        ``invalid_request`` (aligné FAPI 1/2).
        """
        decrypter, public_key = _op_encryption_key()
        key, jwks = _jar_key()
        resolver = _encrypted_resolver(_federated_client(jwks), decrypter)

        resolved = run(
            resolver,
            **_base_params(),
            request=_jwe(_signed_jar(key, claims={"exp": _future()}), public_key),
        )

        assert isinstance(resolved, RequestObjectError)
        assert resolved.error == "invalid_request"
        assert "jti" in resolved.error_description

    def test_unknown_kid_selects_no_key(self) -> None:
        """Un ``kid`` étranger ne trouve aucune clé de déchiffrement."""
        decrypter, public_key = _op_encryption_key()
        document = _jwe(_request_object(_base_params()), public_key)

        result = asyncio.run(
            decrypter.decrypt(
                document=document, algorithm="RSA-OAEP", method="A256GCM", key_id="unknown"
            )
        )

        assert result.plaintext is None
        assert "introuvable" in result.reason


def _future() -> int:
    """Horodatage ``exp`` de demain (profil fédéré : ``exp`` exigé, §12.1.1.1)."""
    return int(datetime.now(timezone.utc).timestamp()) + 3600


# --------------------------------------------------------------------------- #
# Fetcher : lecture et filtrage du document
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("192.168.1.10", False),
        ("id.example", False),
        ("", False),
    ],
)
def test_loopback_bind_detects_local_listen_addresses(host: str, expected: bool) -> None:
    assert loopback_bind(host) is expected


def test_local_target_is_refused_when_not_allowed() -> None:
    fetcher = HTTPRequestObjectFetcher()

    assert _fetch(fetcher, "http://127.0.0.1:9/document") is None


def test_non_http_scheme_is_refused() -> None:
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, "file:///etc/passwd") is None


def test_credentials_in_uri_are_refused() -> None:
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, "http://user:pass@127.0.0.1:9/document") is None


def _fetch(fetcher: HTTPRequestObjectFetcher, url: str) -> str | None:
    """Exécute ``fetch`` en dehors de toute boucle d'événements."""
    return asyncio.run(fetcher.fetch(url))


@pytest.fixture
def document_server() -> Iterator[tuple[str, _DocumentState]]:
    """Serveur HTTP local servable comme ``request_uri`` des tests."""
    state = _DocumentState(document=_request_object(_base_params()))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Répond selon l'état courant du serveur de test."""
            state.paths.append(self.path)
            if state.location:
                self.send_response(302)
                self.send_header("Location", state.location)
                self.end_headers()
                return
            body = state.document.encode("utf-8")
            self.send_response(state.status)
            self.send_header("Content-Type", state.content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            """Silence le serveur de test."""
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fetch_reads_local_document_and_ignores_fragment(
    document_server: tuple[str, _DocumentState],
) -> None:
    url, state = document_server
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    document = _fetch(fetcher, f"{url}/requesturi/abc#empreinte-du-document")

    assert document == state.document
    assert state.paths == ["/requesturi/abc"]


def test_fetch_refuses_wrong_content_type(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.content_type = "text/plain"
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/document") is None


def test_fetch_does_not_follow_redirect(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.location = f"{url}/document"
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/start") is None
    assert state.paths == ["/start"]


def test_fetch_refuses_oversized_document(document_server: tuple[str, _DocumentState]) -> None:
    url, state = document_server
    state.document = "a" * (64 * 1024 + 1)
    fetcher = HTTPRequestObjectFetcher(allow_local_targets=True)

    assert _fetch(fetcher, f"{url}/document") is None


# --------------------------------------------------------------------------- #
# /authorize : observabilité HTTP
# --------------------------------------------------------------------------- #


def test_authorize_accepts_request_object_and_issues_code() -> None:
    """Le module ``oidcc-unsigned-request-object-…`` : flux happy en ``request``."""
    claims = _base_params(
        code_challenge=_s256_challenge("verifier-verifier"),
        code_challenge_method="S256",
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request": _request_object(claims),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["code"]
    assert query["state"] == ["state-1"]


def test_authorize_redirect_uri_of_request_object_takes_precedence() -> None:
    """``oidcc-ensure-request-object-with-redirect-uri`` : la query porte une URI fausse."""
    claims = _base_params(
        redirect_uri="https://app.example/callback",
        code_challenge=_s256_challenge("verifier-verifier"),
        code_challenge_method="S256",
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback_invalid",
                "scope": "openid profile",
                "state": "state-1",
                "request": _request_object(claims),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://app.example/callback?")


def test_authorize_accepts_rs256_request_object_and_issues_code() -> None:
    """OIDC Core 1.0 §10.1 : le JAR RS256 d'un client standard est vérifié (issue #188)."""
    claims = {
        **_base_params(
            client_id="signed-app",
            code_challenge=_s256_challenge("verifier-verifier"),
            code_challenge_method="S256",
        ),
        "iss": "signed-app",
    }
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "signed-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request": _signed_jar(_JAR_KEY, claims=claims),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["code"]
    assert query["state"] == ["state-1"]


def test_authorize_refuses_rs256_request_object_signed_by_a_foreign_key() -> None:
    """OIDC Core 1.0 §10.3 : clé étrangère -> ``invalid_request_object`` redirigé au client."""
    foreign, _foreign_jwks = _jar_key()
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "signed-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request": _signed_jar(
                    foreign, claims={"iss": "signed-app", "client_id": "signed-app"}
                ),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_request_object"]
    assert query["state"] == ["state-1"]


def test_authorize_shows_error_page_for_invalid_request_object() -> None:
    """Sans ``redirect_uri`` dans la query, la page 400 reste servie (issue #178)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={"request": "pas-un-jwt", "client_id": "web-app"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request_object" in response.text
    assert "location" not in response.headers


def test_authorize_redirects_invalid_request_object_error() -> None:
    """Issue #178 : ``redirect_uri`` de la query enregistrée → 302 avec state."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": "pas-un-jwt",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "state": "state-ro",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback?")
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["invalid_request_object"]
    assert query["state"] == ["state-ro"]


def test_authorize_keeps_error_page_for_unregistered_redirect_uri() -> None:
    """Issue #178 : URI non enregistrée → jamais de redirection (RFC 6749 §4.1.2.1)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": "pas-un-jwt",
                "client_id": "web-app",
                "redirect_uri": "https://evil.example/cb",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request_object" in response.text
    assert "location" not in response.headers


def test_authorize_keeps_error_page_for_unknown_client() -> None:
    """Issue #178 : client inconnu → page 400 (aucun callback de confiance)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": "pas-un-jwt",
                "client_id": "client-inconnu",
                "redirect_uri": "https://app.example/callback",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "location" not in response.headers


def test_authorize_redirects_request_object_error_in_fragment() -> None:
    """Issue #178 : ``response_type`` hybride → erreur dans le fragment (RFC 6749 §4.2.2.1)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": "pas-un-jwt",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "response_type": "code id_token",
                "state": "state-frag",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback#")
    fragment = parse_qs(urlparse(location).fragment)
    assert fragment["error"] == ["invalid_request_object"]
    assert fragment["state"] == ["state-frag"]


def test_authorize_echoes_state_from_rejected_request_object() -> None:
    """Issue #178 : le ``state`` lisible du jeton refusé est réaffiché (RFC 9101 §6.3)."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(json.dumps({"state": "state-du-jar"}).encode())
        .rstrip(b"=")
        .decode()
    )
    jar = f"{header}.{payload}.c2ln"
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": jar,
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_request_object"]
    assert query["state"] == ["state-du-jar"]


def test_authorize_shows_error_page_for_exclusive_parameters() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "request": _request_object(_base_params()),
                "request_uri": "https://rp.example/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request" in response.text


def test_authorize_shows_error_page_for_unreachable_request_uri() -> None:
    """Sans ``redirect_uri`` dans la query : page 400 (issue #178)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={"request_uri": "http://127.0.0.1:9/document", "client_id": "web-app"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request_uri" in response.text
    assert "location" not in response.headers


def test_authorize_fetches_request_uri_document(
    document_server: tuple[str, _DocumentState],
) -> None:
    """``oidcc-request-uri-unsigned-…`` : le document est lu sur le réseau."""
    url, state = document_server
    state.document = _request_object(
        _base_params(
            code_challenge=_s256_challenge("verifier-verifier"),
            code_challenge_method="S256",
        )
    )
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request_uri": f"{url}/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert state.paths == ["/requesturi/abc"]


def test_request_uri_allow_local_targets_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """`PURIDENTITYSERVER_REQUEST_URI_ALLOW_LOCAL_TARGETS` ouvre les cibles locales."""
    assert Settings(_env_file=None).request_uri_allow_local_targets is False

    monkeypatch.setenv("PURIDENTITYSERVER_REQUEST_URI_ALLOW_LOCAL_TARGETS", "true")
    assert Settings(_env_file=None).request_uri_allow_local_targets is True


def _app_binding_all_interfaces(*, allow_local_targets: bool) -> FastAPI:
    """Application avec l'OP bindé sur 0.0.0.0 (topologie du harness)."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            host="0.0.0.0",
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT,),
            request_uri_allow_local_targets=allow_local_targets,
        )
    )


def test_authorize_refuses_local_request_uri_when_harness_flag_is_absent(
    document_server: tuple[str, _DocumentState],
) -> None:
    """Host non-loopback sans drapeau : garde anti-SSRF → erreur au client enregistré."""
    url, _state = document_server
    with TestClient(_app_binding_all_interfaces(allow_local_targets=False)) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request_uri": f"{url}/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_request_uri"]


def test_authorize_fetches_local_request_uri_with_harness_flag(
    document_server: tuple[str, _DocumentState],
) -> None:
    """Harness de certification (#152) : drapeau explicite → fetch accepté."""
    url, state = document_server
    state.document = _request_object(
        _base_params(
            code_challenge=_s256_challenge("verifier-verifier"),
            code_challenge_method="S256",
        )
    )
    with TestClient(_app_binding_all_interfaces(allow_local_targets=True)) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "request_uri": f"{url}/requesturi/abc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert state.paths == ["/requesturi/abc"]


def test_authorize_issues_code_then_unsigned_id_token_for_none_client() -> None:
    """``oidcc-idtoken-unsigned`` : ``id_token_signed_response_alg=none``."""
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "unsigned-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "nonce": "nonce-unsigned",
            },
            follow_redirects=False,
        )
        code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "unsigned-app",
                "client_secret": "super-secret",
            },
        )

    payload = response.json()
    assert response.status_code == 200
    header, claims, signature = payload["id_token"].split(".")
    assert json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["alg"] == "none"
    assert signature == ""
    decoded = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    assert decoded["nonce"] == "nonce-unsigned"
    assert "at_hash" not in decoded
