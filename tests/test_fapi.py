"""Tests du profil FAPI 1.0 Advanced Final (issue #110).

Couvre les écarts G1 (request object obligatoire, ``PS256``/``ES256``,
claims et bornes), G3 (flow hybride exigé, PKCE ``S256`` en PAR) et G6
(discovery) : le resolver FAPI, le validateur d'autorisation, le push PAR
et l'échange du code au token endpoint.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Awaitable
from datetime import datetime, timezone
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRequest,
    ValidatedAuthorization,
    validate_authorization_request,
)
from puridentityserver.application.par import (
    PushedAuthorizationConfig,
    PushedAuthorizationUseCase,
    PushError,
    PushResult,
)
from puridentityserver.application.request_object import (
    RequestObjectConfig,
    RequestObjectError,
    RequestObjectResolver,
)
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.persistence.memory.dpop_replays import (
    InMemoryDpopReplayRepository,
)
from puridentityserver.infrastructure.persistence.memory.pushed_authorizations import (
    InMemoryPushedAuthorizationRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.signed_request_object import (
    PyJWTSignedRequestObjectVerifier,
)
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_ID = "fapi-app"
_CLIENT_SECRET = "fapi-super-secret"
_REDIRECT_URI = "https://fapi.example/callback"
_JAR_KID = "fapi-jar-test-key"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine en synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


# --------------------------------------------------------------------------- #
# Fixtures de test : clé JAR, client FAPI, resolver
# --------------------------------------------------------------------------- #


def _jar_key() -> tuple[RSAPrivateKey, tuple[dict[str, object], ...]]:
    """Paire RSA de test et JWKS embarqué (``kid``/``alg``) pour le request object."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    jwks = (
        {
            "kty": "RSA",
            "use": "sig",
            "kid": _JAR_KID,
            "alg": "PS256",
            "n": n.rstrip(b"=").decode("ascii"),
            "e": e.rstrip(b"=").decode("ascii"),
        },
    )
    return private, jwks


def _fapi_client(jwks: tuple[dict[str, object], ...]) -> Client:
    """Client FAPI1 confidentiel (secret + request object signé exigé)."""
    return Client(
        client_id=_CLIENT_ID,
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        client_type=ClientType.CONFIDENTIAL,
        client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
        fapi_enabled=True,
        jwks=jwks,
    )


def _unsigned_client() -> Client:
    """Client standard (non FAPI) : request object ``alg=none`` toujours admis."""
    return Client(
        client_id="web-app",
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        client_type=ClientType.CONFIDENTIAL,
        client_secret_hash=hashlib.sha256(b"web-secret").hexdigest(),
    )


class _StubFetcher:
    """Port ``RequestObjectFetcher`` de test : aucun document distant."""

    async def fetch(self, url: str) -> str | None:
        """Refuse toute lecture réseau (les tests n'utilisent pas ``request_uri``)."""
        return None


def _clients(*clients: Client) -> InMemoryClientRepository:
    """Registre mémoire pré-rempli avec les clients donnés."""
    repository = InMemoryClientRepository()
    for client in clients:
        run(repository.save(client))
    return repository


def _resolver(repository: InMemoryClientRepository) -> RequestObjectResolver:
    """Resolver FAPI complet : issuer, clients et vérificateur PyJWT réel."""
    return RequestObjectResolver(
        RequestObjectConfig(issuer=_ISSUER),
        _StubFetcher(),
        clients=repository,
        signed=PyJWTSignedRequestObjectVerifier(InMemoryDpopReplayRepository()),
    )


def _now() -> int:
    """Timestamp Unix courant."""
    return int(datetime.now(timezone.utc).timestamp())


def _jar_claims(**overrides: object) -> dict[str, object]:
    """Claims FAPI complets (hybride + PKCE + bornes par défaut valides)."""
    now = _now()
    claims: dict[str, object] = {
        "iss": _CLIENT_ID,
        "aud": _ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "scope": "openid profile",
        "nonce": "nonce-1",
        "redirect_uri": _REDIRECT_URI,
        "response_type": "code id_token",
        "client_id": _CLIENT_ID,
        "state": "state-1",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
    }
    claims.update(overrides)
    return claims


def _sign(
    private: RSAPrivateKey,
    claims: dict[str, object],
    *,
    algorithm: str = "PS256",
    kid: str = _JAR_KID,
) -> str:
    """Signe un request object avec la clé et l'algorithme donnés."""
    return str(pyjwt.encode(claims, private, algorithm=algorithm, headers={"kid": kid}))


def _unsigned(claims: dict[str, object]) -> str:
    """Construit un JWT compact non signé (``header.payload.``)."""

    def segment(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{segment({'alg': 'none'})}.{segment(claims)}."


def _s256_challenge(verifier: str) -> str:
    """Défi PKCE S256 d'un ``code_verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _resolve(
    repository: InMemoryClientRepository, **params: str
) -> dict[str, str] | RequestObjectError:
    """Exécute le resolver FAPI sur des paramètres donnés."""
    return run(_resolver(repository).resolve(params))


def _fapi_repository() -> tuple[RSAPrivateKey, InMemoryClientRepository]:
    """Clé privée de test + registre contenant le client FAPI."""
    private, jwks = _jar_key()
    return private, _clients(_fapi_client(jwks), _unsigned_client())


# --------------------------------------------------------------------------- #
# G1/G6 : resolver FAPI (request object obligatoire, signé, borné)
# --------------------------------------------------------------------------- #


def test_fapi_client_without_request_object_is_refused() -> None:
    """``EnsureAuthorizationRequestWithoutRequestObjectFails`` (5.2.2-1)."""
    _private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        response_type="code id_token",
        client_id=_CLIENT_ID,
        redirect_uri=_REDIRECT_URI,
        scope="openid profile",
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request"
    assert "FAPI" in resolved.error_description


def test_fapi_signed_request_object_is_accepted_and_primes() -> None:
    """Le request object signé prime ; ``state`` hors jeton est ignoré (5.2.3-8)."""
    private, repository = _fapi_repository()
    claims = _jar_claims()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        state="state-hors-jar",
        response_type="code",  # dupliqué falsifié : le JAR fait foi
        request=_sign(private, claims),
    )

    assert isinstance(resolved, dict)
    assert resolved["response_type"] == "code id_token"
    assert resolved["state"] == "state-1"
    assert resolved["nonce"] == "nonce-1"
    assert resolved["code_challenge_method"] == "S256"
    assert resolved["client_id"] == _CLIENT_ID
    assert "request" not in resolved


def test_fapi_accepts_aud_array_containing_issuer() -> None:
    """Le claim ``aud`` peut être un tableau contenant l'issuer (RFC 7519 §4.1.3)."""
    private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_sign(private, _jar_claims(aud=[_ISSUER, "https://other.example"])),
    )

    assert isinstance(resolved, dict)


def test_fapi_unsigned_request_object_is_refused() -> None:
    """``SignatureAlgorithmIsNotNone`` / ``WithoutSignature`` (5.2.2-1)."""
    _private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_unsigned(_jar_claims()),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_fapi_rs256_request_object_is_refused() -> None:
    """Seuls ``PS256``/``ES256`` sont admis (FAPI1-ADV-5.2.2-1)."""
    private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_sign(private, _jar_claims(), algorithm="RS256"),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"
    assert "non admis" in resolved.error_description


def test_fapi_request_object_signed_by_another_key_is_refused() -> None:
    """``InvalidSignature`` : la clé ne figure pas dans les JWKS du client."""
    _private, repository = _fapi_repository()
    rogue, _rogue_jwks = _jar_key()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_sign(rogue, _jar_claims()),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_fapi_issuer_mismatch_is_refused() -> None:
    """``iss`` doit nommer le client (PyJWT ``issuer=``)."""
    private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_sign(private, _jar_claims(iss="other-app")),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_fapi_bad_audience_is_refused() -> None:
    """``BadAud`` : ``aud`` doit contenir l'issuer (5.2.2-14)."""
    private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        client_id=_CLIENT_ID,
        request=_sign(private, _jar_claims(aud="https://rp.example")),
    )

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_fapi_missing_required_claim_is_refused() -> None:
    """``WithoutExp``/``WithoutNbf``/``WithoutScope``/``WithoutNonce``/``WithoutRedirectUri``."""
    private, repository = _fapi_repository()

    for claim in ("exp", "nbf", "scope", "nonce", "redirect_uri"):
        claims = _jar_claims()
        claims.pop(claim)
        resolved = _resolve(
            repository,
            client_id=_CLIENT_ID,
            request=_sign(private, claims),
        )
        assert isinstance(resolved, RequestObjectError), claim
        assert resolved.error == "invalid_request_object", claim


def test_fapi_exp_over_60_minutes_is_refused() -> None:
    """``WithExpOver60`` : ``exp`` ≤ maintenant + 60 minutes (5.2.2-13)."""
    private, repository = _fapi_repository()
    claims = _jar_claims(exp=_now() + 70 * 60)

    resolved = _resolve(repository, client_id=_CLIENT_ID, request=_sign(private, claims))

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_fapi_nbf_over_60_minutes_in_past_is_refused() -> None:
    """``WithNbfOver60`` : ``nbf`` ≥ maintenant - 60 minutes (5.2.2-17)."""
    private, repository = _fapi_repository()
    claims = _jar_claims(nbf=_now() - 70 * 60, exp=_now() + 300)

    resolved = _resolve(repository, client_id=_CLIENT_ID, request=_sign(private, claims))

    assert isinstance(resolved, RequestObjectError)
    assert resolved.error == "invalid_request_object"


def test_non_fapi_client_keeps_unsigned_request_object() -> None:
    """Régression : ``alg=none`` reste admis hors profil FAPI (issue #76)."""
    _private, repository = _fapi_repository()

    resolved = _resolve(
        repository,
        response_type="code",
        client_id="web-app",
        redirect_uri=_REDIRECT_URI,
        scope="openid profile",
        request=_unsigned(_jar_claims(iss="web-app", response_type="code")),
    )

    assert isinstance(resolved, dict)
    assert resolved["response_type"] == "code"


# --------------------------------------------------------------------------- #
# G3 : validateur d'autorisation (flow hybride exigé, PKCE S256)
# --------------------------------------------------------------------------- #


def _request(**overrides: object) -> AuthorizeRequest:
    """Demande d'autorisation FAPI valide (hybride + PKCE + nonce)."""
    values: dict[str, object] = {
        "response_type": "code id_token",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "state-1",
        "nonce": "nonce-1",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
    }
    values.update(overrides)
    return AuthorizeRequest(**values)  # type: ignore[arg-type]


def _validate(request: AuthorizeRequest) -> ValidatedAuthorization | AuthorizeError:
    """Valide une demande contre le registre contenant le client FAPI."""
    _private, repository = _fapi_repository()
    return run(validate_authorization_request(request, repository))


def test_fapi_hybrid_flow_is_accepted() -> None:
    validated = _validate(_request())

    assert isinstance(validated, ValidatedAuthorization)
    assert validated.wants_code
    assert validated.wants_id_token


def test_fapi_rejects_response_type_code() -> None:
    """``EnsureResponseTypeCodeFails`` (5.2.2-2) : ``code`` seul refusé."""
    validated = _validate(_request(response_type="code"))

    assert isinstance(validated, AuthorizeError)
    assert validated.error == "unsupported_response_type"


def test_fapi_rejects_plain_pkce() -> None:
    """``PlainPKCERejected`` (5.2.2-18) : ``plain`` refusé dès le validateur."""
    validated = _validate(_request(code_challenge="plain-challenge", code_challenge_method="plain"))

    assert isinstance(validated, AuthorizeError)
    assert validated.error == "invalid_request"


def test_fapi_requires_nonce_for_hybrid() -> None:
    """OIDC Core 1.0 §3.2.2.10 : ``nonce`` exigé avec ``id_token``."""
    validated = _validate(_request(nonce=""))

    assert isinstance(validated, AuthorizeError)
    assert validated.error == "invalid_request"


# --------------------------------------------------------------------------- #
# G3 : push PAR (résolution du request object + PKCE obligatoire)
# --------------------------------------------------------------------------- #


def _par_usecase(
    repository: InMemoryClientRepository,
) -> tuple[PushedAuthorizationUseCase, InMemoryPushedAuthorizationRepository]:
    """Use case PAR branché sur le resolver FAPI complet."""
    pushed = InMemoryPushedAuthorizationRepository()
    usecase = PushedAuthorizationUseCase(
        PushedAuthorizationConfig(ttl_seconds=90, issuer=_ISSUER),
        repository,
        pushed,
        request_object_resolver=_resolver(repository),
    )
    return usecase, pushed


def _push(
    repository: InMemoryClientRepository, **params: str
) -> tuple[PushResult | PushError, InMemoryPushedAuthorizationRepository]:
    """Pousse une demande FAPI authentifiée par ``client_secret`` (formulaire)."""
    usecase, pushed = _par_usecase(repository)
    base = {
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
    }
    base.update(params)
    return run(usecase.push(base)), pushed


def test_fapi_par_accepts_signed_request_object_with_pkce() -> None:
    """Push FAPI happy path : JAR signé, PKCE S256 en dedans → ``request_uri``."""
    private, repository = _fapi_repository()

    result, pushed_repo = _push(repository, request=_sign(private, _jar_claims()))

    assert isinstance(result, PushResult)
    assert result.request_uri
    stored = run(pushed_repo.find_by_request_uri(result.request_uri))
    assert stored is not None
    assert stored.params["response_type"] == "code id_token"
    assert stored.params["state"] == "state-1"
    assert "request" not in stored.params


def test_fapi_par_refuses_missing_request_object() -> None:
    """Le push sans ``request`` échoue comme l'endpoint d'autorisation (5.2.2-1)."""
    _private, repository = _fapi_repository()

    result, _pushed_repo = _push(
        repository,
        response_type="code id_token",
        redirect_uri=_REDIRECT_URI,
        scope="openid profile",
        nonce="nonce-1",
    )

    assert isinstance(result, PushError)
    assert result.error == "invalid_request"
    assert result.status_code == 400


def test_fapi_par_refuses_unsigned_request_object() -> None:
    _private, repository = _fapi_repository()

    result, _pushed_repo = _push(repository, request=_unsigned(_jar_claims()))

    assert isinstance(result, PushError)
    assert result.error == "invalid_request_object"


def test_fapi_par_requires_pkce() -> None:
    """``PAREnsurePKCERequired`` (5.2.2-18) : ``code_challenge`` exigé en PAR."""
    private, repository = _fapi_repository()
    claims = _jar_claims()
    for claim in ("code_challenge", "code_challenge_method"):
        claims.pop(claim, None)

    result, _pushed_repo = _push(repository, request=_sign(private, claims))

    assert isinstance(result, PushError)
    assert result.error == "invalid_request"
    assert "PKCE" in result.error_description


def test_fapi_par_refuses_plain_pkce() -> None:
    """``PAREnsurePlainPKCERejected`` (5.2.2-18) : ``plain`` refusé au push."""
    private, repository = _fapi_repository()
    claims = _jar_claims(code_challenge="plain-challenge", code_challenge_method="plain")

    result, _pushed_repo = _push(repository, request=_sign(private, claims))

    assert isinstance(result, PushError)
    assert result.error == "invalid_request"
    assert "S256" in result.error_description


def test_fapi_par_rejects_response_type_code() -> None:
    """``EnsureResponseTypeCodeFails`` en variante pushed : erreur PAR 400."""
    private, repository = _fapi_repository()
    claims = _jar_claims(response_type="code")

    result, _pushed_repo = _push(repository, request=_sign(private, claims))

    assert isinstance(result, PushError)
    assert result.error == "unsupported_response_type"


def test_fapi_par_rejects_request_uri_in_request_object() -> None:
    """``PARRejectRequestUriInParAuthorizationRequest`` : ``invalid_request_object``."""
    private, repository = _fapi_repository()
    claims = _jar_claims(request_uri="urn:ietf:params:oauth:request_uri:junk")

    result, _pushed_repo = _push(repository, request=_sign(private, claims))

    assert isinstance(result, PushError)
    assert result.error == "invalid_request_object"
    assert result.status_code == 400


# --------------------------------------------------------------------------- #
# E2E : /authorize + /token avec seed fapi_enabled
# --------------------------------------------------------------------------- #


def _app() -> FastAPI:
    """Application de test avec le client FAPI seedé (``fapi_enabled``)."""
    private, jwks = _jar_key()
    app = create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(
                {
                    "client_id": _CLIENT_ID,
                    "client_secret": _CLIENT_SECRET,
                    "redirect_uris": [_REDIRECT_URI],
                    "scopes": "openid profile",
                    "client_type": "confidential",
                    "fapi_enabled": True,
                    "jwks": list(jwks),
                },
            ),
        )
    )
    app.state.jar_private = private
    return app


def _fragment(location: str) -> dict[str, list[str]]:
    """Paramètres portés par le fragment d'une URL de redirection."""
    return parse_qs(urlparse(location).fragment)


def _left_half_hash(value: str) -> str:
    """Empreinte attendue d'un claim ``*_hash`` (SHA-256, moitié gauche, base64url)."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def test_seed_fapi_enabled_is_parsed() -> None:
    """Le drapeau ``fapi_enabled`` du seed active le profil (composition)."""
    with TestClient(_app()) as client:
        # Sans request object : page d'erreur 400, aucune redirection.
        response = client.get(
            "/authorize",
            params={
                "response_type": "code id_token",
                "client_id": _CLIENT_ID,
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid profile",
                "nonce": "n-1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid_request" in response.text
    assert "FAPI" in response.text


def test_authorize_hybrid_flow_with_signed_jar_succeeds() -> None:
    """E2E : JAR signé + ``code id_token`` → code, ``id_token``, ``s_hash`` en fragment."""
    with TestClient(_app()) as client:
        private = client.app.state.jar_private  # type: ignore[attr-defined]
        auth = client.get(
            "/authorize",
            params={
                "client_id": _CLIENT_ID,
                "request": _sign(private, _jar_claims()),
            },
            follow_redirects=False,
        )
        fragment = _fragment(auth.headers["location"])

    assert auth.status_code == 302
    assert fragment["state"] == ["state-1"]
    assert fragment["code"]
    assert fragment["id_token"]
    claims = pyjwt.decode(fragment["id_token"][0], options={"verify_signature": False})
    assert claims["c_hash"] == _left_half_hash(fragment["code"][0])
    assert claims["s_hash"] == _left_half_hash("state-1")


def test_authorize_without_state_omits_state_and_s_hash() -> None:
    """``WithoutStateSuccess`` : ni ``state`` ni ``s_hash`` quand le JAR n'en porte pas."""
    with TestClient(_app()) as client:
        private = client.app.state.jar_private  # type: ignore[attr-defined]
        auth = client.get(
            "/authorize",
            params={
                "client_id": _CLIENT_ID,
                "request": _sign(private, _jar_claims(state="")),
            },
            follow_redirects=False,
        )
        fragment = _fragment(auth.headers["location"])

    assert auth.status_code == 302
    assert "state" not in fragment
    claims = pyjwt.decode(fragment["id_token"][0], options={"verify_signature": False})
    assert "s_hash" not in claims
    assert "c_hash" in claims


def test_authorize_response_type_code_from_jar_is_refused() -> None:
    """E2E ``EnsureResponseTypeCodeFails`` : redirection d'erreur avec state."""
    with TestClient(_app()) as client:
        private = client.app.state.jar_private  # type: ignore[attr-defined]
        response = client.get(
            "/authorize",
            params={
                "client_id": _CLIENT_ID,
                "request": _sign(private, _jar_claims(response_type="code")),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["state-1"]


def test_token_endpoint_pkce_checks_for_fapi_client() -> None:
    """``PAREnsurePKCECodeVerifierRequired`` / ``Incorrect`` : ``invalid_grant``."""
    verifier = "verifier-verifier"
    with TestClient(_app()) as client:
        private = client.app.state.jar_private  # type: ignore[attr-defined]
        auth = client.get(
            "/authorize",
            params={
                "client_id": _CLIENT_ID,
                "request": _sign(private, _jar_claims()),
            },
            follow_redirects=False,
        )
        code = _fragment(auth.headers["location"])["code"][0]

        missing = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
            },
        )

        wrong = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "code_verifier": "mauvais-verifier",
            },
        )

        valid = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "code_verifier": verifier,
            },
        )

    assert missing.status_code == 400
    assert missing.json()["error"] == "invalid_grant"
    assert wrong.status_code == 400
    assert wrong.json()["error"] == "invalid_grant"
    assert valid.status_code == 200
    assert valid.json()["access_token"]
