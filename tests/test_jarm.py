"""Tests de la feature JARM (JARM Final 1.0 §3, ``response_mode=jwt``).

- politique : ``jarm_signing_alg`` (algorithme du client publiable par l'OP),
  refus ``unsupported_response_mode`` en transport clair, garde asymétrique
  de l'enveloppe ;
- HTTP : succès ``code`` enveloppé et vérifiable via le JWKS de l'OP
  (``kid`` opposé, ``aud`` client, ``exp`` borné), erreurs redirigeables
  signées (``login_required`` ``prompt=none``, ``access_denied`` du
  consentement), ``response`` en query sans autre paramètre ni fragment,
  dégradation en transport clair sans signeur, aller-retour PAR,
  métadonnées de discovery publiées.
"""

import asyncio
import base64
import hashlib
import json
from collections.abc import Awaitable
from typing import Any, TypeVar, cast
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from puridentityserver.application.authorize import (
    AuthorizeConfig,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.application.jarm import JarmSigner, jarm_signing_alg
from puridentityserver.domain.authorization import Client, Scope
from puridentityserver.domain.jwks import JARM_SIGNING_ALGORITHMS
from puridentityserver.infrastructure.jarm import PyJarmEnvelopeSigner
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.domain.jwks import KeyManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"

_JARM_CLIENT_JSON: dict[str, object] = {
    "client_id": "jarm-app",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "public",
    "authorization_signed_response_alg": "RS256",
}

_PLAIN_CLIENT_JSON: dict[str, object] = {
    "client_id": "plain-app",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "public",
}

_CONSENT_JARM_CLIENT_JSON: dict[str, object] = {
    **_JARM_CLIENT_JSON,
    "client_id": "jarm-consent-app",
    "require_consent": True,
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


class _NoopTokenManager:
    """Émetteur de jetons factice : jamais sollicité pour le code flow."""

    async def create_id_token(self, **_kwargs: object) -> str:
        return ""

    async def create_access_token(self, **_kwargs: object) -> str:
        return ""

    async def validate_access_token(self, **_kwargs: object) -> dict[str, object] | None:
        return None


def _app(seed: tuple[dict[str, object], ...] | None = None, **settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=seed or (_JARM_CLIENT_JSON,),
            identity_seed_users=_IDENTITY_SEED,
            **settings,
        )
    )


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(
    client_id: str = "jarm-app",
    response_mode: str = "jwt",
    **extra: str,
) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation valide (code flow + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-jarm",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
        "response_mode": response_mode,
    }
    params.update(extra)
    return params


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


def _jwks_keys(client: TestClient) -> list[dict[str, Any]]:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    return cast(list[dict[str, Any]], response.json()["keys"])


def _decode_envelope(
    envelope: str, keys: list[dict[str, Any]], audience: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Vérifie la signature du JWS JARM contre le JWKS de l'OP et retourne (header, claims)."""
    header = pyjwt.get_unverified_header(envelope)
    key = next(jwk for jwk in keys if jwk.get("kid") == header["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(key))
    claims = pyjwt.decode(
        envelope,
        key=public_key,
        algorithms=[header["alg"]],
        audience=audience,
        issuer=_ISSUER,
    )
    return header, cast(dict[str, Any], claims)


def _envelope_from_location(
    location: str, keys: list[dict[str, Any]], audience: str
) -> dict[str, Any]:
    """Extrait et vérifie le JWT du paramètre ``response`` d'une redirection."""
    parsed = urlparse(location)
    assert not parsed.fragment, "l'enveloppe JARM voyage en query, jamais en fragment"
    query = parse_qs(parsed.query)
    assert set(query) == {"response"}, f"paramètres inattendus : {sorted(query)}"
    header, claims = _decode_envelope(query["response"][0], keys, audience)
    assert header["kid"]
    return claims


# ─────────────────────────────────────────────────────────────────────────────
# Politique d'algorithme et enveloppe
# ─────────────────────────────────────────────────────────────────────────────


def _jarm_client(alg: str = "RS256") -> Client:
    return Client(
        client_id="jarm-app",
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        authorization_signed_response_alg=alg,
    )


def test_jarm_signing_alg_requires_jwt_mode() -> None:
    assert jarm_signing_alg(_jarm_client(), "jwt") == "RS256"
    assert jarm_signing_alg(_jarm_client(), "") == ""
    assert jarm_signing_alg(_jarm_client(), "fragment") == ""


def test_jarm_signing_alg_rejects_unknown_algorithm() -> None:
    assert jarm_signing_alg(_jarm_client(alg="HS256"), "jwt") == ""
    assert jarm_signing_alg(_jarm_client(alg=""), "jwt") == ""
    for algorithm in JARM_SIGNING_ALGORITHMS:
        assert jarm_signing_alg(_jarm_client(alg=algorithm), "jwt") == algorithm


def test_envelope_signer_refuses_symmetric_algorithm() -> None:
    signer = PyJarmEnvelopeSigner(cast(KeyManager, object()), _ISSUER)
    envelope = signer.sign_envelope(audience="jarm-app", algorithm="HS256", params={})
    with pytest.raises(ValueError, match="non signable"):
        run(envelope)


def test_jarm_signer_refuses_client_without_alg() -> None:
    signer = JarmSigner(
        PyJarmEnvelopeSigner(cast(KeyManager, object()), _ISSUER), InMemoryClientRepository()
    )
    call = signer.sign(_jarm_client(alg=""), {})
    with pytest.raises(ValueError, match="sans authorization_signed_response_alg"):
        run(call)


def test_sign_by_client_id_returns_none_for_unsignable_client() -> None:
    """Client inconnu ou sans algorithme : ``None`` (repli en transport clair)."""
    clients = InMemoryClientRepository()
    run(clients.save(_jarm_client(alg="")))
    signer = JarmSigner(PyJarmEnvelopeSigner(cast(KeyManager, object()), _ISSUER), clients)

    assert run(signer.sign_by_client_id("jarm-app", {})) is None
    assert run(signer.sign_by_client_id("unknown", {})) is None


def test_signer_failure_falls_back_to_clear_transport() -> None:
    """Une défaillance du signeur retombe sur le transport clair (jamais d'URL vide)."""

    class _FailingSigner:
        async def sign(self, _client: Client, _params: object) -> str:
            raise ValueError("clé indisponible")

    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    run(clients.save(_jarm_client()))
    usecase = AuthorizeUseCase(
        AuthorizeConfig(),
        clients,
        codes,
        _NoopTokenManager(),
        jarm_signer=cast(Any, _FailingSigner()),
    )

    result = run(
        usecase.execute(
            AuthorizeRequest(
                response_type="code",
                client_id="jarm-app",
                redirect_uri=_REDIRECT_URI,
                scope="openid",
                response_mode="jwt",
            )
        )
    )

    assert isinstance(result, AuthorizeRedirect)
    assert result.redirect_uri.startswith(_REDIRECT_URI + "?")
    assert "response=" not in result.redirect_uri
    assert _redirect_query(result.redirect_uri)["code"]


def test_success_without_signer_degrades_to_clear_query() -> None:
    """Sans signeur injecté (composition réduite), ``jwt`` retombe sur ``query`` clair."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    run(clients.save(_jarm_client()))
    usecase = AuthorizeUseCase(AuthorizeConfig(), clients, codes, _NoopTokenManager())

    result = run(
        usecase.execute(
            AuthorizeRequest(
                response_type="code",
                client_id="jarm-app",
                redirect_uri=_REDIRECT_URI,
                scope="openid",
                response_mode="jwt",
            )
        )
    )

    assert isinstance(result, AuthorizeRedirect)
    assert result.redirect_uri.startswith(_REDIRECT_URI + "?")
    assert "response=" not in result.redirect_uri
    assert _redirect_query(result.redirect_uri)["code"]


# ─────────────────────────────────────────────────────────────────────────────
# Intégration HTTP
# ─────────────────────────────────────────────────────────────────────────────


def test_authorize_success_returns_signed_envelope() -> None:
    with TestClient(_app()) as client:
        response = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        assert response.status_code == 302
        claims = _envelope_from_location(
            response.headers["location"], _jwks_keys(client), "jarm-app"
        )

    assert claims["code"]
    assert claims["state"] == "st-jarm"
    assert claims["iss"] == _ISSUER
    assert claims["aud"] == "jarm-app"
    assert "error" not in claims
    assert claims["exp"] - claims["iat"] == 600


def test_authorize_prompt_none_returns_signed_login_required() -> None:
    """``prompt=none`` sans session renvoie ``login_required`` signé (JARM §3)."""
    with TestClient(_app(require_login=True)) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(prompt="none"),
            follow_redirects=False,
        )
        assert response.status_code == 302
        claims = _envelope_from_location(
            response.headers["location"], _jwks_keys(client), "jarm-app"
        )

    assert claims["error"] == "login_required"
    assert claims["state"] == "st-jarm"
    assert claims["aud"] == "jarm-app"
    assert "code" not in claims


def test_consent_deny_returns_signed_access_denied() -> None:
    """Le refus du consentement (``access_denied``) part dans l'enveloppe signée."""
    with TestClient(_app(seed=(_CONSENT_JARM_CLIENT_JSON,))) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302
        decision = client.post(
            "/consent",
            data={**_authorize_params(client_id="jarm-consent-app"), "action": "deny"},
            follow_redirects=False,
        )
        assert decision.status_code == 302
        claims = _envelope_from_location(
            decision.headers["location"], _jwks_keys(client), "jarm-consent-app"
        )

    assert claims["error"] == "access_denied"
    assert claims["state"] == "st-jarm"
    assert claims["aud"] == "jarm-consent-app"


def test_unsupported_client_without_alg_is_refused_in_clear() -> None:
    """Sans ``authorization_signed_response_alg``, le refus part en query claire.

    ``response_mode=jwt`` ne peut pas porter l'enveloppe qui refuse justement
    la demande (JARM Final 1.0 §4).
    """
    with TestClient(_app(seed=(_PLAIN_CLIENT_JSON,))) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(client_id="plain-app"),
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(_REDIRECT_URI + "?")
    query = _redirect_query(location)
    assert query["error"] == ["unsupported_response_mode"]
    assert query["state"] == ["st-jarm"]
    assert "response" not in query
    assert not urlparse(location).fragment


def test_par_round_trip_keeps_jwt_response_mode() -> None:
    """Le ``response_mode=jwt`` poussé revient dans l'enveloppe après résolution."""
    with TestClient(_app(par_enabled=True)) as client:
        push = client.post("/par", data=_authorize_params())
        assert push.status_code == 201
        request_uri = push.json()["request_uri"]

        response = client.get(
            "/authorize",
            params={"client_id": "jarm-app", "request_uri": request_uri},
            follow_redirects=False,
        )
        assert response.status_code == 302
        claims = _envelope_from_location(
            response.headers["location"], _jwks_keys(client), "jarm-app"
        )

    assert claims["code"]
    assert claims["state"] == "st-jarm"


def test_discovery_publishes_jarm_metadata() -> None:
    """``response_modes_supported`` contient ``jwt`` et les algos JARM sont publiés."""
    with TestClient(_app()) as client:
        response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    metadata = response.json()
    assert "jwt" in metadata["response_modes_supported"]
    assert metadata["authorization_signing_alg_values_supported"] == list(JARM_SIGNING_ALGORITHMS)
