"""Tests de la feature DPoP (RFC 9449) : preuves, liaison des jetons, endpoints."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import time
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, TypeVar
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.dpop import DpopBinding, DpopGrantGuard, DpopGuardError
from puridentityserver.application.par import (
    PushedAuthorizationConfig,
    PushedAuthorizationUseCase,
    PushError,
    PushResult,
)
from puridentityserver.application.registration import (
    RegisterRequest,
    RegistrationConfig,
    RegistrationError,
    RegistrationUseCase,
)
from puridentityserver.application.token import TokenConfig, TokenRequest, TokenUseCase
from puridentityserver.application.userinfo import (
    UserInfoConfig,
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ClientType,
    RefreshToken,
    Scope,
)
from puridentityserver.domain.dpop import (
    DPOP_PROOF_TYPE,
    access_token_hash,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.dpop import PyJWTDpopProofValidator, jwk_thumbprint
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.device_authorizations import (
    InMemoryDeviceAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.dpop_replays import (
    InMemoryDpopReplayRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.pushed_authorizations import (
    InMemoryPushedAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.refresh_tokens import (
    InMemoryRefreshTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.domain.dpop import DpopValidationError
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_TOKEN_ENDPOINT = f"{_ISSUER}/token"
_USERINFO_ENDPOINT = f"{_ISSUER}/userinfo"
_PAR_ENDPOINT = f"{_ISSUER}/par"

_CLIENT_ID = "dpop-app"
_CLIENT_SECRET = "super-secret"
_REDIRECT_URI = "https://app.example/callback"

_JTI = itertools.count(1)

# Vecteur de référence de la RFC 7638 §3 (empreinte RFC 7638).
_RFC7638_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
        "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
        "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
        "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
        "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
        "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
}
_RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _b64url(value: int, size: int) -> str:
    """Encode un entier en base64url big-endian sur ``size`` octets."""
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode("ascii")


def _ec_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """JWK public EC (P-256) d'une clé privée."""
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x, 32),
        "y": _b64url(numbers.y, 32),
    }


def _proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    htu: str = _TOKEN_ENDPOINT,
    method: str = "POST",
    jwk: dict[str, Any] | None = None,
    typ: str = DPOP_PROOF_TYPE,
    alg: str = "ES256",
    sign_key: ec.EllipticCurvePrivateKey | str | None = None,
    **claims: object,
) -> str:
    """Signe une preuve DPoP ES256 avec les claims fournis."""
    payload: dict[str, object] = {
        "jti": f"jti-{next(_JTI)}",
        "htm": method,
        "htu": htu,
        "iat": int(time.time()),
        **claims,
    }
    headers: dict[str, object] = {"typ": typ, "jwk": jwk if jwk is not None else _ec_jwk(key)}
    return str(
        pyjwt.encode(
            payload,
            key if sign_key is None else sign_key,
            algorithm=alg,
            headers=headers,
        )
    )


def _validator() -> tuple[PyJWTDpopProofValidator, InMemoryDpopReplayRepository]:
    """Validateur de preuves isolé sur son store anti-replay en mémoire."""
    replays = InMemoryDpopReplayRepository()
    return PyJWTDpopProofValidator(replays), replays


def _future_expiry() -> datetime:
    """Expiration dans le futur (évite l'expiration immédiate du défaut)."""
    return datetime.now(timezone.utc) + timedelta(minutes=5)


class TestJwkThumbprint:
    """Couvre jwk_thumbprint (RFC 7638 §3)."""

    def test_matches_rfc7638_vector(self) -> None:
        assert jwk_thumbprint(_RFC7638_JWK) == _RFC7638_THUMBPRINT

    def test_ec_thumbprint_is_base64url_sha256(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        thumbprint = jwk_thumbprint(_ec_jwk(key))

        assert len(thumbprint) == 43
        assert thumbprint == jwk_thumbprint(_ec_jwk(key))

    def test_unknown_kty_raises(self) -> None:
        with pytest.raises(ValueError, match="Famille JWK"):
            jwk_thumbprint({"kty": "oct", "k": "Zm9vYmFy"})


class TestDpopProofValidator:
    """Couvre PyJWTDpopProofValidator (RFC 9449 §4.3, §11)."""

    @staticmethod
    def _rejects(reason: str, proof: str, **kwargs: str) -> None:
        validator, _ = _validator()
        result = run(
            validator.validate(
                proof=proof,
                htu=kwargs.pop("htu", _TOKEN_ENDPOINT),
                method=kwargs.pop("method", "POST"),
                **kwargs,
            )
        )
        assert isinstance(result, DpopValidationError)
        assert reason in result.error_description

    def test_rejects_missing_proof(self) -> None:
        self._rejects("absente", "")

    def test_rejects_wrong_typ(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("typ", _proof(key, typ="jwt"))

    def test_rejects_symmetric_algorithm(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects(
            "algorithme",
            _proof(key, alg="HS256", sign_key="shared-secret"),
        )

    def test_rejects_private_key_member_in_jwk(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        jwk = {**_ec_jwk(key), "d": "le-secret"}
        self._rejects("clé privée", _proof(key, jwk=jwk, sign_key=key))

    def test_rejects_htm_mismatch(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("htm", _proof(key, method="GET"))

    def test_rejects_htu_mismatch(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("htu", _proof(key, htu=f"{_ISSUER}/revoke"))

    def test_rejects_future_iat(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("futur", _proof(key, iat=int(time.time()) + 3600))

    def test_rejects_stale_iat(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("ancienne", _proof(key, iat=int(time.time()) - 3600))

    def test_rejects_missing_iat(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        payload: dict[str, object] = {"jti": "sans-iat", "htm": "POST", "htu": _TOKEN_ENDPOINT}
        headers = {"typ": DPOP_PROOF_TYPE, "jwk": _ec_jwk(key)}
        proof = str(pyjwt.encode(payload, key, algorithm="ES256", headers=headers))
        self._rejects("iat", proof)

    def test_rejects_expiration_in_milliseconds(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("millisecondes", _proof(key, exp=int(time.time() * 1000)))

    def test_rejects_ath_absent_at_resource_server(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        self._rejects("ath", _proof(key), ath="zzz")

    def test_rejects_ath_mismatch(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key, ath=access_token_hash("autre-jeton"))
        self._rejects("ath", proof, ath=access_token_hash("jeton-presente"))

    def test_rejects_ath_at_token_endpoint(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key, ath=access_token_hash("jeton"))
        self._rejects("token endpoint", proof)

    def test_rejects_signature_of_another_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP256R1())
        self._rejects("Signature", _proof(key, sign_key=other))

    def test_rejects_replayed_jti(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        validator, _ = _validator()
        proof = _proof(key)
        first = run(validator.validate(proof=proof, htu=_TOKEN_ENDPOINT, method="POST"))
        second = run(validator.validate(proof=proof, htu=_TOKEN_ENDPOINT, method="POST"))

        assert not isinstance(first, DpopValidationError)
        assert isinstance(second, DpopValidationError)
        assert "déjà" in second.error_description

    def test_accepts_valid_proof_and_returns_binding(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        validator, replays = _validator()
        proof = _proof(key, nonce="server-nonce")

        result = run(validator.validate(proof=proof, htu=_TOKEN_ENDPOINT, method="POST"))

        assert not isinstance(result, DpopValidationError)
        assert result.jkt == jwk_thumbprint(_ec_jwk(key))
        assert result.nonce == "server-nonce"
        assert result.htm == "POST"
        assert run(replays.is_used(hashlib.sha256(result.jti.encode()).hexdigest()))


class TestDpopGrantGuard:
    """Couvre DpopGrantGuard (RFC 9449 §5.2, §10)."""

    @staticmethod
    def _guard() -> DpopGrantGuard:
        validator, _ = _validator()
        return DpopGrantGuard(validator)

    @staticmethod
    def _client(*, require_dpop: bool = False) -> Client:
        return Client(
            client_id=_CLIENT_ID,
            redirect_uris=frozenset({_REDIRECT_URI}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.PUBLIC,
            require_dpop=require_dpop,
        )

    @staticmethod
    def _evaluate(client: Client, proof: str, *, bound_jkt: str = "") -> object:
        return run(
            DpopGrantGuard(PyJWTDpopProofValidator(InMemoryDpopReplayRepository())).evaluate(
                client=client, proof=proof, htu=_TOKEN_ENDPOINT, bound_jkt=bound_jkt
            )
        )

    def test_requires_proof_when_client_flag_set(self) -> None:
        result = self._evaluate(self._client(require_dpop=True), "")

        assert isinstance(result, DpopGuardError)
        assert result.error == "invalid_request"

    def test_requires_proof_for_bound_request(self) -> None:
        result = self._evaluate(self._client(), "", bound_jkt="une-empreinte")

        assert isinstance(result, DpopGuardError)
        assert result.error == "invalid_request"

    def test_rejects_invalid_proof(self) -> None:
        result = self._evaluate(self._client(), "preuve-malformee")

        assert isinstance(result, DpopGuardError)
        assert result.error == "invalid_dpop_proof"

    def test_rejects_proof_of_another_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP256R1())
        bound = jwk_thumbprint(_ec_jwk(other))
        proof = _proof(key)

        result = self._evaluate(self._client(), proof, bound_jkt=bound)

        assert isinstance(result, DpopGuardError)
        assert result.error == "invalid_grant"

    def test_binds_token_when_proof_valid(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key)

        result = self._evaluate(self._client(), proof)

        assert isinstance(result, DpopBinding)
        assert result.bound is True
        assert result.jkt == jwk_thumbprint(_ec_jwk(key))

    def test_leaves_token_bearer_without_proof_or_flag(self) -> None:
        result = self._evaluate(self._client(), "")

        assert isinstance(result, DpopBinding)
        assert result.bound is False
        assert result.jkt == ""


class TestTokenUseCaseDPoP:
    """Couvre l'émission liée au token endpoint (RFC 9449 §5.1)."""

    def _make_usecase(
        self, *, require_dpop: bool = False
    ) -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository, InMemoryRefreshTokenRepository]:
        """Construit un TokenUseCase DPoP sur des repos en mémoire."""
        clients = InMemoryClientRepository()
        codes = InMemoryAuthorizationCodeRepository()
        refresh_tokens = InMemoryRefreshTokenRepository()
        replays = InMemoryDpopReplayRepository()
        device_codes = InMemoryDeviceAuthorizationRepository()
        run(
            clients.save(
                Client(
                    client_id=_CLIENT_ID,
                    redirect_uris=frozenset({_REDIRECT_URI}),
                    scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
                    client_type=ClientType.PUBLIC,
                    require_dpop=require_dpop,
                )
            )
        )
        token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        usecase = TokenUseCase(
            TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
            clients,
            codes,
            token_manager,
            refresh_tokens,
            device_codes,
            dpop=DpopGrantGuard(PyJWTDpopProofValidator(replays)),
        )
        return usecase, codes, refresh_tokens

    @staticmethod
    def _request(proof: str, *, code: str = "dpop-code") -> TokenRequest:
        return TokenRequest(
            grant_type="authorization_code",
            code=code,
            redirect_uri=_REDIRECT_URI,
            client_id=_CLIENT_ID,
            code_verifier="exact-match",
            dpop_proof=proof,
        )

    @staticmethod
    def _code(*, dpop_jkt: str = "") -> AuthorizationCode:
        """Code d'autorisation PKCE (client public) pour l'échange."""
        return AuthorizationCode(
            code="dpop-code",
            client_id=_CLIENT_ID,
            redirect_uri=_REDIRECT_URI,
            subject="alice",
            scopes=frozenset({Scope.OPENID}),
            dpop_jkt=dpop_jkt,
            code_challenge="exact-match",
            code_challenge_method="plain",
            expires_at=_future_expiry(),
        )

    def test_rejects_code_exchange_without_proof_when_required(self) -> None:
        usecase, codes, _ = self._make_usecase(require_dpop=True)
        run(codes.save(self._code()))

        result = run(usecase.execute(self._request("")))

        assert getattr(result, "error", "") == "invalid_request"

    def test_issues_bound_token_with_valid_proof(self) -> None:
        usecase, codes, _ = self._make_usecase(require_dpop=True)
        run(codes.save(self._code()))
        key = ec.generate_private_key(ec.SECP256R1())

        result = run(usecase.execute(self._request(_proof(key))))

        assert result.token_type == "DPoP"
        claims = pyjwt.decode(
            result.access_token, options={"verify_signature": False, "verify_exp": False}
        )
        assert claims["cnf"]["jkt"] == jwk_thumbprint(_ec_jwk(key))

    def test_rejects_bound_code_presented_without_proof(self) -> None:
        usecase, codes, _ = self._make_usecase()
        run(codes.save(self._code(dpop_jkt="une-empreinte")))

        result = run(usecase.execute(self._request("")))

        assert getattr(result, "error", "") == "invalid_request"

    def test_rejects_proof_of_another_key_on_bound_code(self) -> None:
        usecase, codes, _ = self._make_usecase()
        run(codes.save(self._code(dpop_jkt="une-empreinte")))
        key = ec.generate_private_key(ec.SECP256R1())

        result = run(usecase.execute(self._request(_proof(key))))

        assert getattr(result, "error", "") == "invalid_grant"

    def test_bound_refresh_keeps_link_across_renewal(self) -> None:
        usecase, _, refresh_tokens = self._make_usecase()
        key = ec.generate_private_key(ec.SECP256R1())
        thumbprint = jwk_thumbprint(_ec_jwk(key))
        run(
            refresh_tokens.save(
                RefreshToken(
                    token_hash=hashlib.sha256(b"refresh-dpop").hexdigest(),
                    client_id=_CLIENT_ID,
                    subject="alice",
                    scopes=frozenset({Scope.OPENID}),
                    expires_at=_future_expiry(),
                    dpop_jkt=thumbprint,
                )
            )
        )

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-dpop",
                    client_id=_CLIENT_ID,
                    dpop_proof=_proof(key),
                )
            )
        )

        assert result.token_type == "DPoP"
        claims = pyjwt.decode(
            result.access_token, options={"verify_signature": False, "verify_exp": False}
        )
        assert claims["cnf"]["jkt"] == thumbprint

    def test_rejects_bound_refresh_without_proof(self) -> None:
        usecase, _, refresh_tokens = self._make_usecase()
        run(
            refresh_tokens.save(
                RefreshToken(
                    token_hash=hashlib.sha256(b"refresh-dpop").hexdigest(),
                    client_id=_CLIENT_ID,
                    subject="alice",
                    scopes=frozenset({Scope.OPENID}),
                    expires_at=_future_expiry(),
                    dpop_jkt="une-empreinte",
                )
            )
        )

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-dpop",
                    client_id=_CLIENT_ID,
                )
            )
        )

        assert getattr(result, "error", "") == "invalid_request"


class TestUserInfoDPoP:
    """Couvre la présentation d'un jeton lié à /userinfo (RFC 9449 §7)."""

    @staticmethod
    def _usecase() -> tuple[UserInfoUseCase, PyJWTTokenManager]:
        """Construit le use case avec un token manager partagé pour l'émission."""
        validator, _ = _validator()
        token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER, userinfo_endpoint=_USERINFO_ENDPOINT),
            token_manager,
            UserStoreClaimsProvider(InMemoryUserRepository()),
            InMemoryRevokedTokenRepository(),
            dpop=validator,
        )
        return usecase, token_manager

    @staticmethod
    def _token(token_manager: PyJWTTokenManager, key: ec.EllipticCurvePrivateKey | None) -> str:
        """Émet un access token signé par ``token_manager``, lié si ``key`` est fourni."""
        additional: dict[str, object] | None = None
        if key is not None:
            additional = {"cnf": {"jkt": jwk_thumbprint(_ec_jwk(key))}}
        return run(
            token_manager.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience=_CLIENT_ID,
                expires_at=4102444800,
                issued_at=1700000000,
                scopes=frozenset({Scope.OPENID}),
                additional_claims=additional,
            )
        )

    def test_rejects_bearer_scheme_for_bound_token(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        usecase, token_manager = self._usecase()
        token = self._token(token_manager, key)

        result = run(usecase.execute(UserInfoRequest(access_token=token, auth_scheme="bearer")))

        assert isinstance(result, UserInfoError)
        assert result.error == "invalid_token"
        assert result.challenge.startswith('DPoP error="invalid_token"')

    def test_accepts_bound_token_with_matching_proof(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        usecase, token_manager = self._usecase()
        token = self._token(token_manager, key)
        proof = _proof(
            key,
            htu=_USERINFO_ENDPOINT,
            method="GET",
            ath=access_token_hash(token),
        )

        result = run(
            usecase.execute(
                UserInfoRequest(
                    access_token=token, auth_scheme="dpop", dpop_proof=proof, htu=_USERINFO_ENDPOINT
                )
            )
        )

        assert isinstance(result, UserInfoResponse)
        assert result.claims["sub"] == "alice"

    def test_rejects_bound_token_without_proof(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        usecase, token_manager = self._usecase()
        token = self._token(token_manager, key)

        result = run(
            usecase.execute(
                UserInfoRequest(access_token=token, auth_scheme="dpop", htu=_USERINFO_ENDPOINT)
            )
        )

        assert isinstance(result, UserInfoError)
        assert result.error == "invalid_token"

    def test_rejects_proof_of_another_key(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        other = ec.generate_private_key(ec.SECP256R1())
        usecase, token_manager = self._usecase()
        token = self._token(token_manager, key)
        proof = _proof(other, htu=_USERINFO_ENDPOINT, method="GET", ath=access_token_hash(token))

        result = run(
            usecase.execute(
                UserInfoRequest(
                    access_token=token, auth_scheme="dpop", dpop_proof=proof, htu=_USERINFO_ENDPOINT
                )
            )
        )

        assert isinstance(result, UserInfoError)
        assert result.error == "invalid_dpop_proof"

    def test_accepts_unbound_token_in_bearer(self) -> None:
        usecase, token_manager = self._usecase()
        token = self._token(token_manager, None)

        result = run(usecase.execute(UserInfoRequest(access_token=token)))

        assert isinstance(result, UserInfoResponse)
        assert result.claims["sub"] == "alice"


class TestParDpopProof:
    """Couvre la preuve DPoP au push (RFC 9449 §10.1)."""

    @staticmethod
    def _usecase(validator: PyJWTDpopProofValidator | None = None) -> PushedAuthorizationUseCase:
        """Construit le use case /par sur un client public de test."""
        clients = InMemoryClientRepository()
        run(
            clients.save(
                Client(
                    client_id=_CLIENT_ID,
                    redirect_uris=frozenset({_REDIRECT_URI}),
                    scopes=frozenset({Scope.OPENID}),
                    client_type=ClientType.PUBLIC,
                )
            )
        )
        return PushedAuthorizationUseCase(
            PushedAuthorizationConfig(par_endpoint=_PAR_ENDPOINT),
            clients,
            InMemoryPushedAuthorizationRepository(),
            dpop=validator,
        )

    @staticmethod
    def _params(**extra: str) -> dict[str, str]:
        """Paramètres de push minimaux (code + openid) complétés par ``extra``."""
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": _CLIENT_ID,
            "redirect_uri": _REDIRECT_URI,
            "scope": "openid",
        }
        params.update(extra)
        return params

    def test_rejects_mismatch_between_dpop_jkt_and_proof(self) -> None:
        validator, _ = _validator()
        usecase = self._usecase(validator)
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key, htu=_PAR_ENDPOINT)

        result = run(usecase.push(self._params(dpop_jkt="autre-empreinte"), dpop_proof=proof))

        assert isinstance(result, PushError)
        assert result.error == "invalid_dpop_proof"

    def test_injects_jkt_from_proof_when_not_declared(self) -> None:
        validator, _ = _validator()
        usecase = self._usecase(validator)
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key, htu=_PAR_ENDPOINT)

        result = run(usecase.push(self._params(), dpop_proof=proof))

        assert isinstance(result, PushResult)

    def test_accepts_push_without_proof(self) -> None:
        validator, _ = _validator()
        usecase = self._usecase(validator)

        result = run(usecase.push(self._params()))

        assert isinstance(result, PushResult)

    def test_rejects_proof_when_validator_absent(self) -> None:
        usecase = self._usecase()
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key, htu=_PAR_ENDPOINT)

        result = run(usecase.push(self._params(), dpop_proof=proof))

        assert isinstance(result, PushError)
        assert result.error == "invalid_dpop_proof"


class TestDpopHttpEndpoints:
    """Couvre les endpoints HTTP DPoP (/token, /userinfo, discovery, /par)."""

    _SEED: ClassVar[dict[str, object]] = {
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
        "redirect_uris": [_REDIRECT_URI],
        "scopes": "openid",
        "client_type": "confidential",
        "require_dpop": True,
    }

    @staticmethod
    def _app() -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                clients_seed=(TestDpopHttpEndpoints._SEED,),
                api_resources_seed=(),
            )
        )

    @staticmethod
    def _s256_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _authorization_code(self, client: TestClient) -> str:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid",
                "code_challenge": self._s256_challenge("verifier-verifier"),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        return parse_qs(urlparse(auth.headers["location"]).query)["code"][0]

    @staticmethod
    def _token_request(
        client: TestClient, code: str, *, proofs: tuple[str, ...] = ()
    ) -> httpx.Response:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT_URI,
            "client_id": _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "code_verifier": "verifier-verifier",
        }
        headers: dict[str, str] | list[tuple[str, str]] = {}
        if len(proofs) == 1:
            headers = {"DPoP": proofs[0]}
        elif len(proofs) > 1:
            headers = [("DPoP", value) for value in proofs]
        return client.post("/token", data=data, headers=headers)

    def test_token_rejects_missing_proof_when_required(self) -> None:
        with TestClient(self._app()) as client:
            code = self._authorization_code(client)
            response = self._token_request(client, code)

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_token_issues_dpop_bound_access_token(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with TestClient(self._app()) as client:
            code = self._authorization_code(client)
            response = self._token_request(client, code, proofs=(_proof(key),))

        assert response.status_code == 200
        payload = response.json()
        assert payload["token_type"] == "DPoP"
        claims = pyjwt.decode(
            payload["access_token"], options={"verify_signature": False, "verify_exp": False}
        )
        assert claims["cnf"]["jkt"] == jwk_thumbprint(_ec_jwk(key))

    def test_token_rejects_duplicate_dpop_headers(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        proof = _proof(key)
        with TestClient(self._app()) as client:
            code = self._authorization_code(client)
            response = self._token_request(client, code, proofs=(proof, proof))

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_userinfo_rejects_bound_token_with_bearer_scheme(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with TestClient(self._app()) as client:
            code = self._authorization_code(client)
            token = self._token_request(client, code, proofs=(_proof(key),)).json()["access_token"]
            response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith('DPoP error="invalid_token"')

    def test_userinfo_accepts_bound_token_with_proof(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with TestClient(self._app()) as client:
            code = self._authorization_code(client)
            token = self._token_request(client, code, proofs=(_proof(key),)).json()["access_token"]
            proof = _proof(
                key,
                htu="http://testserver/userinfo",
                method="GET",
                ath=access_token_hash(token),
            )
            response = client.get(
                "/userinfo",
                headers={"Authorization": f"DPoP {token}", "DPoP": proof},
            )

        assert response.status_code == 200
        assert response.json()["sub"] == ""

    def test_discovery_advertises_dpop_signing_algorithms(self) -> None:
        with TestClient(self._app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        algorithms = metadata["dpop_signing_alg_values_supported"]
        assert "RS256" in algorithms
        assert "none" not in algorithms
        assert not any(name.startswith("HS") for name in algorithms)

    def test_par_rejects_proof_mismatching_dpop_jkt(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        with TestClient(self._app()) as client:
            response = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "client_secret": _CLIENT_SECRET,
                    "redirect_uri": _REDIRECT_URI,
                    "scope": "openid",
                    "dpop_jkt": "autre-empreinte",
                },
                headers={"DPoP": _proof(key, htu=_PAR_ENDPOINT)},
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_dpop_proof"


class TestRegistrationDPoP:
    """Couvre ``dpop_bound_access_tokens`` à l'enregistrement (RFC 9449 §5.1)."""

    @staticmethod
    def _usecase() -> RegistrationUseCase:
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=False,
        )
        return RegistrationUseCase(config, InMemoryClientRepository())

    def test_echoes_dpop_bound_access_tokens_flag(self) -> None:
        result = run(
            self._usecase().register(
                RegisterRequest(
                    metadata={
                        "redirect_uris": [_REDIRECT_URI],
                        "dpop_bound_access_tokens": True,
                    }
                )
            )
        )

        assert result.dpop_bound_access_tokens is True

    def test_defaults_flag_to_false(self) -> None:
        result = run(
            self._usecase().register(RegisterRequest(metadata={"redirect_uris": [_REDIRECT_URI]}))
        )

        assert result.dpop_bound_access_tokens is False

    def test_rejects_non_boolean_flag(self) -> None:
        result = run(
            self._usecase().register(
                RegisterRequest(
                    metadata={
                        "redirect_uris": [_REDIRECT_URI],
                        "dpop_bound_access_tokens": "oui",
                    }
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
