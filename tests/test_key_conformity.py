"""Tests de conformité des clés JWKS enregistrées par un client (#47, jalon 3).

Couvre la validation structurelle des JWK (RFC 7517/7518 : ``kty`` supporté,
membres ``n``/``e`` ou ``crv``/``x``/``y`` requis et intègres, module RSA
>= 2048 bits, ``use``/``alg`` cohérents), son application à l'enregistrement
(rejet ``invalid_client_metadata``) et la défense rejouée à l'émission
(``RSA-OAEP*`` chiffre l'``id_token``, ``private_key_jwt`` signe l'assertion).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from puridentityserver.application.registration import (
    RegisterRequest,
    RegistrationConfig,
    RegistrationError,
    RegistrationUseCase,
    hash_secret,
)
from puridentityserver.domain.key_validation import (
    require_encryption_rsa_key,
    require_signing_key,
    usable_for_signing,
    validate_client_jwks,
)
from puridentityserver.infrastructure.client_assertions import (
    PyJWTClientAssertionVerifier,
    verify_jwks_assertion,
)
from puridentityserver.infrastructure.jwe import JWEUnavailableError, rsa_public_key_from_jwks
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_REDIRECT_URI = "https://app.example/callback"

_INITIAL_TOKEN = "registrar-token"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _b64u(value: int) -> str:
    """Encode un entier en base64url big-endian sans padding (RFC 7517 §4.3)."""
    return (
        __import__("base64")
        .urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))
        .rstrip(b"=")
        .decode("ascii")
    )


def _rsa_public(width: int, *, use: str = "sig", alg: str = "RS256") -> dict[str, object]:
    """JWK public RSA d'une paire générée (``width`` = taille du module)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=width)
    numbers = private.public_key().public_numbers()
    key: dict[str, object] = {
        "kty": "RSA",
        "kid": "key-1",
        "n": _b64u(numbers.n),
        "e": _b64u(numbers.e),
    }
    if use:
        key["use"] = use
    if alg:
        key["alg"] = alg
    return key


def _private_rsa(width: int = 2048) -> rsa.RSAPrivateKey:
    """Paire privée RSA de la largeur demandée (signature des assertions de test)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=width)


def _ec_key(curve: str = "P-256") -> dict[str, object]:
    """JWK EC factice structurellement valide (coordonnées d'un point canonique)."""
    return {
        "kty": "EC",
        "kid": "ec-1",
        "crv": curve,
        "use": "sig",
        "alg": "ES256",
        "x": _b64u(4),
        "y": _b64u(9),
    }


def _assertion(
    private: rsa.RSAPrivateKey,
    kid: str,
    *,
    issuer: str = "jwt-client",
    subject: str = "jwt-client",
    audience: str = "https://id.example/token",
) -> str:
    """Assertion JWT RS256 signée avec ``private``, adressée au token endpoint."""
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        private,
        algorithm="RS256",
        headers={"kid": kid},
    )


class TestValidateClientJwks:
    """Validation structurelle unitaire de chaque JWK (RFC 7517/7518)."""

    def test_accepts_rsa_and_ec_keys(self) -> None:
        assert validate_client_jwks((_rsa_public(2048), _ec_key())) == ()

    def test_rejects_unknown_kty(self) -> None:
        problems = validate_client_jwks(({"kty": "OKP", "use": "sig"},))
        assert len(problems) == 1
        assert "kty 'OKP' non supporté" in problems[0]

    def test_rejects_oct_symmetric_key(self) -> None:
        problems = validate_client_jwks(({"kty": "oct", "k": _b64u(1)},))
        assert "oct" in problems[0]

    def test_rejects_rsa_missing_members(self) -> None:
        problems = validate_client_jwks(({"kty": "RSA", "n": _b64u(1 << 2047)},))
        assert "n et e requis" in problems[0]

    def test_rejects_rsa_invalid_base64(self) -> None:
        problems = validate_client_jwks(({"kty": "RSA", "n": "!!pas-une-cle!!", "e": "AQAB"},))
        assert "n et e requis" in problems[0]

    def test_rejects_short_rsa_modulus(self) -> None:
        problems = validate_client_jwks((_rsa_public(1024),))
        assert len(problems) == 1
        assert "2048" in problems[0]

    def test_rejects_unknown_use(self) -> None:
        problems = validate_client_jwks(({**_rsa_public(2048), "use": "wrap"},))
        assert "use 'wrap' non supporté" in problems[0]

    def test_rejects_alg_inconsistent_with_kty(self) -> None:
        problems = validate_client_jwks(({**_rsa_public(2048), "alg": "ES256"},))
        assert "alg 'ES256' non supporté pour une clé RSA" in problems[0]

    def test_accepts_encryption_algorithm_on_rsa(self) -> None:
        problems = validate_client_jwks(({**_rsa_public(2048), "use": "enc", "alg": "RSA-OAEP"},))
        assert problems == ()

    def test_rejects_ec_without_curve(self) -> None:
        problems = validate_client_jwks(({"kty": "EC", "x": _b64u(4), "y": _b64u(9)},))
        assert "crv 'None' non supporté" in problems[0]

    def test_rejects_unknown_ec_curve(self) -> None:
        problems = validate_client_jwks(({**_ec_key("P-224")},))
        assert "crv 'P-224' non supporté" in problems[0]


class TestKeyUsageSelectors:
    """Sélection des clés par usage (signature vs chiffrement RSA-OAEP)."""

    def test_usable_for_signing_excludes_enc_keys(self) -> None:
        enc = _rsa_public(2048, use="enc")
        sig = _rsa_public(2048, use="sig")
        assert usable_for_signing((enc, sig)) == (sig,)

    def test_usable_for_signing_keeps_unspecified_use(self) -> None:
        key = {**_rsa_public(2048), "use": None}
        assert usable_for_signing((key,)) == (key,)

    def test_require_signing_key_on_enc_only_keys(self) -> None:
        problem = require_signing_key((_rsa_public(2048, use="enc"),))
        assert problem is not None
        assert "private_key_jwt" in problem

    def test_require_signing_key_accepts_ec(self) -> None:
        assert require_signing_key((_ec_key(),)) is None

    def test_require_encryption_key_skips_sig_keys(self) -> None:
        problem = require_encryption_rsa_key((_rsa_public(2048, use="sig"),))
        assert problem is not None
        assert "RSA-OAEP" in problem

    def test_require_encryption_key_accepts_enc_key(self) -> None:
        assert require_encryption_rsa_key((_rsa_public(2048, use="enc"),)) is None

    def test_require_encryption_key_rejects_short_modulus(self) -> None:
        assert require_encryption_rsa_key((_rsa_public(1024, use="enc"),)) is not None


class TestRegistrationKeyConformity:
    """L'enregistrement rejette les clés non conformes (RFC 7591 §2.1)."""

    def _usecase(self) -> RegistrationUseCase:
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=True,
            initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
        )
        return RegistrationUseCase(config, InMemoryClientRepository())

    def _register(self, metadata: dict[str, object]) -> RegistrationError | object:
        return run(
            self._usecase().register(RegisterRequest(metadata, initial_access_token=_INITIAL_TOKEN))
        )

    def test_rejects_structural_broken_key(self) -> None:
        result = self._register(
            {
                "redirect_uris": [_REDIRECT_URI],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [{"kty": "RSA", "use": "sig"}]},
            }
        )
        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "n et e requis" in result.error_description

    def test_rejects_oct_key(self) -> None:
        result = self._register(
            {
                "redirect_uris": [_REDIRECT_URI],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [{"kty": "oct", "k": _b64u(1)}]},
            }
        )
        assert isinstance(result, RegistrationError)
        assert "kty 'oct' non supporté" in result.error_description

    def test_rejects_private_key_jwt_with_enc_only_key(self) -> None:
        result = self._register(
            {
                "redirect_uris": [_REDIRECT_URI],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [_rsa_public(2048, use="enc", alg="RSA-OAEP")]},
            }
        )
        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "Aucune clé de signature" in result.error_description

    def test_accepts_private_key_jwt_with_signing_key(self) -> None:
        result = self._register(
            {
                "redirect_uris": [_REDIRECT_URI],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [_rsa_public(2048, use="sig")]},
            }
        )
        assert not isinstance(result, RegistrationError)

    def test_rejects_rsa_oaep_with_signing_only_key(self) -> None:
        result = self._register(
            {
                "redirect_uris": [_REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_basic",
                "jwks": {"keys": [_rsa_public(2048, use="sig")]},
                "id_token_encrypted_response_alg": "RSA-OAEP",
            }
        )
        assert isinstance(result, RegistrationError)
        assert "Aucune clé publique RSA" in result.error_description


class TestEmissionDefense:
    """Les vérifications sont rejouées à l'émission (défense en profondeur)."""

    def test_rsa_public_key_rejects_short_modulus(self) -> None:
        key = _rsa_public(1024, use="enc")
        with pytest.raises(JWEUnavailableError, match="aucune clé publique RSA"):
            rsa_public_key_from_jwks((key,))

    def test_rsa_public_key_accepts_conform_key(self) -> None:
        assert rsa_public_key_from_jwks((_rsa_public(2048, use="enc"),)) is not None

    def test_assertion_verifier_rejects_enc_only_embedded_key(self) -> None:
        private = _private_rsa()
        enc_jwks = {
            **_rsa_public(2048, use="enc"),
            "kid": "enc-only",
            "n": _b64u(private.public_key().public_numbers().n),
            "e": _b64u(private.public_key().public_numbers().e),
        }
        token = _assertion(private, str(enc_jwks["kid"]))

        claims = run(
            verify_jwks_assertion(
                token,
                audience="https://id.example/token",
                issuer="jwt-client",
                jwks=(enc_jwks,),
            )
        )

        assert claims is None

    def test_assertion_verifier_accepts_signing_embedded_key(self) -> None:
        private = _private_rsa()
        sig_jwks = {
            **_rsa_public(2048, use="sig"),
            "kid": "sig-ok",
            "n": _b64u(private.public_key().public_numbers().n),
            "e": _b64u(private.public_key().public_numbers().e),
        }
        token = _assertion(private, str(sig_jwks["kid"]))

        claims = run(
            verify_jwks_assertion(
                token,
                audience="https://id.example/token",
                issuer="jwt-client",
                jwks=(sig_jwks,),
            )
        )

        assert claims is not None
        assert claims["sub"] == "jwt-client"

    def test_verifier_entry_point_uses_embedded_keys(self) -> None:
        private = _private_rsa()
        sig_jwks = {
            **_rsa_public(2048, use="sig"),
            "kid": "sig-ok",
            "n": _b64u(private.public_key().public_numbers().n),
            "e": _b64u(private.public_key().public_numbers().e),
        }
        token = _assertion(private, str(sig_jwks["kid"]))
        from puridentityserver.domain.authorization import Client, ClientType, Scope

        client = Client(
            client_id="jwt-client",
            redirect_uris=frozenset({_REDIRECT_URI}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            jwks=(sig_jwks,),
        )
        verifier = PyJWTClientAssertionVerifier()

        claims = run(
            verifier.verify(
                token=token,
                client=client,
                audience="https://id.example/token",
                require_iss_eq_sub=True,
            )
        )

        assert claims is not None
