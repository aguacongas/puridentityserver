"""Tests pour le slice d'issuance OpenID4VCI (subset #222)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from puridentityserver.application.oid4vci import (
    CREDENTIAL_CONFIGURATION_ID,
    CredentialError,
    OID4VCIIssuerUseCase,
    credential_vct,
)
from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.dpop import DPoPProof
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.domain.dpop import DpopValidationError

ISSUER = "https://id.example"


def _token_manager() -> PyJWTTokenManager:
    return PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))


def _proof(
    nonce: str,
    *,
    audience: str = ISSUER,
    signing_key: object | None = None,
    proof_type: str = "openid4vci-proof+jwt",
) -> str:
    """Construit une preuve ``jwt`` complète, signée pour l'audience demandée."""
    private_key = signing_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    jwk["alg"] = "RS256"
    now = int(datetime.now(timezone.utc).timestamp())
    return pyjwt.encode(
        {"aud": audience, "iat": now, "nonce": nonce},
        private_key,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"typ": proof_type, "jwk": jwk},
    )


class _FakeTokenManager:
    """Gestionnaire de jetons factice : rend les claims imposés."""

    def __init__(self, claims: dict[str, object] | None) -> None:
        self._claims = claims

    async def validate_access_token(self, *, token: str, issuer: str) -> dict[str, object] | None:
        return self._claims


class _FakeDpopValidator:
    """Validateur DPoP factice : rend le résultat imposé."""

    def __init__(self, result: object) -> None:
        self._result = result
        self.calls = 0

    async def validate(self, *, proof: str, htu: str, method: str, ath: str = "") -> object:
        self.calls += 1
        return self._result


def _usecase_with(
    claims: dict[str, object] | None, dpop: _FakeDpopValidator | None = None
) -> OID4VCIIssuerUseCase:
    return OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=DefaultKeyManager(InMemoryKeyPairRepository()),
        algorithm=JWTAlgorithm.RS256,
        token_manager=_FakeTokenManager(claims),  # type: ignore[arg-type]
        dpop=dpop,  # type: ignore[arg-type]
    )


async def _ready_usecase() -> tuple[OID4VCIIssuerUseCase, str]:
    """Prépare un émetteur avec une clé active et un access token valide."""
    token_manager = _token_manager()
    now = int(datetime.now(timezone.utc).timestamp())
    await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
    token = await token_manager.create_access_token(
        algorithm=JWTAlgorithm.RS256,
        issuer=ISSUER,
        subject="alice",
        audience="wallet-client",
        expires_at=now + 600,
        issued_at=now,
        scopes=frozenset({Scope.OID4VCI}),
    )
    usecase = OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=token_manager._key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=token_manager,
    )
    return usecase, token


def test_issuer_issues_sdjwt_credential_for_valid_access_token() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]
        result = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof(nonce),),
        )
        assert isinstance(result, dict)
        credential = result["credentials"][0]["credential"]
        assert isinstance(credential, str)
        # Format combiné SD-JWT (RFC 9901 §8.1) : JWT + ``~`` sans divulgation.
        assert credential.endswith("~")
        signed = credential.split("~")[0]
        assert signed.count(".") == 2
        header = pyjwt.get_unverified_header(signed)
        assert header["typ"] == "dc+sd-jwt"
        claims = pyjwt.decode(signed, options={"verify_signature": False})
        assert claims["vct"] == credential_vct(ISSUER)
        assert claims["sub"] == "alice"
        # La JWK de la preuve est liée au credential (OID4VCI 1.0 §7.1).
        assert claims["cnf"]["jwk"]["kty"] == "RSA"

    asyncio.run(_task())


def test_issued_c_nonce_can_authorize_a_second_request() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        first_nonce = (await usecase.issue_nonce())["c_nonce"]
        first = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof(first_nonce),),
        )
        assert isinstance(first, dict)
        second_nonce = (await usecase.issue_nonce())["c_nonce"]
        second = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof(second_nonce),),
        )
        assert isinstance(second, dict)

    asyncio.run(_task())


def test_issuer_rejects_invalid_access_token() -> None:
    usecase = _usecase_with(None)

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        error = await usecase.issue_credential(
            "not-a-valid-jwt", credential_configuration_id=CREDENTIAL_CONFIGURATION_ID
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_token"
        assert error.status_code == 401

    asyncio.run(_task())


def test_issuer_rejects_malformed_proof() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=("not-a-jwt",),
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_proof"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_requires_proof() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(
            token, credential_configuration_id=CREDENTIAL_CONFIGURATION_ID
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_proof"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_rejects_invalid_proof_signature() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]
        proof = _proof(nonce)
        broken = f"{proof[:-4]}AAAA"
        error = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(broken,),
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_proof"

    asyncio.run(_task())


def test_issuer_rejects_proof_for_another_audience() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]
        error = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof(nonce, audience="https://other.example"),),
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_proof"

    asyncio.run(_task())


def test_issuer_rejects_unknown_c_nonce() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof("random-value"),),
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_nonce"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_rejects_unknown_credential_configuration() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(
            token, credential_configuration_id="unknown-configuration"
        )
        assert isinstance(error, CredentialError)
        assert error.error == "unknown_credential_configuration"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_rejects_unknown_credential_identifier() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(token, credential_identifier="unknown-identifier")
        assert isinstance(error, CredentialError)
        assert error.error == "unknown_credential_identifier"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_rejects_missing_configuration_target() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(token)
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_credential_request"
        assert error.status_code == 400

    asyncio.run(_task())


def test_issuer_rejects_unsupported_format() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        error = await usecase.issue_credential(
            token,
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            requested_format="ldp_vc",
        )
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_credential_request"
        assert error.status_code == 400

    asyncio.run(_task())


def test_bound_token_requires_dpop_scheme() -> None:
    usecase = _usecase_with({"sub": "alice", "cnf": {"jkt": "thumbprint"}})

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        error = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            auth_scheme="bearer",
        )
        assert isinstance(error, CredentialError)
        assert error.status_code == 401

    asyncio.run(_task())


def test_bound_token_rejected_without_dpop_proof() -> None:
    usecase = _usecase_with({"sub": "alice", "cnf": {"jkt": "thumbprint"}})

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        error = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            auth_scheme="dpop",
        )
        assert isinstance(error, CredentialError)
        assert error.status_code == 401

    asyncio.run(_task())


def test_bound_token_accepted_with_matching_dpop_proof() -> None:
    validator = _FakeDpopValidator(
        DPoPProof(jkt="thumbprint", jti="j", htm="POST", htu="https://id.example/credential")
    )
    usecase = _usecase_with(
        {"sub": "alice", "scope": "openid4vci", "cnf": {"jkt": "thumbprint"}}, validator
    )

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        nonce = (await usecase.issue_nonce())["c_nonce"]
        result = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=(_proof(nonce),),
            auth_scheme="dpop",
            dpop_proof="proof",
            htu="https://id.example/credential",
        )
        assert isinstance(result, dict)
        assert validator.calls == 1

    asyncio.run(_task())


def test_bound_token_rejected_when_dpop_proof_invalid() -> None:
    validator = _FakeDpopValidator(DpopValidationError("invalid_dpop_proof", "bad"))
    usecase = _usecase_with(
        {"sub": "alice", "scope": "openid4vci", "cnf": {"jkt": "thumbprint"}}, validator
    )

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        error = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            auth_scheme="dpop",
        )
        assert isinstance(error, CredentialError)
        assert error.status_code == 401

    asyncio.run(_task())


def test_bound_token_rejected_when_dpop_key_differs() -> None:
    validator = _FakeDpopValidator(
        DPoPProof(jkt="other", jti="j", htm="POST", htu="https://id.example/credential")
    )
    usecase = _usecase_with(
        {"sub": "alice", "scope": "openid4vci", "cnf": {"jkt": "thumbprint"}}, validator
    )

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        error = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            auth_scheme="dpop",
        )
        assert isinstance(error, CredentialError)
        assert error.status_code == 401

    asyncio.run(_task())


def test_key_attestation_valid_signature_accepted() -> None:
    """Une attestation de cle valide est acceptee (OID4VCI appendice D.1)."""
    import asyncio

    key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
    usecase = OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=_FakeTokenManager({"sub": "user1", "scope": "openid4vci"}),
    )
    nonce = asyncio.run(usecase.issue_nonce())["c_nonce"]

    bind_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bind_jwk = RSAAlgorithm.to_jwk(bind_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    bind_jwk["alg"] = "RS256"

    att_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    att_jwk = RSAAlgorithm.to_jwk(att_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    att_jwk["alg"] = "RS256"
    now = int(datetime.now(timezone.utc).timestamp())
    attestation = pyjwt.encode(
        {"iat": now, "exp": now + 300, "attested_keys": {"keys": [bind_jwk]}},
        att_key,
        algorithm="RS256",
        headers={"typ": "key-attestation+jwt", "jwk": att_jwk},
    )

    proof = pyjwt.encode(
        {"aud": ISSUER, "iat": now, "nonce": nonce},
        bind_key,
        algorithm="RS256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": bind_jwk, "key_attestation": attestation},
    )

    result = asyncio.run(
        usecase.issue_credential(
            "dummy",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=[proof],
        )
    )
    assert isinstance(result, dict)
    assert len(result["credentials"]) == 1


def test_key_attestation_invalid_signature_rejected() -> None:
    """Une attestation de cle a signature invalide est rejetee (invalid_proof)."""
    import asyncio

    key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
    usecase = OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=_FakeTokenManager({"sub": "user1", "scope": "openid4vci"}),
    )
    nonce = asyncio.run(usecase.issue_nonce())["c_nonce"]

    bind_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bind_jwk = RSAAlgorithm.to_jwk(bind_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    bind_jwk["alg"] = "RS256"

    att_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    att_jwk = RSAAlgorithm.to_jwk(att_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    att_jwk["alg"] = "RS256"
    now = int(datetime.now(timezone.utc).timestamp())
    attestation = pyjwt.encode(
        {"iat": now, "exp": now + 300},
        att_key,
        algorithm="RS256",
        headers={"typ": "key-attestation+jwt", "jwk": att_jwk},
    )
    parts = attestation.split(".")
    bad_attestation = parts[0] + "." + parts[1] + "." + ("A" + parts[2][1:])

    proof = pyjwt.encode(
        {"aud": ISSUER, "iat": now, "nonce": nonce},
        bind_key,
        algorithm="RS256",
        headers={
            "typ": "openid4vci-proof+jwt",
            "jwk": bind_jwk,
            "key_attestation": bad_attestation,
        },
    )

    result = asyncio.run(
        usecase.issue_credential(
            "dummy",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=[proof],
        )
    )
    assert isinstance(result, CredentialError)
    assert result.error == "invalid_proof"


def test_key_attestation_x509_valid_accepted() -> None:
    """Branche x5c : attestation valide acceptee."""
    import asyncio
    import base64

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID

    key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
    usecase = OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=_FakeTokenManager({"sub": "user1", "scope": "openid4vci"}),
    )
    nonce = asyncio.run(usecase.issue_nonce())["c_nonce"]

    bind_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bind_jwk = RSAAlgorithm.to_jwk(bind_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    bind_jwk["alg"] = "RS256"

    ec_key = _ec.generate_private_key(_ec.SECP256R1())
    subject = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "attester")])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ec_key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + __import__("datetime").timedelta(hours=1))
        .sign(ec_key, hashes.SHA256())
    )
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    now = int(datetime.now(timezone.utc).timestamp())
    attestation = pyjwt.encode(
        {"iat": now, "exp": now + 300},
        ec_key,
        algorithm="ES256",
        headers={"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [x5c]},
    )

    proof = pyjwt.encode(
        {"aud": ISSUER, "iat": now, "nonce": nonce},
        bind_key,
        algorithm="RS256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": bind_jwk, "key_attestation": attestation},
    )

    result = asyncio.run(
        usecase.issue_credential(
            "dummy",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            proofs=[proof],
        )
    )
    assert isinstance(result, dict)


def test_issuer_issues_with_authorization_details() -> None:
    claims = {
        "sub": "user1",
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
                "credential_identifiers": [CREDENTIAL_CONFIGURATION_ID],
            }
        ],
    }
    usecase = _usecase_with(claims)

    async def _task() -> None:
        await usecase._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
        nonce = (await usecase.issue_nonce())["c_nonce"]
        proof = _proof(nonce)
        result = await usecase.issue_credential(
            "token",
            credential_identifier=CREDENTIAL_CONFIGURATION_ID,
            proofs=(proof,),
        )
        assert isinstance(result, dict)

    asyncio.run(_task())


def test_issuer_rejects_config_with_authorization_details() -> None:
    claims = {
        "sub": "user1",
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
                "credential_identifiers": [CREDENTIAL_CONFIGURATION_ID],
            }
        ],
    }
    usecase = _usecase_with(claims)

    async def _task() -> None:
        result = await usecase.issue_credential(
            "token",
            credential_configuration_id=CREDENTIAL_CONFIGURATION_ID,
            credential_identifier=CREDENTIAL_CONFIGURATION_ID,
            proofs=(),
        )
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_credential_request"

    asyncio.run(_task())


def test_issuer_requires_identifier_with_authorization_details() -> None:
    claims = {
        "sub": "user1",
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
                "credential_identifiers": [CREDENTIAL_CONFIGURATION_ID],
            }
        ],
    }
    usecase = _usecase_with(claims)

    async def _task() -> None:
        result = await usecase.issue_credential("token", proofs=())
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_credential_request"

    asyncio.run(_task())


def test_issuer_rejects_unknown_identifier_with_authorization_details() -> None:
    claims = {
        "sub": "user1",
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
                "credential_identifiers": [CREDENTIAL_CONFIGURATION_ID],
            }
        ],
    }
    usecase = _usecase_with(claims)

    async def _task() -> None:
        result = await usecase.issue_credential("token", credential_identifier="nope", proofs=())
        assert isinstance(result, CredentialError)
        assert result.error == "unknown_credential_identifier"

    asyncio.run(_task())


def test_deferred_credential_returns_invalid_transaction() -> None:
    usecase = _usecase_with({"sub": "user1", "scope": "openid4vci"})

    async def _task() -> None:
        result = await usecase.deferred_credential("token", "tid")
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_transaction_id"

    asyncio.run(_task())


def test_deferred_credential_rejects_invalid_token() -> None:
    usecase = _usecase_with(None)

    async def _task() -> None:
        result = await usecase.deferred_credential("token", "tid")
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_token"

    asyncio.run(_task())


def test_notify_rejects_unknown_id() -> None:
    usecase = _usecase_with({"sub": "user1", "scope": "openid4vci"})

    async def _task() -> None:
        result = await usecase.notify("token", "nope", "credential_accepted")
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_notification_id"

    asyncio.run(_task())


def test_notify_rejects_invalid_event() -> None:
    usecase = _usecase_with({"sub": "user1", "scope": "openid4vci"})
    usecase._notifications.add("nid")

    async def _task() -> None:
        result = await usecase.notify("token", "nid", "bad")
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_notification_request"

    asyncio.run(_task())


def test_notify_accepts_registered_id() -> None:
    usecase = _usecase_with({"sub": "user1", "scope": "openid4vci"})
    usecase._notifications.add("nid")

    async def _task() -> None:
        result = await usecase.notify("token", "nid", "credential_accepted")
        assert result is None

    asyncio.run(_task())


def test_notify_rejects_invalid_token() -> None:
    usecase = _usecase_with(None)

    async def _task() -> None:
        result = await usecase.notify("token", "nid", "credential_accepted")
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_token"

    asyncio.run(_task())
