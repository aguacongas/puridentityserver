"""Tests du chiffrement ECDH-ES des credential requests/réponses OID4VCI (issues #304/#310).

Le réglage ``oid4vci_encryption_enabled`` publie les blocs
``credential_request_encryption`` / ``credential_response_encryption`` dans
les métadonnées, accepte les corps ``/credential`` en ``application/jwt`` et
scelle les réponses demandées (OID4VCI 1.0 §8.2). Désactivé par défaut,
aucune capability n'est annoncée ni acceptée. La famille de clés
``KeyUse.CREDENTIAL`` est mise en rotation au démarrage (issue #310) :
les clés antérieures restent publiées et déchiffrables (drain).
"""

from __future__ import annotations

import asyncio
import json
import time
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from puridentityprotocol.server import ProtocolDependencies
from puridentityserver.application.oid4vci import (
    ALG_VALUES_SUPPORTED,
    CREDENTIAL_CONFIGURATION_ID,
    CREDENTIAL_KEY_SIZE,
    CredentialError,
    CredentialResponseEncryption,
    OID4VCIIssuerUseCase,
    issuer_metadata_payload,
)
from puridentityserver.domain.jwe import ECDH_ES, JWEEncryptionMethod
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair, KeyUse
from puridentityserver.infrastructure.dpop import jwk_thumbprint
from puridentityserver.infrastructure.jwe import (
    b64u,
    decrypt_compact_ecdh_es,
    deflate_compress,
    deflate_decompress,
    ec_jwk,
    ec_public_key,
    encrypt_compact_ecdh_es,
    protected_header,
)
from puridentityserver.infrastructure.jwks import (
    DefaultKeyManager,
    load_credential_key_pair,
    pem_key_kid,
    rotate_if_stale,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.stores import build_stores
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_ISSUER = "https://id.example"


def _settings(*, encryption: bool = True) -> Settings:
    """Réglages d'un OP OID4VCI avec capability de chiffrement demandée."""
    settings = Settings(oid4vci_enabled=True, oid4vci_encryption_enabled=encryption)
    settings.clients_seed = [
        {
            "client_id": "enc-client",
            "client_secret": "secret-enc",
            "scopes": "openid4vci",
            "client_type": "confidential",
        }
    ]
    return settings


def _access_token(client: TestClient) -> str:
    """Obtient un access token ``client_credentials`` pour l'issuance."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "enc-client",
            "client_secret": "secret-enc",
            "scope": "openid4vci",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _wallet_jwk(
    *, kid: str = "wallet-1", alg: str | None = ECDH_ES
) -> tuple[ec.EllipticCurvePrivateKey, dict[str, str]]:
    """Génère la paire EC P-256 du wallet et son JWK public de chiffrement."""
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key(), as_dict=False))
    if alg is not None:
        jwk["alg"] = alg
    jwk["use"] = "enc"
    jwk["kid"] = kid
    return key, jwk


def _credential_body(
    client: TestClient, settings: Settings, *, encryption: dict[str, object] | None = None
) -> dict[str, object]:
    """Construit un credential request avec ``proofs.jwt`` signé (ES256)."""
    nonce = client.post("/nonce").json()["c_nonce"]
    proof_key = ec.generate_private_key(ec.SECP256R1())
    proof_jwk = json.loads(ECAlgorithm.to_jwk(proof_key.public_key(), as_dict=False))
    proof_jwk["alg"] = "ES256"
    proof = pyjwt.encode(
        {"aud": settings.issuer, "nonce": nonce, "iat": int(time.time())},
        proof_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        algorithm="ES256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": proof_jwk},
    )
    body: dict[str, object] = {
        "credential_configuration_id": CREDENTIAL_CONFIGURATION_ID,
        "proofs": {"jwt": [proof]},
    }
    if encryption is not None:
        body["credential_response_encryption"] = encryption
    return body


def _fake_jwe(header: dict[str, str]) -> str:
    """Fabrique un JWE compact syntactique mais non déchiffrable."""
    protected = b64u(json.dumps(header).encode("utf-8"))
    return ".".join((protected, "", b64u(b"iv"), b64u(b"ct"), b64u(b"tag")))


def _usecase(
    *, encryption: bool = True, encryption_store: InMemoryKeyPairRepository | None = None
) -> OID4VCIIssuerUseCase:
    """Construit un émetteur autonome pour les tests de cas d'usage.

    ``encryption_store`` partage le store ``key_pair`` de la famille
    ``KeyUse.CREDENTIAL`` entre instances simulées (load balancing) ;
    un store vierge est créé sinon.
    """
    if encryption_store is None:
        encryption_store = InMemoryKeyPairRepository()
    return OID4VCIIssuerUseCase(
        issuer=_ISSUER,
        key_manager=DefaultKeyManager(InMemoryKeyPairRepository()),
        algorithm=JWTAlgorithm.RS256,
        token_manager=PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
        encryption_enabled=encryption,
        encryption_key_manager=DefaultKeyManager(encryption_store, use=KeyUse.CREDENTIAL),
    )


def test_metadata_publishes_encryption_capability() -> None:
    """Les métadonnées publient les deux blocs avec A256GCM en tête (s8.2)."""
    with TestClient(create_app(settings=_settings())) as client:
        metadata = client.get("/.well-known/openid-credential-issuer").json()

    request_block = metadata["credential_request_encryption"]
    jwk = request_block["jwks"]["keys"][0]
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk["kid"]
    assert jwk["alg"] == ECDH_ES
    assert jwk["use"] == "enc"
    # A256GCM en tête : émetteur et wallet retiennent l'élément [0] par défaut.
    assert request_block["enc_values_supported"][0] == "A256GCM"
    assert len(request_block["enc_values_supported"]) == 6
    assert request_block["encryption_required"] is False
    assert request_block["zip_values_supported"] == ["DEF"]

    response_block = metadata["credential_response_encryption"]
    assert response_block["alg_values_supported"] == list(ALG_VALUES_SUPPORTED)
    assert response_block["enc_values_supported"][0] == "A256GCM"
    assert response_block["encryption_required"] is False
    assert response_block["zip_values_supported"] == ["DEF"]


def test_metadata_omits_capability_when_disabled() -> None:
    """Sans ``oid4vci_encryption_enabled``, aucune capability n'est annoncée."""
    with TestClient(create_app(settings=_settings(encryption=False))) as client:
        metadata = client.get("/.well-known/openid-credential-issuer").json()

    assert "credential_request_encryption" not in metadata
    assert "credential_response_encryption" not in metadata


def test_issuer_metadata_payload_gate_on_encryption_jwks() -> None:
    """``issuer_metadata_payload`` n'ajoute les blocs que si les clés sont fournies."""
    plain = issuer_metadata_payload(_ISSUER)
    assert "credential_request_encryption" not in plain

    sealed = issuer_metadata_payload(_ISSUER, encryption_jwks=[{"kty": "EC"}])
    assert sealed["credential_request_encryption"]["jwks"]["keys"] == [{"kty": "EC"}]
    assert "credential_response_encryption" in sealed


def test_signed_metadata_carries_encryption_blocks() -> None:
    """Le metadata signé (Accept: application/jwt) embarque les blocs (s12.2.2)."""
    with TestClient(create_app(settings=_settings())) as client:
        response = client.get(
            "/.well-known/openid-credential-issuer",
            headers={"Accept": "application/jwt"},
        )

    assert response.status_code == 200
    header = pyjwt.get_unverified_header(response.text)
    jwk = header["jwk"]
    if jwk["kty"] == "RSA":
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    else:
        public_key = ECAlgorithm.from_jwk(json.dumps(jwk))
    claims = pyjwt.decode(
        response.text, public_key, algorithms=[str(header["alg"])], options={"verify_aud": False}
    )
    assert claims["credential_request_encryption"]["jwks"]["keys"][0]["use"] == "enc"
    assert claims["credential_response_encryption"]["encryption_required"] is False


def test_credential_response_sealed_as_jwe_when_requested() -> None:
    """Le chiffrement demandé scelle la réponse en ``application/jwt`` (s8.2)."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        wallet_key, wallet_jwk = _wallet_jwk()
        body = _credential_body(
            client,
            settings,
            encryption={"jwk": wallet_jwk, "enc": "A256GCM"},
        )
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/jwt")
        header = protected_header(response.text)
        assert header["alg"] == ECDH_ES
        assert header["enc"] == "A256GCM"
        # Le kid du jwk du wallet permet la sélection de clé côté déchiffreur.
        assert header["kid"] == wallet_jwk["kid"]
        payload = json.loads(decrypt_compact_ecdh_es(response.text, private_key=wallet_key))
        credential = payload["credentials"][0]["credential"]
        assert credential.endswith("~")
        assert payload["notification_id"]


def test_credential_response_honours_zip_def_request() -> None:
    """``zip = DEF`` demandé est rejeté dans l'en-tête de la réponse (RFC 7516)."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        wallet_key, wallet_jwk = _wallet_jwk()
        body = _credential_body(
            client,
            settings,
            encryption={"jwk": wallet_jwk, "enc": "A256GCM", "zip": "DEF"},
        )
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200, response.text
        header = protected_header(response.text)
        assert header["zip"] == "DEF"
        payload = json.loads(decrypt_compact_ecdh_es(response.text, private_key=wallet_key))
        assert payload["credentials"][0]["credential"].endswith("~")


def test_encrypted_credential_request_accepted() -> None:
    """Un corps ``application/jwt`` est déchiffré avec la clé publiée (s8.2)."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        metadata = client.get("/.well-known/openid-credential-issuer").json()
        issuer_jwk = metadata["credential_request_encryption"]["jwks"]["keys"][0]
        token = _access_token(client)
        body = _credential_body(client, settings)
        sealed = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=ec_public_key(issuer_jwk),
        )
        response = client.post(
            "/credential",
            content=sealed,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/jwt"},
        )

        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        assert response.json()["credentials"][0]["credential"].endswith("~")


def test_encrypted_request_rejected_when_capability_disabled() -> None:
    """Sans activation, un corps ``application/jwt`` est refusé (400)."""
    settings = _settings(encryption=False)
    with TestClient(create_app(settings=settings)) as client:
        response = client.post(
            "/credential",
            content=_fake_jwe({"alg": ECDH_ES, "enc": "A256GCM"}),
            headers={"Authorization": "Bearer x", "Content-Type": "application/jwt"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ({"alg": "A128KW", "enc": "A256GCM"}, "algorithme de gestion de clé non supporté"),
        ({"alg": ECDH_ES, "enc": "A128SIV"}, "méthode de chiffrement non supportée"),
        (
            {"alg": ECDH_ES, "enc": "A256GCM", "zip": "GZIP"},
            "algorithme de compression non supporté",
        ),
    ],
)
def test_encrypted_request_header_outside_capability_rejected(
    header: dict[str, str], expected: str
) -> None:
    """Un en-tête hors capability oppose ``invalid_encryption_parameters`` (s8.3.1)."""
    with TestClient(create_app(settings=_settings())) as client:
        response = client.post(
            "/credential",
            content=_fake_jwe(header),
            headers={"Authorization": "Bearer x", "Content-Type": "application/jwt"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"
    assert expected in response.json()["error_description"]


def test_encrypted_request_with_foreign_key_rejected() -> None:
    """Un JWE chiffré pour une autre clé échoue au déchiffrement (400)."""
    with TestClient(create_app(settings=_settings())) as client:
        stranger = ec.generate_private_key(ec.SECP256R1())
        sealed = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=b'{"credential_configuration_id": "x"}',
            recipient_public_key=stranger.public_key(),
        )
        response = client.post(
            "/credential",
            content=sealed,
            headers={"Authorization": "Bearer x", "Content-Type": "application/jwt"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_encrypted_request_with_non_object_payload_rejected() -> None:
    """Un plaintext JSON qui n'est pas un objet est refusé (400)."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        metadata = client.get("/.well-known/openid-credential-issuer").json()
        issuer_jwk = metadata["credential_request_encryption"]["jwks"]["keys"][0]
        sealed = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=b'"une chaine"',
            recipient_public_key=ec_public_key(issuer_jwk),
        )
        response = client.post(
            "/credential",
            content=sealed,
            headers={"Authorization": "Bearer x", "Content-Type": "application/jwt"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_encrypted_request_with_garbage_body_rejected() -> None:
    """Un corps ``application/jwt`` illisible est refusé (400)."""
    with TestClient(create_app(settings=_settings())) as client:
        response = client.post(
            "/credential",
            content=b"pas-un-jwe",
            headers={"Authorization": "Bearer x", "Content-Type": "application/jwt"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_response_encryption_rejected_when_disabled() -> None:
    """Sans activation, la demande de chiffrement oppose ``invalid_encryption_parameters``."""
    settings = _settings(encryption=False)
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        _, wallet_jwk = _wallet_jwk()
        body = _credential_body(client, settings, encryption={"jwk": wallet_jwk, "enc": "A256GCM"})
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"


@pytest.mark.parametrize(
    ("encryption", "expected"),
    [
        ("oups", "credential_response_encryption invalide"),
        ({}, "jwk requis"),
        ({"jwk": {"kty": "RSA", "n": "x", "e": "AQAB"}, "enc": "A256GCM"}, "EC P-256"),
    ],
)
def test_response_encryption_rejects_bad_parameters(encryption: object, expected: str) -> None:
    """Les paramètres hors capability opposent ``invalid_encryption_parameters`` (s8.3.1)."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        body = _credential_body(client, settings, encryption=encryption)  # type: ignore[arg-type]
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"
    assert expected in response.json()["error_description"]


def test_response_encryption_rejects_unsupported_enc() -> None:
    """Un ``enc`` hors capability est refusé même avec un jwk valide."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        _, wallet_jwk = _wallet_jwk()
        body = _credential_body(client, settings, encryption={"jwk": wallet_jwk, "enc": "A128SIV"})
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"
    assert "enc non supporté" in response.json()["error_description"]


def test_response_encryption_rejects_unsupported_zip() -> None:
    """Un ``zip`` hors ``DEF`` est refusé même avec un jwk valide."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        _, wallet_jwk = _wallet_jwk()
        body = _credential_body(
            client, settings, encryption={"jwk": wallet_jwk, "enc": "A256GCM", "zip": "GZIP"}
        )
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"
    assert "zip non supporté" in response.json()["error_description"]


def test_response_encryption_rejects_non_ecdh_alg_in_jwk() -> None:
    """Un ``alg`` de jwk différent d'ECDH-ES est refusé."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        token = _access_token(client)
        _, wallet_jwk = _wallet_jwk(alg="A128KW")
        body = _credential_body(client, settings, encryption={"jwk": wallet_jwk, "enc": "A256GCM"})
        response = client.post(
            "/credential", json=body, headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_encryption_parameters"
    assert "alg de chiffrement non supporté" in response.json()["error_description"]


def test_error_responses_stay_plain_json_when_encryption_requested() -> None:
    """OID4VCI s8.3.1 : les erreurs restent en JSON non chiffré, chiffrement ou non."""
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        _, wallet_jwk = _wallet_jwk()
        body = _credential_body(client, settings, encryption={"jwk": wallet_jwk, "enc": "A256GCM"})
        unauthorized = client.post(
            "/credential", json=body, headers={"Authorization": "Bearer invalide"}
        )
        assert unauthorized.status_code == 401
        assert unauthorized.headers["content-type"].startswith("application/json")
        assert unauthorized.json()["error"] == "invalid_token"

        token = _access_token(client)
        bad_proof = dict(body)
        bad_proof["proofs"] = {"jwt": ["pas-un-jwt"]}
        invalid = client.post(
            "/credential", json=bad_proof, headers={"Authorization": f"Bearer {token}"}
        )
        assert invalid.status_code == 400
        assert invalid.headers["content-type"].startswith("application/json")
        assert invalid.json()["error"] == "invalid_proof"


def test_encryption_key_provisioned_once_and_shared() -> None:
    """La clé est provisionnée une fois puis partagée entre instances (load balancing)."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        manager = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
        first = _usecase(encryption_store=store)
        second = _usecase(encryption_store=store)
        jwks_one = await first.encryption_jwks()
        jwks_two = await second.encryption_jwks()
        assert jwks_one is not None
        assert jwks_two is not None
        assert len(jwks_one) == 1
        assert [key["kid"] for key in jwks_one] == [key["kid"] for key in jwks_two]
        assert jwks_one[0]["alg"] == ECDH_ES
        assert jwks_one[0]["use"] == "enc"
        assert len(await manager.get_active_keys()) == 1
        # Mise en cache : la provisionnante ne régénère rien.
        assert await first.encryption_jwks() is jwks_one

    asyncio.run(_task())


def test_encryption_capability_absent_without_flag_or_store() -> None:
    """Sans activation ou sans store, aucune clé n'est provisionnée."""

    async def _task() -> None:
        disabled = _usecase(encryption=False)
        assert await disabled.encryption_jwks() is None
        enabled_without_store = OID4VCIIssuerUseCase(
            issuer=_ISSUER,
            key_manager=DefaultKeyManager(InMemoryKeyPairRepository()),
            algorithm=JWTAlgorithm.RS256,
            token_manager=PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
            encryption_enabled=True,
        )
        assert await enabled_without_store.encryption_jwks() is None

    asyncio.run(_task())


def test_response_encryption_spec_validation() -> None:
    """Validation directe des paramètres de chiffrement de réponse (s8.2)."""

    async def _task() -> None:
        usecase = _usecase()
        spec, error = await usecase.credential_response_encryption({})
        assert spec is None
        assert error is None

        spec, error = await usecase.credential_response_encryption(
            {"credential_response_encryption": "oups"}
        )
        assert spec is None
        assert error is not None
        assert error.error == "invalid_encryption_parameters"

        _, wallet_jwk = _wallet_jwk()
        off = _usecase(encryption=False)
        spec, error = await off.credential_response_encryption(
            {"credential_response_encryption": {"jwk": wallet_jwk, "enc": "A256GCM"}}
        )
        assert spec is None
        assert error is not None
        assert "non activé" in error.error_description

        spec, error = await usecase.credential_response_encryption(
            {"credential_response_encryption": {"jwk": wallet_jwk, "enc": "A256GCM"}}
        )
        assert error is None
        assert isinstance(spec, CredentialResponseEncryption)
        assert spec.kid == "wallet-1"
        assert spec.compress is False

    asyncio.run(_task())


def test_decrypt_credential_request_roundtrip_and_rejections() -> None:
    """Déchiffrement direct : roundtrip, capability et rejets typés."""

    async def _task() -> None:
        usecase = _usecase()
        jwks = await usecase.encryption_jwks()
        assert jwks is not None
        public = ec_public_key(jwks[0])
        body = {"credential_configuration_id": CREDENTIAL_CONFIGURATION_ID}
        sealed = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=public,
        )
        decrypted = await usecase.decrypt_credential_request(sealed.encode("ascii"))
        assert decrypted == body

        off = _usecase(encryption=False)
        error = await off.decrypt_credential_request(sealed.encode("ascii"))
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_request"

        error = await usecase.decrypt_credential_request(b"\xff\xfe")
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_request"

        error = await usecase.decrypt_credential_request(_fake_jwe({"alg": "A128KW"}).encode())
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_encryption_parameters"

        stranger = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=b"{}",
            recipient_public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        )
        error = await usecase.decrypt_credential_request(stranger.encode("ascii"))
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_request"

        scalar = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=b'"une chaine"',
            recipient_public_key=public,
        )
        error = await usecase.decrypt_credential_request(scalar.encode("ascii"))
        assert isinstance(error, CredentialError)
        assert error.error == "invalid_request"

    asyncio.run(_task())


def test_seal_credential_response_roundtrip() -> None:
    """Scellement direct : kid écho, zip reçu et déchiffrement par le wallet."""

    async def _task() -> None:
        usecase = _usecase()
        wallet_key, wallet_jwk = _wallet_jwk(kid="wallet-kid")
        spec, error = await usecase.credential_response_encryption(
            {"credential_response_encryption": {"jwk": wallet_jwk, "enc": "A256GCM", "zip": "DEF"}}
        )
        assert error is None
        assert isinstance(spec, CredentialResponseEncryption)
        sealed = await usecase.seal_credential_response({"ok": True}, spec)
        header = protected_header(sealed)
        assert header["kid"] == "wallet-kid"
        assert header["zip"] == "DEF"
        assert json.loads(decrypt_compact_ecdh_es(sealed, private_key=wallet_key)) == {"ok": True}

    asyncio.run(_task())


def test_deflate_roundtrip() -> None:
    """Compression et décompression DEFLATE brut sont symétriques (RFC 1951)."""
    payload = json.dumps({"credentials": [{"credential": "x" * 500}]}).encode("utf-8")

    assert deflate_decompress(deflate_compress(payload)) == payload


def test_deflate_rejects_zip_bomb() -> None:
    """La décompression refuse un contenu de taille abusive (zip bomb)."""
    bomb = zlib.compress(b"\0" * (2 << 20), wbits=-15)

    with pytest.raises(ValueError):
        deflate_decompress(bomb)


def test_deflate_rejects_truncated_stream() -> None:
    """La décompression refuse un flux tronqué (pas de fin de bloc)."""
    truncated = deflate_compress("un contenu suffisamment long pour être tronqué".encode())[:-4]

    with pytest.raises(ValueError):
        deflate_decompress(truncated)


def test_deflate_rejects_invalid_stream() -> None:
    """La décompression refuse un flux illisible (BTYPE réservé = 3)."""
    with pytest.raises(ValueError):
        deflate_decompress(b"\x06")


async def _seed_stale_credential_key(store: InMemoryKeyPairRepository) -> KeyPair:
    """Insère une clé ``KeyUse.CREDENTIAL`` plus vieille que ``jwks_rotation_days``."""
    manager = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
    key = await manager.generate_key_pair(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)
    stale = datetime.now(timezone.utc) - timedelta(days=91)  # > jwks_rotation_days (90)
    await store.update(replace(key, created_at=stale))
    return key


def _jwk_of(key: KeyPair) -> dict[str, object]:
    """Reconstruit le JWK public (avec ``kid``) d'une paire stockée."""
    public = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
    assert isinstance(public, ec.EllipticCurvePublicKey)
    jwk = ec_jwk(public)
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def test_startup_rotation_generates_on_empty_store() -> None:
    """Au démarrage, une famille vide reçoit une clé de chiffrement (issue #310)."""

    async def _task() -> None:
        settings = _settings()
        stores = build_stores(settings)
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        keys = await deps.credential_encryption_key_manager.get_active_keys()
        assert len(keys) == 1
        assert keys[0].use is KeyUse.CREDENTIAL

    asyncio.run(_task())


def test_startup_rotation_is_noop_when_fresh() -> None:
    """Une clé fraîche n'est pas remplacée à chaque démarrage."""

    async def _task() -> None:
        settings = _settings()
        stores = build_stores(settings)
        manager = DefaultKeyManager(stores.key_pair, use=KeyUse.CREDENTIAL)
        await manager.generate_key_pair(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        keys = await deps.credential_encryption_key_manager.get_active_keys()
        assert len(keys) == 1

    asyncio.run(_task())


def test_startup_rotation_keeps_previous_key_in_drain() -> None:
    """Une clé périmée est remplacée ; l'ancienne reste en drain (jamais purgée)."""

    async def _task() -> None:
        settings = _settings()
        stores = build_stores(settings)
        old = await _seed_stale_credential_key(stores.key_pair)
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        keys = await deps.credential_encryption_key_manager.get_active_keys()
        assert len(keys) == 2
        assert old.kid in {key.kid for key in keys}
        assert max(keys, key=lambda key: key.created_at).kid != old.kid

    asyncio.run(_task())


def test_startup_rotation_skipped_when_encryption_disabled() -> None:
    """Sans ``oid4vci_encryption_enabled``, aucune clé n'est générée au démarrage."""

    async def _task() -> None:
        settings = _settings(encryption=False)
        stores = build_stores(settings)
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        assert await deps.credential_encryption_key_manager.get_active_keys() == []

    asyncio.run(_task())


def test_metadata_publishes_every_living_key_newest_first() -> None:
    """Le ``jwks`` publié liste toutes les clés vivantes, la plus récente en tête."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        old = await _seed_stale_credential_key(store)
        manager = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
        assert await rotate_if_stale(manager, CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256, 90)
        usecase = _usecase(encryption_store=store)

        jwks = await usecase.encryption_jwks()

        assert jwks is not None
        assert len(jwks) == 2
        kids = [key["kid"] for key in jwks]
        assert len(set(kids)) == 2
        assert kids[1] == _jwk_of(old)["kid"]
        assert all(key["use"] == "enc" and key["alg"] == ECDH_ES for key in jwks)

    asyncio.run(_task())


def test_request_encrypted_under_previous_key_still_accepted() -> None:
    """Après rotation, un credential request chiffré sous l'ancienne clé passe (drain)."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        old = await _seed_stale_credential_key(store)
        manager = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
        assert await rotate_if_stale(manager, CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256, 90)
        usecase = _usecase(encryption_store=store)
        jwks = await usecase.encryption_jwks()
        assert jwks is not None
        old_jwk = _jwk_of(old)
        body = {"credential_configuration_id": CREDENTIAL_CONFIGURATION_ID}

        # kid déclaré : résolution directe sur la clé d'origine.
        sealed_with_kid = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=ec_public_key(old_jwk),
            kid=str(old_jwk["kid"]),
        )
        # Sans kid : repli par essai sur l'ensemble du trousseau.
        sealed_without_kid = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=ec_public_key(old_jwk),
        )
        sealed_new = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=ec_public_key(jwks[0]),
        )

        for sealed in (sealed_with_kid, sealed_without_kid, sealed_new):
            decrypted = await usecase.decrypt_credential_request(sealed.encode("ascii"))
            assert decrypted == body

    asyncio.run(_task())


def test_two_instances_converge_on_the_same_published_jwks() -> None:
    """Deux instances partageant le store publient le même JWKS dans le même ordre."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        first = _usecase(encryption_store=store)
        second = _usecase(encryption_store=store)

        jwks_one = await first.encryption_jwks()
        jwks_two = await second.encryption_jwks()

        assert jwks_one is not None
        assert jwks_two is not None
        assert [key["kid"] for key in jwks_one] == [key["kid"] for key in jwks_two]

    asyncio.run(_task())


def test_concurrent_first_provisioning_converges_on_one_key() -> None:
    """Deux premiers démarrages simultanés n'écrivent qu'une seule clé courante."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        first = _usecase(encryption_store=store)
        second = _usecase(encryption_store=store)

        results = await asyncio.gather(first.encryption_jwks(), second.encryption_jwks())

        jwks_one, jwks_two = results
        assert jwks_one is not None
        assert jwks_two is not None
        # L'arbitrage du slot ``(use, slot)`` fait échouer l'instance perdante,
        # qui adopte la clé gagnante : le store n'en détient qu'une et les deux
        # instances publient exactement cette même clé (issue #310).
        stored = await DefaultKeyManager(store, use=KeyUse.CREDENTIAL).get_active_keys()
        assert len(stored) == 1
        expected = {_jwk_of(stored[0])["kid"]}
        assert {key["kid"] for key in jwks_one} == expected
        assert {key["kid"] for key in jwks_two} == expected

    asyncio.run(_task())


class _ScriptedRepository:
    """Repository factice rejouant une course de provisionnement (issue #310).

    ``stale_reads`` vide les ``N`` premières lectures : l'instance perdante lit
    un store que l'autre n'a pas encore écrit. ``after_read`` s'exécute après
    chaque lecture, ce qui permet à l'instance concurrente d'écrire entre la
    lecture et l'écriture de celle-ci. Les écritures déléguent toutes au store
    réel, seul détenteur du verrou d'arbitrage du ``slot``.
    """

    def __init__(
        self,
        delegate: InMemoryKeyPairRepository,
        *,
        stale_reads: int = 0,
        after_read: Callable[[int], Awaitable[None]] | None = None,
    ) -> None:
        """Prépare le repository factice autour d'un store réel.

        Args:
            delegate: store mémoire dépositaire des écritures réelles.
            stale_reads: nombre de lectures initiales rendant la famille vide.
            after_read: hook appelé avec le numéro de lecture après lecture.
        """
        self._delegate = delegate
        self._stale_reads = stale_reads
        self._after_read = after_read
        self.reads = 0

    async def find_all(self) -> list[KeyPair]:
        """Retourne l'état du store *avant* le hook (lecture potentiellement périmée)."""
        keys = await self._delegate.find_all()
        self.reads += 1
        if self._stale_reads > 0:
            self._stale_reads -= 1
            keys = []
        if self._after_read is not None:
            await self._after_read(self.reads)
        return keys

    async def save(self, key_pair: KeyPair) -> None:
        """Délègue l'insertion au store réel (arbitrage du ``slot`` inclus)."""
        await self._delegate.save(key_pair)

    async def update(self, key_pair: KeyPair) -> None:
        """Délègue la mise à jour au store réel."""
        await self._delegate.update(key_pair)

    async def delete(self, kid: str) -> None:
        """Délègue la suppression au store réel."""
        await self._delegate.delete(kid)


def test_stale_first_read_converges_on_the_winner_key() -> None:
    """Une instance qui lit un store encore vide adopte la clé déjà écrite."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        winner = await DefaultKeyManager(store, use=KeyUse.CREDENTIAL).generate_key_pair(
            CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256
        )
        loser = DefaultKeyManager(_ScriptedRepository(store, stale_reads=1), use=KeyUse.CREDENTIAL)

        adopted = await loser.generate_key_pair(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)

        assert adopted.kid == winner.kid
        assert [key.kid for key in await store.find_all()] == [winner.kid]

    asyncio.run(_task())


def test_rotation_race_adopts_the_key_rotated_by_another_instance() -> None:
    """Une rotation placée entre lecture et écriture est adoptée : pas de 3e clé."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        old = await _seed_stale_credential_key(store)

        async def _concurrent_rotation(reads: int) -> None:
            if reads != 1:
                return
            concurrent = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
            rotated = await rotate_if_stale(concurrent, CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256, 90)
            assert rotated

        runner = DefaultKeyManager(
            _ScriptedRepository(store, after_read=_concurrent_rotation),
            use=KeyUse.CREDENTIAL,
        )

        rotated = await rotate_if_stale(runner, CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256, 90)

        assert rotated
        keys = await store.find_all()
        # L'ancienne clé passe en drain (slot libéré) et la nouvelle prend le
        # slot : l'instance perdante n'a écrit aucune troisième clé.
        assert len(keys) == 2
        holder = next(key for key in keys if key.slot is not None)
        assert holder.kid != old.kid
        assert next(key for key in keys if key.kid == old.kid).slot is None

    asyncio.run(_task())


def _ec_p256_seed_pem() -> str:
    """PEM d'une clé privée EC P-256 servant de seed de chiffrement."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def test_load_credential_key_pair_is_deterministic() -> None:
    """Le ``kid`` du seed dérive de la clé publique : stable d'un usage à l'autre."""
    pem = _ec_p256_seed_pem()

    first = load_credential_key_pair(pem)
    second = load_credential_key_pair(pem)

    assert first.kid == second.kid == pem_key_kid(first.public_key_pem)
    assert first.use is KeyUse.CREDENTIAL
    assert first.algorithm is JWTAlgorithm.ES256


def test_startup_registers_encryption_seed_on_empty_family() -> None:
    """Le seed PEM est enregistré au démarrage quand la famille est vide."""

    async def _task() -> None:
        settings = _settings()
        settings.oid4vci_encryption_key_pem = _ec_p256_seed_pem()
        stores = build_stores(settings)
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        keys = await deps.credential_encryption_key_manager.get_active_keys()
        assert len(keys) == 1
        assert keys[0].kid == load_credential_key_pair(settings.oid4vci_encryption_key_pem).kid

    asyncio.run(_task())


def test_startup_ignores_seed_when_family_already_provisioned() -> None:
    """Famille fraîche : le seed n'est pas consommé et aucune clé n'est ajoutée."""

    async def _task() -> None:
        settings = _settings()
        stores = build_stores(settings)
        manager = DefaultKeyManager(stores.key_pair, use=KeyUse.CREDENTIAL)
        existing = await manager.generate_key_pair(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)
        settings.oid4vci_encryption_key_pem = _ec_p256_seed_pem()
        deps = ProtocolDependencies(settings, stores)

        await deps._rotate_credential_encryption_key()

        keys = await deps.credential_encryption_key_manager.get_active_keys()
        assert [key.kid for key in keys] == [existing.kid]

    asyncio.run(_task())


def test_startup_rejects_non_p256_encryption_seed() -> None:
    """Un seed qui n'est pas une clé EC P-256 fait échouer le démarrage."""

    async def _task() -> None:
        settings = _settings()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        settings.oid4vci_encryption_key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
        stores = build_stores(settings)
        deps = ProtocolDependencies(settings, stores)

        with pytest.raises(ValueError, match="EC P-256"):
            await deps._rotate_credential_encryption_key()

    asyncio.run(_task())


def test_decrypt_heals_cache_after_concurrent_rotation() -> None:
    """Un déchiffrement raté relecture le store : la clé d'une autre instance est vue."""

    async def _task() -> None:
        store = InMemoryKeyPairRepository()
        manager = DefaultKeyManager(store, use=KeyUse.CREDENTIAL)
        key_a = await manager.generate_key_pair(CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256)
        usecase = _usecase(encryption_store=store)
        cached = await usecase.encryption_jwks()
        assert cached is not None
        assert len(cached) == 1
        # Une autre instance tourne après la construction du cache local.
        key_b = await manager.generate_key_pair(
            CREDENTIAL_KEY_SIZE, JWTAlgorithm.ES256, replace_kid=key_a.kid
        )
        body = {"credential_configuration_id": CREDENTIAL_CONFIGURATION_ID}
        sealed = encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A256GCM,
            plaintext=json.dumps(body).encode("utf-8"),
            recipient_public_key=ec_public_key(_jwk_of(key_b)),
        )

        decrypted = await usecase.decrypt_credential_request(sealed.encode("ascii"))

        assert decrypted == body
        healed = await usecase.encryption_jwks()
        assert healed is not None
        assert len(healed) == 2

    asyncio.run(_task())
