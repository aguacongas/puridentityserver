"""Tests du chiffrement ECDH-ES des credential requests/réponses OID4VCI (issue #304).

Le réglage ``oid4vci_encryption_enabled`` publie les blocs
``credential_request_encryption`` / ``credential_response_encryption`` dans
les métadonnées, accepte les corps ``/credential`` en ``application/jwt`` et
scelle les réponses demandées (OID4VCI 1.0 §8.2). Désactivé par défaut,
aucune capability n'est annoncée ni acceptée.
"""

from __future__ import annotations

import asyncio
import json
import time
import zlib
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from puridentityserver.application.oid4vci import (
    ALG_VALUES_SUPPORTED,
    CREDENTIAL_CONFIGURATION_ID,
    CredentialError,
    CredentialResponseEncryption,
    OID4VCIIssuerUseCase,
    issuer_metadata_payload,
)
from puridentityserver.domain.jwe import ECDH_ES, JWEEncryptionMethod
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwe import (
    b64u,
    decrypt_compact_ecdh_es,
    deflate_compress,
    deflate_decompress,
    ec_public_key,
    encrypt_compact_ecdh_es,
    generate_ec_p256_private_key_pem,
    protected_header,
)
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_encryption_key_repository,
)
from puridentityserver.infrastructure.persistence.memory.encryption_keys import (
    InMemoryEncryptionKeyRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.sql.encryption_keys import (
    SQLEncryptionKeyRepository,
)
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
    *, encryption: bool = True, repository: InMemoryEncryptionKeyRepository | None = None
) -> OID4VCIIssuerUseCase:
    """Construit un émetteur autonome pour les tests de cas d'usage."""
    if encryption and repository is None:
        repository = InMemoryEncryptionKeyRepository()
    return OID4VCIIssuerUseCase(
        issuer=_ISSUER,
        key_manager=DefaultKeyManager(InMemoryKeyPairRepository()),
        algorithm=JWTAlgorithm.RS256,
        token_manager=PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
        encryption_enabled=encryption,
        encryption_key_repository=repository,
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


def test_issuer_metadata_payload_gate_on_encryption_jwk() -> None:
    """``issuer_metadata_payload`` n'ajoute les blocs que si la clé est fournie."""
    plain = issuer_metadata_payload(_ISSUER)
    assert "credential_request_encryption" not in plain

    sealed = issuer_metadata_payload(_ISSUER, encryption_jwk={"kty": "EC"})
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
        repository = InMemoryEncryptionKeyRepository()
        first = _usecase(repository=repository)
        second = _usecase(repository=repository)
        jwk_one = await first.encryption_jwk()
        jwk_two = await second.encryption_jwk()
        assert jwk_one is not None
        assert jwk_two is not None
        assert jwk_one["kid"] == jwk_two["kid"]
        assert jwk_one["alg"] == ECDH_ES
        assert jwk_one["use"] == "enc"
        assert await repository.load() is not None
        # Mise en cache : la provisionnante ne régénère rien.
        assert await first.encryption_jwk() is jwk_one

    asyncio.run(_task())


def test_encryption_capability_absent_without_flag_or_store() -> None:
    """Sans activation ou sans store, aucune clé n'est provisionnée."""

    async def _task() -> None:
        disabled = _usecase(encryption=False, repository=InMemoryEncryptionKeyRepository())
        assert await disabled.encryption_jwk() is None
        enabled_without_store = OID4VCIIssuerUseCase(
            issuer=_ISSUER,
            key_manager=DefaultKeyManager(InMemoryKeyPairRepository()),
            algorithm=JWTAlgorithm.RS256,
            token_manager=PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
            encryption_enabled=True,
        )
        assert await enabled_without_store.encryption_jwk() is None

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
        jwk = await usecase.encryption_jwk()
        assert jwk is not None
        public = ec_public_key(jwk)
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


def test_memory_encryption_key_keeps_first_value() -> None:
    """Le store mémoire conserve la première clé inscrite (save_if_absent)."""

    async def _task() -> None:
        repository = InMemoryEncryptionKeyRepository()
        await repository.initialise()
        await repository.save_if_absent("PEM-1")
        await repository.save_if_absent("PEM-2")
        assert await repository.load() == "PEM-1"
        await repository.close()

    asyncio.run(_task())


def test_factory_builds_memory_encryption_repository() -> None:
    repository = build_encryption_key_repository(Settings(storage_type="memory"))

    assert isinstance(repository, InMemoryEncryptionKeyRepository)


def test_factory_builds_sql_encryption_repository() -> None:
    repository = build_encryption_key_repository(
        Settings(storage_type="sql", storage_dsn="sqlite:///memory")
    )

    assert isinstance(repository, SQLEncryptionKeyRepository)


def test_factory_rejects_unknown_encryption_store_type() -> None:
    settings = Settings.model_construct(storage_type="cassandra")

    with pytest.raises(ValueError, match="non supporté"):
        build_encryption_key_repository(settings)


def test_sql_encryption_key_round_trip_and_restart(tmp_path: Path) -> None:
    """Le store SQL persiste la clé : premier gagne, relisible après redémarrage."""
    dsn = f"sqlite+aiosqlite:///{tmp_path / 'enc.db'}"

    async def _task() -> None:
        repository = SQLEncryptionKeyRepository(dsn)
        await repository.initialise()
        assert await repository.load() is None
        pem = generate_ec_p256_private_key_pem()
        await repository.save_if_absent(pem)
        await repository.save_if_absent(generate_ec_p256_private_key_pem())
        assert await repository.load() == pem
        await repository.close()

        reopened = SQLEncryptionKeyRepository(dsn)
        await reopened.initialise()
        assert await reopened.load() == pem
        await reopened.close()

    asyncio.run(_task())
