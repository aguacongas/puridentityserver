"""Tests de la feature JWKS (RFC 7517) — clés multi-algorithmes."""

import asyncio
import base64
import time
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi.testclient import TestClient

from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.domain.authorization import ClientType
from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS, JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_KEY_SIZE = 2048

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _manager() -> DefaultKeyManager:
    return DefaultKeyManager(InMemoryKeyPairRepository())


def test_key_manager_generates_rsa_pair() -> None:
    manager = _manager()
    key_pair = run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.RS256))

    assert key_pair.algorithm is JWTAlgorithm.RS256
    assert key_pair.kid
    assert key_pair.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert key_pair.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert key_pair.is_active


def test_key_manager_generates_ec_pair() -> None:
    manager = _manager()
    key_pair = run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.ES256))

    assert key_pair.algorithm is JWTAlgorithm.ES256
    assert key_pair.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_jwks_use_case_initialise_creates_one_active_key_per_algorithm() -> None:
    algorithms = (JWTAlgorithm.RS256, JWTAlgorithm.ES256, JWTAlgorithm.ES512)
    usecase = JWKSetUseCase(JWKSetConfig(key_size=_KEY_SIZE, algorithms=algorithms), _manager())
    run(usecase.initialise())

    keys = run(usecase.get_active_keys())
    assert len(keys) == 3
    assert {key.algorithm for key in keys} == set(algorithms)
    assert all(key.is_active for key in keys)


def test_settings_default_to_all_supported_algorithms() -> None:
    settings = Settings()

    # ``none`` est une valeur d'en-tête (JWA RFC 7519 §6), pas un algorithme
    # de clé : il ne peut pas entrer dans la dérive des paires du serveur.
    assert settings.jwks_algorithms == tuple(
        algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS
    )
    assert "none" not in settings.jwks_algorithms


def test_settings_read_algorithm_list_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PURIDENTITYSERVER_JWKS_ALGORITHMS", "RS256,ES256")
    settings = Settings(_env_file=None)

    assert settings.jwks_algorithms == ("RS256", "ES256")
    assert settings.jwks_signing_algorithms == (JWTAlgorithm.RS256, JWTAlgorithm.ES256)


def test_jwks_endpoint_returns_keys_for_each_configured_algorithm() -> None:
    settings = Settings(
        issuer=_ISSUER,
        base_url=_ISSUER,
        jwks_key_size=_KEY_SIZE,
        jwks_algorithms=("RS256", "ES256"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    keys = response.json()["keys"]
    signing = [key for key in keys if key.get("use") == "sig"]
    assert len(signing) == 2
    by_alg = {key["alg"]: key for key in signing}
    assert set(by_alg) == {"RS256", "ES256"}
    assert by_alg["RS256"]["kty"] == "RSA"
    assert _is_valid_base64url(by_alg["RS256"]["n"])
    assert _is_valid_base64url(by_alg["RS256"]["e"])
    assert by_alg["ES256"]["kty"] == "EC"
    assert by_alg["ES256"]["crv"] == "P-256"
    assert _is_valid_base64url(by_alg["ES256"]["x"])
    assert _is_valid_base64url(by_alg["ES256"]["y"])


def test_jwks_endpoint_publishes_the_request_object_encryption_key() -> None:
    """OIDC Core 1.0 §10.1 (issue #204) : clé ``use=enc`` sans ``alg``.

    La suite de certification sélectionne ce matériel dans le ``jwks`` de
    l'entity statement (``JWEUtil.selectAsymmetricKeyForEncryption`` :
    ``kty`` + ``use`` seulement) ; l'absence d'``alg`` admet la même clé
    RSA-OAEP et RSA-OAEP-256 (RFC 7517 §4.3, membre optionnel).
    """
    settings = Settings(issuer=_ISSUER, base_url=_ISSUER, jwks_key_size=_KEY_SIZE)
    with TestClient(create_app(settings)) as client:
        keys = client.get("/.well-known/jwks.json").json()["keys"]

    # La clé de chiffrement est publiée sans ``use`` (cf. note ci-dessous) :
    # elle se reconnaît donc à l'absence du membre.
    encryption = [key for key in keys if "use" not in key]
    assert len(encryption) == 1
    assert encryption[0]["kty"] == "RSA"
    assert encryption[0]["alg"] == "RSA-OAEP"
    assert _is_valid_base64url(encryption[0]["n"])


def test_jwks_endpoint_keys_are_verifiable_with_pyjwt() -> None:
    settings = Settings(issuer=_ISSUER, base_url=_ISSUER, jwks_key_size=_KEY_SIZE)
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    key_set = response.json()["keys"]
    import jwt as pyjwt

    public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(key_set[0])
    assert public_key is not None
    for key in (entry for entry in key_set if entry["kty"] == "EC"):
        assert pyjwt.PyJWK(key, algorithm=key["alg"]).key is not None


def test_jwks_endpoint_omits_the_members_inapplicable_to_a_key() -> None:
    """RFC 7517 §4 : un JWK ne porte que les paramètres de sa clé.

    Les membres absents (``crv``/``x``/``y`` pour une clé RSA) sont omis du
    JSON et non sérialisés ``null`` : la condition
    ``VerifyNewJwksHasNewSigningKey`` de la suite de certification lit ces
    membres sans tolérer de ``null`` (elle compare le JWKS avant/après
    rotation des clés de signature).
    """
    settings = Settings(
        issuer=_ISSUER,
        base_url=_ISSUER,
        jwks_key_size=_KEY_SIZE,
        jwks_algorithms=("RS256", "ES256"),
    )
    with TestClient(create_app(settings)) as client:
        keys = client.get("/.well-known/jwks.json").json()["keys"]

    for key in keys:
        if key["kty"] == "RSA":
            assert "n" in key
            assert "e" in key
            assert "crv" not in key
            assert "x" not in key
            assert "y" not in key
        else:
            assert "crv" in key
            assert "x" in key
            assert "y" in key
            assert "n" not in key
            assert "e" not in key


def test_discovery_advertises_jwks_uri() -> None:
    settings = Settings(issuer=_ISSUER, base_url=_ISSUER, jwks_key_size=_KEY_SIZE)
    with TestClient(create_app(settings)) as client:
        discovery = client.get("/.well-known/openid-configuration")
        jwks = client.get("/.well-known/jwks.json")

    assert discovery.status_code == 200
    assert discovery.json()["jwks_uri"] == f"{_ISSUER}/.well-known/jwks.json"
    assert jwks.status_code == 200


def test_rotation_deactivates_expired_key_and_keeps_recent() -> None:
    manager = _manager()
    _plant_keys(manager, JWTAlgorithm.RS256, 91, 1)
    usecase = JWKSetUseCase(
        JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.RS256,)), manager
    )

    active = run(usecase.get_active_keys())

    assert len(active) == 1
    assert len(run(manager._repository.find_all())) == 2


def test_rotation_removes_expired_keys_and_regenerates_when_all_stale() -> None:
    manager = _manager()
    _plant_keys(manager, JWTAlgorithm.RS256, 100, 98)
    usecase = JWKSetUseCase(
        JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.RS256,)), manager
    )

    active = run(usecase.get_active_keys())

    assert len(active) == 1
    assert len(run(manager._repository.find_all())) == 1


def test_rotation_regenerates_a_missing_algorithm_alongside_active_others() -> None:
    manager = _manager()
    run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.RS256))
    _plant_keys(manager, JWTAlgorithm.ES256, 100)
    usecase = JWKSetUseCase(
        JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.ES256, JWTAlgorithm.RS256)),
        manager,
    )

    active = run(usecase.get_active_keys())

    assert {key.algorithm for key in active} == {JWTAlgorithm.ES256, JWTAlgorithm.RS256}


def test_settings_reject_unsupported_algorithm() -> None:
    with pytest.raises(ValueError):
        Settings(jwks_algorithms=("RS256", "HE256"))


def test_settings_reject_unsupported_storage_type() -> None:
    with pytest.raises(ValueError):
        Settings(storage_type="cassandra")


def test_settings_client_seed_with_scalar_redirect_uris() -> None:
    settings = Settings(clients_seed=({"client_id": "x", "redirect_uris": "https://x.example/cb"},))

    client = settings.seed_clients[0]
    assert client.redirect_uris == frozenset()


def test_settings_client_seed_rejects_unsupported_client_type() -> None:
    settings = Settings(clients_seed=({"client_id": "x", "client_type": "service"},))

    with pytest.raises(ValueError, match="non supporté"):
        _ = settings.seed_clients


def test_settings_client_seed_reads_json_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "PURIDENTITYSERVER_CLIENTS_SEED",
        '[{"client_id": "env-app", "redirect_uris": ["https://e.example/cb"]}]',
    )
    settings = Settings(_env_file=None)

    assert [client.client_id for client in settings.seed_clients] == ["env-app"]


def test_settings_client_seed_reads_defaults_from_config_toml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = Path(__file__).resolve().parents[1] / "config.toml"
    monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))
    settings = Settings(_env_file=None)

    client = settings.seed_clients[0]
    assert [c.client_id for c in settings.seed_clients] == [
        "sample-pkce-client",
        "sample-implicit-client",
        "sample-hybrid-client",
        "sample-refresh-client",
        "sample-cc-client",
        "sample-api-client",
        "sample-admin-client",
        "sample-introspect-client",
        "sample-resource-client",
        "sample-device-client",
        "sample-par-client",
        "sample-spa-client",
        "sample-swagger-client",
        "sample-dpop-client",
        "sample-ciba-client",
        "sample-ciba-ping-client",
        "sample-jarm-client",
        "sample-form-post-client",
        "sample-prompt-create-client",
    ]
    assert client.redirect_uris == frozenset({"http://127.0.0.1:5173/callback"})
    assert client.scopes == frozenset({"openid", "profile", "email"})
    assert client.client_type == ClientType.PUBLIC
    assert client.session_lifetime_seconds is None
    assert client.access_token_lifetime_seconds is None
    assert client.authorization_code_lifetime_seconds is None
    assert client.par_required is False
    par_client = next(c for c in settings.seed_clients if c.client_id == "sample-par-client")
    assert par_client.par_required is True
    dpop_client = next(c for c in settings.seed_clients if c.client_id == "sample-dpop-client")
    assert dpop_client.require_dpop is True
    ciba_client = next(c for c in settings.seed_clients if c.client_id == "sample-ciba-client")
    assert ciba_client.backchannel_token_delivery_mode == "poll"
    ping_client = next(c for c in settings.seed_clients if c.client_id == "sample-ciba-ping-client")
    assert ping_client.backchannel_token_delivery_mode == "ping"
    assert ping_client.backchannel_client_notification_endpoint == "http://127.0.0.1:8118/notify"
    jarm_client = next(c for c in settings.seed_clients if c.client_id == "sample-jarm-client")
    assert jarm_client.authorization_signed_response_alg == "PS256"
    form_post_client = next(
        c for c in settings.seed_clients if c.client_id == "sample-form-post-client"
    )
    assert form_post_client.redirect_uris == frozenset({"http://127.0.0.1:8122/callback"})
    prompt_create_client = next(
        c for c in settings.seed_clients if c.client_id == "sample-prompt-create-client"
    )
    assert prompt_create_client.redirect_uris == frozenset({"http://127.0.0.1:8124/callback"})


def test_settings_client_seed_parses_lifetime_fields() -> None:
    settings = Settings(
        clients_seed=(
            {
                "client_id": "x",
                "redirect_uris": ("https://x.example/cb",),
                "session_lifetime_seconds": 1800,
                "access_token_lifetime_seconds": 120,
                "authorization_code_lifetime_seconds": 30,
            },
        )
    )

    client = settings.seed_clients[0]
    assert client.session_lifetime_seconds == 1800
    assert client.access_token_lifetime_seconds == 120
    assert client.authorization_code_lifetime_seconds == 30


def test_settings_client_seed_parses_logout_channel_fields() -> None:
    settings = Settings(
        clients_seed=(
            {
                "client_id": "x",
                "redirect_uris": ("https://x.example/cb",),
                "frontchannel_logout_uri": "https://x.example/front-logout",
                "frontchannel_logout_session_required": True,
                "backchannel_logout_uri": "https://ssr.example/back-logout",
                "backchannel_logout_session_required": True,
            },
        )
    )

    client = settings.seed_clients[0]
    assert client.frontchannel_logout_uri == "https://x.example/front-logout"
    assert client.frontchannel_logout_session_required is True
    assert client.backchannel_logout_uri == "https://ssr.example/back-logout"
    assert client.backchannel_logout_session_required is True


def test_settings_client_seed_logout_channels_default_absent() -> None:
    settings = Settings(
        clients_seed=({"client_id": "x", "redirect_uris": ("https://x.example/cb",)},)
    )

    client = settings.seed_clients[0]
    assert client.frontchannel_logout_uri == ""
    assert client.frontchannel_logout_session_required is False
    assert client.backchannel_logout_uri == ""
    assert client.backchannel_logout_session_required is False


def test_settings_client_seed_rejects_non_list_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PURIDENTITYSERVER_CLIENTS_SEED", '{"client_id": "env-app"}')
    with pytest.raises(ValueError, match="doit être une liste JSON"):
        Settings(_env_file=None)


def test_jwk_response_handles_unknown_key_family() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    pub_pem = (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    key_pair = KeyPair(algorithm=JWTAlgorithm.RS256, public_key_pem=pub_pem)

    jwk = JWKKeyResponse.from_key_pair(key_pair)

    assert jwk.kty == "RSA"
    assert jwk.n is None
    assert jwk.e is None
    assert jwk.crv is None
    assert jwk.x is None
    assert jwk.y is None


def test_ec_coordinates_use_full_curve_field_length() -> None:
    """Coordonnées EC sur la pleine taille de courbe (RFC 7518 §6.2.1).

    Reproduit le tirage (~0,8 % des clés) dont une coordonnée tête nulle
    n'occupait que 31 octets : l'encodage à longueur variable tronquait les
    zéros de tête et rendait le JWK émis illisible
    (``Coords should be 32 bytes for curve P-256``).
    """
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key: ec.EllipticCurvePrivateKey | None = None
    for _ in range(5000):
        candidate = ec.generate_private_key(ec.SECP256R1())
        numbers = candidate.public_key().public_numbers()
        if numbers.x.bit_length() <= 248 or numbers.y.bit_length() <= 248:
            private_key = candidate
            break
    assert private_key is not None, "aucune coordonnée tête nulle en 5000 tirages P-256"

    pub_pem = (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    jwk = JWKKeyResponse.from_key_pair(
        KeyPair(algorithm=JWTAlgorithm.ES256, public_key_pem=pub_pem)
    )

    assert pyjwt.PyJWK(jwk.model_dump(exclude_none=True), algorithm="ES256").key is not None
    for coordinate in (jwk.x, jwk.y):
        assert coordinate is not None
        padded = coordinate + "=" * (-len(coordinate) % 4)
        assert len(base64.urlsafe_b64decode(padded)) == 32


def _is_valid_base64url(value: str) -> bool:
    padded = value + "=" * (-len(value) % 4)
    base64.urlsafe_b64decode(padded)
    return True


def _plant_keys(manager: DefaultKeyManager, algorithm: JWTAlgorithm, *ages_days: int) -> None:
    """Remplit le magasin avec des clés datées artificiellement (en jours)."""
    now = datetime.now(timezone.utc)
    for age in ages_days:
        run(
            manager._repository.save(
                replace(
                    run(manager.generate_key_pair(_KEY_SIZE, algorithm)),
                    created_at=now - timedelta(days=age),
                )
            )
        )


def _plant_key(manager: DefaultKeyManager, algorithm: JWTAlgorithm, age: timedelta) -> KeyPair:
    """Remplit le magasin avec une clé datée artificiellement (précision seconde)."""
    aged = replace(
        run(manager.generate_key_pair(_KEY_SIZE, algorithm)),
        created_at=datetime.now(timezone.utc) - age,
    )
    run(manager._repository.save(aged))
    return aged


class TestSigningKeyRotation:
    """Rotation proactive des clés de signature (OIDC Core 1.0 §10.1)."""

    def test_rotation_is_disabled_by_default(self) -> None:
        """Sans période configurée, la clé de signature ne tourne pas."""
        manager = _manager()
        planted = _plant_key(manager, JWTAlgorithm.RS256, timedelta(seconds=30))
        usecase = JWKSetUseCase(
            JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.RS256,)), manager
        )

        published = run(usecase.get_published_keys())

        assert [key.kid for key in published] == [planted.kid]

    def test_publication_rotates_a_key_older_than_the_period(self) -> None:
        """La publication du JWKS fait pivoter la clé de signature Trop ancienne."""
        manager = _manager()
        planted = _plant_key(manager, JWTAlgorithm.RS256, timedelta(seconds=30))
        usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=_KEY_SIZE,
                algorithms=(JWTAlgorithm.RS256,),
                rotation_seconds=10.0,
            ),
            manager,
        )

        published = run(usecase.get_published_keys())

        active = [key for key in published if key.is_active]
        retired = [key for key in published if not key.is_active]
        assert len(active) == 1
        assert active[0].kid != planted.kid
        # OIDC Core 1.0 §10.1 : la clé retirée reste publiée (transition en douceur).
        assert [key.kid for key in retired] == [planted.kid]

    def test_rotation_only_applies_to_the_configured_algorithms(self) -> None:
        """``rotation_algorithms`` restreint la rotation proactive."""
        manager = _manager()
        rsa_key = _plant_key(manager, JWTAlgorithm.RS256, timedelta(seconds=30))
        ec_key = _plant_key(manager, JWTAlgorithm.ES256, timedelta(seconds=30))
        usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=_KEY_SIZE,
                algorithms=(JWTAlgorithm.RS256, JWTAlgorithm.ES256),
                rotation_seconds=10.0,
                rotation_algorithms=(JWTAlgorithm.RS256,),
            ),
            manager,
        )

        published = run(usecase.get_published_keys())

        kids = {key.kid for key in published}
        assert rsa_key.kid in kids
        assert ec_key.kid in kids
        assert len(kids) == 3

    def test_retention_bounds_the_retired_keys(self) -> None:
        """Au-delà de la rétention, les clés retirées sont purgées du magasin."""
        manager = _manager()
        for _ in range(3):
            _plant_key(manager, JWTAlgorithm.RS256, timedelta(seconds=30))
        usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=_KEY_SIZE,
                algorithms=(JWTAlgorithm.RS256,),
                rotation_seconds=10.0,
                retained_keys=1,
            ),
            manager,
        )

        published = run(usecase.get_published_keys())

        assert len(published) == 4
        assert len(run(manager._repository.find_all())) == 4

    def test_token_signed_before_the_rotation_is_still_valid(self) -> None:
        """La clé retirée continue de valider les jetons qu'elle a signés."""
        manager = _manager()
        _plant_key(manager, JWTAlgorithm.RS256, timedelta(seconds=30))
        usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=_KEY_SIZE,
                algorithms=(JWTAlgorithm.RS256,),
                rotation_seconds=10.0,
            ),
            manager,
        )
        token_manager = PyJWTTokenManager(manager)
        now = int(datetime.now(timezone.utc).timestamp())
        token = run(
            token_manager.create_id_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience="web-app",
                expires_at=now + 300,
                issued_at=now,
            )
        )

        run(usecase.get_published_keys())

        claims = run(token_manager.validate_id_token(token=token, issuer=_ISSUER))
        assert claims is not None
        assert claims["sub"] == "alice"

    def test_rotate_signing_keys_replaces_the_active_key(self) -> None:
        """Rotation à la demande : nouvelle paire, ancienne retirée (non publiée)."""
        manager = _manager()
        usecase = JWKSetUseCase(
            JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.RS256,)), manager
        )
        run(usecase.initialise())
        before = run(usecase.get_published_keys())

        rotated = run(usecase.rotate_signing_keys())

        assert [key.algorithm for key in rotated] == [JWTAlgorithm.RS256]
        published = run(usecase.get_published_keys())
        kids = {key.kid for key in published}
        assert rotated[0].kid in kids
        assert {key.kid for key in before} & kids, "l'ancienne clé n'est plus publiée"

    def test_jwks_endpoint_rotates_and_keeps_the_previous_key(self) -> None:
        """Au niveau HTTP : une nouvelle clé apparaît, l'ancienne reste publiée."""
        # rotation_seconds volontairement large (et attente explicite entre
        # les deux relevés) : rotation paresseuse par âge -> sinon la flakiness
        # selon la résolution d'horloge (cf. issue #217).
        settings = Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_key_size=_KEY_SIZE,
            jwks_algorithms=("RS256",),
            jwks_rotation_seconds=0.05,
        )
        with TestClient(create_app(settings)) as client:
            first = client.get("/.well-known/jwks.json").json()["keys"]
            time.sleep(0.15)
            second = client.get("/.well-known/jwks.json").json()["keys"]

        first_kids = {key["kid"] for key in first if key.get("use") == "sig"}
        second_kids = {key["kid"] for key in second if key.get("use") == "sig"}
        assert len(first_kids) == 2
        assert len(second_kids) == 3
        assert first_kids != second_kids
        assert first_kids & second_kids


def test_settings_read_rotation_parameters_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PURIDENTITYSERVER_JWKS_ROTATION_SECONDS", "0.5")
    monkeypatch.setenv("PURIDENTITYSERVER_JWKS_ROTATION_ALGORITHMS", "RS256")
    settings = Settings(_env_file=None)

    assert settings.jwks_rotation_seconds == pytest.approx(0.5)
    assert settings.jwks_rotation_algorithms == ("RS256",)
    assert settings.jwks_rotation_signing_algorithms == (JWTAlgorithm.RS256,)
    assert settings.jwks_retained_keys == 1
