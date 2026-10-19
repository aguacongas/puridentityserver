"""Tests des subject types pairwise et ephemeral (OIDC Core 1.0 §8.1, ESID 1.0 §4).

Couvre la dérivation (``domain/subjects.py``), le secteur du client, le
fail-fast du seed au démarrage (``Settings.seed_clients``), le Dynamic
Client Registration (écho ``subject_type`` / ``sector_identifier_uri`` et
refus ``invalid_client_metadata``) et les parcours E2E ``login →
/authorize → /token → /userinfo`` : sub pairwise stable par client et
distincte entre clients, sub ephemeral jamais réutilisée entre deux
authentifications, non-régression ``public`` (défaut rétrocompatible).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid as uuid_mod
from collections.abc import Awaitable
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.registration import (
    ClientRegistration,
    RegisterRequest,
    RegistrationConfig,
    RegistrationError,
    RegistrationUseCase,
    UpdateClientRequest,
)
from puridentityserver.domain.authorization import Client, SubjectType
from puridentityserver.domain.subjects import (
    access_token_subject_claims,
    display_subject,
    ephemeral_subject,
    pairwise_subject,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_SEED = "subject-types-test-seed"

_PAIRWISE_A = {
    "client_id": "pairwise-app-a",
    "client_secret": "secret-a",
    "redirect_uris": ["https://app-a.example/callback"],
    "scopes": "openid profile offline_access",
    "client_type": "confidential",
    "subject_type": "pairwise",
}
_PAIRWISE_B = {
    "client_id": "pairwise-app-b",
    "client_secret": "secret-b",
    "redirect_uris": ["https://app-b.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
    "subject_type": "pairwise",
}
_EPHEMERAL = {
    "client_id": "ephemeral-app",
    "client_secret": "secret-e",
    "redirect_uris": ["https://ephemeral.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
    "subject_type": "ephemeral",
}
_PUBLIC = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

_IDENTITY_SEED = {"alice": {"email": "alice@example.com", "password": "password"}}
_USERS_SEED = {
    "alice": {
        "name": "Alice Martin",
        "preferred_username": "alice-martin",
        "email": "alice.martin@example.com",
        "email_verified": True,
    },
}

_DCR_METADATA = {
    "redirect_uris": ["https://app.example/callback"],
    "scope": "openid profile",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _s256_challenge(verifier: str) -> str:
    """Défi PKCE S256 (RFC 7636 §4.2) pour les parcours E2E."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    """Query string d'une redirection d'autorisation."""
    return parse_qs(urlparse(redirect_url).query)


class _StaticSectorFetcher:
    """Fetcher secteur de test renvoyant un document JSON fixe (ou l'échec)."""

    def __init__(self, document: str | None) -> None:
        """``document`` est le corps retourné ; ``None`` simule un refus réseau."""
        self._document = document

    async def fetch(self, url: str) -> str | None:
        """Retourne le document préchargé, quelle que soit l'URL demandée."""
        return self._document


class TestSubjectSector:
    """Secteur de dérivation pairwise (OIDC Core 1.0 §8.1)."""

    def test_sector_comes_from_sector_identifier_uri(self) -> None:
        client = Client(
            client_id="c",
            redirect_uris=frozenset({"https://app.example/callback"}),
            sector_identifier_uri="https://sector.example/ids.json",
        )

        assert client.subject_sector() == "sector.example"

    def test_sector_falls_back_to_unique_redirect_host(self) -> None:
        client = Client(
            client_id="c",
            redirect_uris=frozenset({"https://app.example/callback", "https://app.example/other"}),
        )

        assert client.subject_sector() == "app.example"

    def test_sector_is_empty_for_multiple_hosts(self) -> None:
        client = Client(
            client_id="c",
            redirect_uris=frozenset({"https://a.example/cb", "https://b.example/cb"}),
        )

        assert client.subject_sector() == ""


class TestDerivation:
    """Dérivation HMAC des ``sub`` pairwise et ephemeral."""

    def test_pairwise_subject_is_deterministic(self) -> None:
        first = pairwise_subject(_SEED, "app.example", "alice")
        second = pairwise_subject(_SEED, "app.example", "alice")

        assert first == second
        assert len(first) == 43
        assert first != "alice"

    def test_pairwise_subject_varies_by_sector_and_subject(self) -> None:
        base = pairwise_subject(_SEED, "app.example", "alice")

        assert pairwise_subject(_SEED, "other.example", "alice") != base
        assert pairwise_subject(_SEED, "app.example", "bob") != base
        assert pairwise_subject("another-seed", "app.example", "alice") != base

    def test_ephemeral_subject_never_reused_across_materials(self) -> None:
        first = ephemeral_subject(_SEED, "alice", "session-1")
        second = ephemeral_subject(_SEED, "alice", "session-2")

        assert first == ephemeral_subject(_SEED, "alice", "session-1")
        assert first != second
        assert first != "alice"

    def test_display_subject_passthrough_for_public_client(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.PUBLIC)

        assert display_subject(client, "alice", seed=_SEED) == "alice"

    def test_display_subject_pairwise_without_seed_keeps_real_subject(self) -> None:
        client = Client(
            client_id="c",
            redirect_uris=frozenset({"https://app.example/callback"}),
            subject_type=SubjectType.PAIRWISE,
        )

        assert display_subject(client, "alice", seed="") == "alice"
        assert display_subject(client, "alice", seed=_SEED) == pairwise_subject(
            _SEED, "app.example", "alice"
        )

    def test_display_subject_ephemeral_uses_material(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.EPHEMERAL)

        assert display_subject(client, "alice", material="sid-1", seed=_SEED) == (
            ephemeral_subject(_SEED, "alice", "sid-1")
        )

    def test_display_subject_keeps_empty_subject(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.PAIRWISE)

        assert display_subject(client, "", seed=_SEED) == ""

    def test_access_token_claims_empty_for_public_client(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.PUBLIC)

        assert access_token_subject_claims(client, "alice") == {}

    def test_access_token_claims_identify_pairwise_client(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.PAIRWISE)

        assert access_token_subject_claims(client, "alice") == {"client_id": "c"}

    def test_access_token_claims_carry_ephemeral_material(self) -> None:
        client = Client(client_id="c", subject_type=SubjectType.EPHEMERAL)

        claims = access_token_subject_claims(client, "alice", material="sid-1")

        assert claims == {"client_id": "c", "subject_material": "sid-1"}
        assert access_token_subject_claims(client, "alice") == {"client_id": "c"}


class TestSeedClientsValidation:
    """Fail-fast du seed et du secteur au démarrage (``Settings.seed_clients``)."""

    @staticmethod
    def _settings(**overrides: object) -> Settings:
        """Settings de test, seed de dérivation fourni sauf écrasement explicite."""
        base: dict[str, object] = {
            "issuer": _ISSUER,
            "base_url": _ISSUER,
            "jwks_algorithms": ("RS256",),
            "subject_pairwise_seed": _SEED,
        }
        base.update(overrides)
        return Settings(**base)

    def test_seed_client_defaults_to_public_subject_type(self) -> None:
        settings = self._settings(clients_seed=(_PUBLIC,))

        client = settings.seed_clients[0]

        assert client.subject_type is SubjectType.PUBLIC
        assert client.sector_identifier_uri == ""

    def test_pairwise_seed_client_accepted_with_seed(self) -> None:
        settings = self._settings(clients_seed=(_PAIRWISE_A,))

        assert settings.seed_clients[0].subject_type is SubjectType.PAIRWISE

    def test_pairwise_seed_client_rejected_without_seed(self) -> None:
        settings = self._settings(clients_seed=(_PAIRWISE_A,), subject_pairwise_seed="")

        try:
            _ = settings.seed_clients
        except ValueError as error:
            assert "subject_pairwise_seed" in str(error)
        else:  # pragma: no cover - le fail-fast est exigé
            raise AssertionError("pairwise sans seed doit être refusé au boot")

    def test_ephemeral_seed_client_rejected_without_seed(self) -> None:
        settings = self._settings(clients_seed=(_EPHEMERAL,), subject_pairwise_seed="")

        try:
            _ = settings.seed_clients
        except ValueError as error:
            assert "subject_pairwise_seed" in str(error)
        else:  # pragma: no cover - le fail-fast est exigé
            raise AssertionError("ephemeral sans seed doit être refusé au boot")

    def test_invalid_sector_scheme_rejected(self) -> None:
        settings = self._settings(
            clients_seed=(
                {
                    **_PAIRWISE_A,
                    "sector_identifier_uri": "http://sector.example/ids.json",
                },
            )
        )

        try:
            _ = settings.seed_clients
        except ValueError as error:
            assert "sector_identifier_uri" in str(error)
        else:  # pragma: no cover - le fail-fast est exigé
            raise AssertionError("secteur http doit être refusé au boot")

    def test_multi_host_pairwise_without_sector_rejected(self) -> None:
        settings = self._settings(
            clients_seed=(
                {
                    **_PAIRWISE_A,
                    "redirect_uris": ["https://a.example/cb", "https://b.example/cb"],
                },
            )
        )

        try:
            _ = settings.seed_clients
        except ValueError as error:
            assert "hôte unique" in str(error)
        else:  # pragma: no cover - le fail-fast est exigé
            raise AssertionError("pairwise multi-hôte sans secteur doit être refusé")


class TestRegistrationSubjectTypes:
    """Dynamic Client Registration des subject types (RFC 7591 + Core §8.1)."""

    @staticmethod
    def _usecase(
        *, seed: str = _SEED, fetcher: _StaticSectorFetcher | None = None
    ) -> RegistrationUseCase:
        """Construit un usecase DCR sans authentification initiale."""
        config = RegistrationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            requires_initial_access_token=False,
            subject_seed=seed,
        )
        return RegistrationUseCase(config, InMemoryClientRepository(), sector_fetcher=fetcher)

    def test_register_defaults_to_public_subject_type(self) -> None:
        usecase = self._usecase()

        result = run(usecase.register(RegisterRequest(_DCR_METADATA)))

        assert isinstance(result, ClientRegistration)
        assert result.subject_type == "public"
        assert result.sector_identifier_uri == ""

    def test_register_rejects_unknown_subject_type(self) -> None:
        usecase = self._usecase()

        result = run(
            usecase.register(RegisterRequest({**_DCR_METADATA, "subject_type": "pairwise2"}))
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert result.status_code == 400

    def test_register_pairwise_without_seed_rejected(self) -> None:
        usecase = self._usecase(seed="")

        result = run(
            usecase.register(RegisterRequest({**_DCR_METADATA, "subject_type": "pairwise"}))
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert result.status_code == 400
        assert "subject_pairwise_seed" in result.error_description

    def test_register_ephemeral_without_seed_rejected(self) -> None:
        usecase = self._usecase(seed="")

        result = run(
            usecase.register(RegisterRequest({**_DCR_METADATA, "subject_type": "ephemeral"}))
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_register_rejects_non_https_sector_identifier_uri(self) -> None:
        usecase = self._usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "http://sector.example/ids.json",
                    }
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert result.status_code == 400

    def test_register_pairwise_with_valid_sector_document(self) -> None:
        document = json.dumps(["https://app.example/callback", "https://other.example/cb"])
        usecase = self._usecase(fetcher=_StaticSectorFetcher(document))

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "https://sector.example/ids.json",
                    }
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.subject_type == "pairwise"
        assert result.sector_identifier_uri == "https://sector.example/ids.json"
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.subject_type is SubjectType.PAIRWISE

    def test_register_rejects_inaccessible_sector_document(self) -> None:
        usecase = self._usecase(fetcher=_StaticSectorFetcher(None))

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "https://sector.example/ids.json",
                    }
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert result.status_code == 400

    def test_register_rejects_sector_document_not_a_list(self) -> None:
        usecase = self._usecase(fetcher=_StaticSectorFetcher('{"redirects": []}'))

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "https://sector.example/ids.json",
                    }
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_register_rejects_sector_not_covering_redirect_uris(self) -> None:
        usecase = self._usecase(
            fetcher=_StaticSectorFetcher(json.dumps(["https://other.example/cb"]))
        )

        result = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "subject_type": "pairwise",
                        "sector_identifier_uri": "https://sector.example/ids.json",
                    }
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "app.example" in result.error_description

    def test_register_pairwise_without_sector_requires_unique_host(self) -> None:
        usecase = self._usecase()

        multi_host = run(
            usecase.register(
                RegisterRequest(
                    {
                        **_DCR_METADATA,
                        "redirect_uris": ["https://a.example/cb", "https://b.example/cb"],
                        "subject_type": "pairwise",
                    }
                )
            )
        )

        assert isinstance(multi_host, RegistrationError)
        assert multi_host.error == "invalid_client_metadata"

        single_host = run(
            usecase.register(RegisterRequest({**_DCR_METADATA, "subject_type": "pairwise"}))
        )

        assert isinstance(single_host, ClientRegistration)
        assert single_host.subject_type == "pairwise"
        assert single_host.sector_identifier_uri == ""

    def test_register_ephemeral_accepted_with_seed(self) -> None:
        usecase = self._usecase()

        result = run(
            usecase.register(RegisterRequest({**_DCR_METADATA, "subject_type": "ephemeral"}))
        )

        assert isinstance(result, ClientRegistration)
        assert result.subject_type == "ephemeral"
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.subject_type is SubjectType.EPHEMERAL

    def test_update_rejects_pairwise_without_seed(self) -> None:
        usecase = self._usecase(seed="")
        registered = run(usecase.register(RegisterRequest(_DCR_METADATA)))
        assert isinstance(registered, ClientRegistration)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    client_id=registered.client_id,
                    registration_access_token=registered.registration_access_token,
                    metadata={**_DCR_METADATA, "subject_type": "pairwise"},
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert result.status_code == 400


def _app(**overrides: object) -> FastAPI:
    """Application de test avec les trois clients subject et alice seedée."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            subject_pairwise_seed=_SEED,
            clients_seed=(_PUBLIC, _PAIRWISE_A, _PAIRWISE_B, _EPHEMERAL),
            identity_seed_users=_IDENTITY_SEED,
            users_seed=_USERS_SEED,
            **overrides,
        )
    )


def _login(http: TestClient) -> None:
    """Authentifie alice et pose la session (nouveau ``sid`` à chaque appel)."""
    response = http.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def _flow(
    http: TestClient, client_id: str, redirect_uri: str, client_secret: str
) -> dict[str, object]:
    """Parcours complet ``/authorize`` → ``/token`` et retourne le payload."""
    verifier = "verifier-verifier"
    challenge = _s256_challenge(verifier)
    authorize = http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile offline_access",
            "nonce": "n-subject",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302
    code = _redirect_query(authorize.headers["location"])["code"][0]
    response = http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _id_sub(http: TestClient, id_token: str, audience: str) -> str:
    """Décode l'``sub`` d'un id_token émis par le serveur de test."""
    jwks = http.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks.json()["keys"][0])
    claims = jwt.decode(
        id_token,
        public_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=_ISSUER,
    )
    return str(claims["sub"])


class TestEndToEndSubjectTypes:
    """Parcours E2E : id_token, userinfo et refresh cohérents avec le sujet émis."""

    def test_public_client_keeps_real_subject(self) -> None:
        """Non-régression : le défaut ``public`` émet le sujet réel (UUID)."""
        with TestClient(_app()) as http:
            _login(http)
            payload = _flow(http, "web-app", "https://app.example/callback", "super-secret")
            sub = _id_sub(http, str(payload["id_token"]), "web-app")

            userinfo = http.get(
                "/userinfo", headers={"Authorization": f"Bearer {payload['access_token']}"}
            )
            assert userinfo.status_code == 200

        assert uuid_mod.UUID(sub)
        assert userinfo.json()["sub"] == sub

    def test_pairwise_sub_stable_per_client_and_distinct_between_clients(self) -> None:
        """Même client : ``sub`` stable ; deux clients : ``sub`` non corrélable."""
        with TestClient(_app()) as http:
            _login(http)
            first = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "pairwise-app-a",
                        "https://app-a.example/callback",
                        "secret-a",
                    )["id_token"]
                ),
                "pairwise-app-a",
            )
            second = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "pairwise-app-a",
                        "https://app-a.example/callback",
                        "secret-a",
                    )["id_token"]
                ),
                "pairwise-app-a",
            )
            other = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "pairwise-app-b",
                        "https://app-b.example/callback",
                        "secret-b",
                    )["id_token"]
                ),
                "pairwise-app-b",
            )
            public = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "web-app",
                        "https://app.example/callback",
                        "super-secret",
                    )["id_token"]
                ),
                "web-app",
            )

        assert first == second
        assert other != first
        assert first != public
        assert len(first) == 43

    def test_pairwise_userinfo_matches_id_token_sub(self) -> None:
        """``/userinfo`` dérive la même ``sub`` que l'id_token, profil résolu sur le sujet réel."""
        with TestClient(_app()) as http:
            _login(http)
            payload = _flow(http, "pairwise-app-a", "https://app-a.example/callback", "secret-a")
            expected_sub = _id_sub(http, str(payload["id_token"]), "pairwise-app-a")

            userinfo = http.get(
                "/userinfo", headers={"Authorization": f"Bearer {payload['access_token']}"}
            )
            assert userinfo.status_code == 200
            claims = userinfo.json()

        assert claims["sub"] == expected_sub
        assert claims["name"] == "Alice Martin"

    def test_ephemeral_sub_constant_within_session_new_per_authentication(self) -> None:
        """ESID 1.0 §4 : même ``sub`` dans la session, jamais réutilisée dehors."""
        with TestClient(_app()) as http:
            _login(http)
            first = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "ephemeral-app",
                        "https://ephemeral.example/callback",
                        "secret-e",
                    )["id_token"]
                ),
                "ephemeral-app",
            )
            same_session = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "ephemeral-app",
                        "https://ephemeral.example/callback",
                        "secret-e",
                    )["id_token"]
                ),
                "ephemeral-app",
            )
            _login(http)  # nouvelle session = nouvelle matière de dérivation
            new_session = _id_sub(
                http,
                str(
                    _flow(
                        http,
                        "ephemeral-app",
                        "https://ephemeral.example/callback",
                        "secret-e",
                    )["id_token"]
                ),
                "ephemeral-app",
            )

        assert first == same_session
        assert new_session != first

    def test_refresh_token_preserves_pairwise_sub(self) -> None:
        """Le renouvellement reproduit exactement la ``sub`` de l'id_token initial."""
        with TestClient(_app()) as http:
            _login(http)
            payload = _flow(http, "pairwise-app-a", "https://app-a.example/callback", "secret-a")
            expected_sub = _id_sub(http, str(payload["id_token"]), "pairwise-app-a")
            assert payload["refresh_token"]

            refreshed = http.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": payload["refresh_token"],
                    "client_id": "pairwise-app-a",
                    "client_secret": "secret-a",
                },
            )
            assert refreshed.status_code == 200, refreshed.text
            body = refreshed.json()
            refreshed_sub = _id_sub(http, str(body["id_token"]), "pairwise-app-a")

            userinfo = http.get(
                "/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
            )
            assert userinfo.status_code == 200

        assert refreshed_sub == expected_sub
        assert userinfo.json()["sub"] == expected_sub
