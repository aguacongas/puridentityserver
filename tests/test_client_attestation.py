"""Tests de l'authentification client par attestation (issue #304).

Couvre le draft-ietf-oauth-attestation-based-client-auth : extraction des
en-têtes ``OAuth-Client-Attestation`` / ``OAuth-Client-Attestation-PoP``
(§6.1, §9-1), vérification de la paire attestation + PoP (§5, §9),
câblage de la méthode ``attest_jwt_client_auth``, métadonnées de
discovery (§10.1) et endpoints ``/par`` et ``/token``.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm
from starlette.datastructures import Headers

from puridentityserver.application.client_auth import (
    ASSERTION_INVALID_ERROR,
    authenticate_client,
)
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
)
from puridentityserver.infrastructure.client_attestation import PyJWTClientAttestationVerifier
from puridentityserver.infrastructure.dpop import jwk_thumbprint
from puridentityserver.infrastructure.persistence.memory.dpop_replays import (
    InMemoryDpopReplayRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.client_attestation import (
    ATTESTATION_HEADER,
    ATTESTATION_POP_HEADER,
    extract_client_attestation,
)
from puridentityserver.interfaces.domain.client_attestation import (
    CLIENT_ATTESTATION_POP_TYPE,
    CLIENT_ATTESTATION_TYPE,
)
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_ATTESTER = "https://client-attester.example.org/"
_CLIENT_ID = "haip-wallet"
_REDIRECT_URI = "https://app.example/callback"

_PAR_DATA = {
    "response_type": "code",
    "client_id": _CLIENT_ID,
    "redirect_uri": _REDIRECT_URI,
    "scope": "openid",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _public_jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, object]:
    jwk: dict[str, object] = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg="ES256", use="sig")
    return jwk


def _sign(
    key: ec.EllipticCurvePrivateKey,
    payload: dict[str, object],
    *,
    typ: str,
    kid: str,
) -> str:
    return pyjwt.encode(payload, key, algorithm="ES256", headers={"typ": typ, "kid": kid})


class _Attester:
    """Attester de confiance et wallet ``cnf`` : paires de clés et fabrique de JWT."""

    def __init__(self) -> None:
        self.key = _new_key()
        self.jwks = (_public_jwk(self.key, "attester-key"),)
        self.wallet_key = _new_key()
        self.wallet_jwk = _public_jwk(self.wallet_key, "wallet-key")

    def attestation_payload(
        self, *, client_id: str = _CLIENT_ID, wallet_jwk: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {
            "iss": _ATTESTER,
            "sub": client_id,
            "iat": _now(),
            "exp": _now() + 300,
            "cnf": {"jwk": wallet_jwk if wallet_jwk is not None else self.wallet_jwk},
        }

    def attestation(
        self,
        *,
        client_id: str = _CLIENT_ID,
        wallet_jwk: dict[str, object] | None = None,
        **claims: object,
    ) -> str:
        payload = self.attestation_payload(client_id=client_id, wallet_jwk=wallet_jwk)
        payload.update(claims)
        return _sign(self.key, payload, typ=CLIENT_ATTESTATION_TYPE, kid="attester-key")

    def pop_payload(self, *, jti: str | None = None) -> dict[str, object]:
        return {
            "iss": _CLIENT_ID,
            "aud": _ISSUER,
            "iat": _now(),
            "jti": jti if jti is not None else f"jti-{uuid.uuid4()}",
        }

    def pop(
        self,
        *,
        key: ec.EllipticCurvePrivateKey | None = None,
        kid: str = "wallet-key",
        **claims: object,
    ) -> str:
        payload = self.pop_payload()
        payload.update(claims)
        return _sign(
            key if key is not None else self.wallet_key,
            payload,
            typ=CLIENT_ATTESTATION_POP_TYPE,
            kid=kid,
        )

    def headers(self) -> dict[str, str]:
        return {
            ATTESTATION_HEADER: self.attestation(),
            ATTESTATION_POP_HEADER: self.pop(),
        }


def _verifier(
    attester: _Attester,
    *,
    issuer: str = _ATTESTER,
    as_issuer: str = _ISSUER,
    replays: InMemoryDpopReplayRepository | None = None,
) -> PyJWTClientAttestationVerifier:
    return PyJWTClientAttestationVerifier(
        issuer=issuer,
        as_issuer=as_issuer,
        jwks=attester.jwks,
        replays=replays if replays is not None else InMemoryDpopReplayRepository(),
    )


def _attest_client(method: TokenEndpointAuthMethod) -> Client:
    return Client(
        client_id=_CLIENT_ID,
        redirect_uris=frozenset({_REDIRECT_URI}),
        scopes=frozenset({Scope.OPENID}),
        client_type=ClientType.CONFIDENTIAL,
        token_endpoint_auth_method=method,
    )


def _app(*, scopes: str = "openid", **settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(
                {
                    "client_id": _CLIENT_ID,
                    "redirect_uris": [_REDIRECT_URI],
                    "scopes": scopes,
                    "client_type": "confidential",
                    "token_endpoint_auth_method": "attest_jwt_client_auth",
                },
            ),
            **settings,
        )
    )


def _code_of(client: TestClient, attester: _Attester) -> str:
    """Pousse une demande, la visite sur /authorize et retourne le code émis."""
    push = client.post("/par", data=_PAR_DATA, headers=attester.headers())
    assert push.status_code == 201
    auth = client.get(
        "/authorize",
        params={"client_id": _CLIENT_ID, "request_uri": push.json()["request_uri"]},
        follow_redirects=False,
    )
    assert auth.status_code == 302
    query = parse_qs(urlparse(auth.headers["location"]).query)
    assert query["code"]
    return query["code"][0]


class TestExtractionHeaders:
    """Lecture des en-têtes d'attestation (§6.1, §9-1)."""

    def test_extracts_both_values(self) -> None:
        headers = Headers({ATTESTATION_HEADER: " attestation ", ATTESTATION_POP_HEADER: "pop"})
        assert extract_client_attestation(headers) == ("attestation", "pop", None)

    def test_returns_empty_tuple_when_absent(self) -> None:
        assert extract_client_attestation(Headers()) == ("", "", None)

    def test_rejects_duplicate_attestation_header(self) -> None:
        headers = Headers(
            raw=[
                (ATTESTATION_HEADER.encode("latin-1"), b"first"),
                (ATTESTATION_HEADER.encode("latin-1"), b"second"),
                (ATTESTATION_POP_HEADER.encode("latin-1"), b"pop"),
            ]
        )
        attestation, pop, error = extract_client_attestation(headers)
        assert (attestation, pop) == ("", "")
        assert error is not None
        assert "OAuth-Client-Attestation" in error

    def test_rejects_duplicate_pop_header(self) -> None:
        headers = Headers(
            raw=[
                (ATTESTATION_HEADER.encode("latin-1"), b"attestation"),
                (ATTESTATION_POP_HEADER.encode("latin-1"), b"first"),
                (ATTESTATION_POP_HEADER.encode("latin-1"), b"second"),
            ]
        )
        attestation, pop, error = extract_client_attestation(headers)
        assert (attestation, pop) == ("", "")
        assert error is not None
        assert "OAuth-Client-Attestation-PoP" in error


class TestVerifier:
    """Validation de la paire attestation + PoP (§5, §9)."""

    def test_accepts_valid_pair(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=attester.pop(), client_id=_CLIENT_ID
            )
        )
        assert reason is None

    def test_refuses_missing_client_id(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=attester.pop(), client_id=""
            )
        )
        assert reason is not None
        assert "client_id" in reason

    def test_refuses_unreadable_attestation(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation="pas-un-jwt", pop=attester.pop(), client_id=_CLIENT_ID
            )
        )
        assert reason is not None
        assert "illisible" in reason

    def test_refuses_unknown_attester_key(self) -> None:
        attester = _Attester()
        intruder = _Attester()
        token = _sign(
            intruder.key,
            attester.attestation_payload(),
            typ=CLIENT_ATTESTATION_TYPE,
            kid="key-inconnue",
        )
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "attester de confiance" in reason

    def test_refuses_attestation_signed_by_intruder(self) -> None:
        attester = _Attester()
        intruder = _Attester()
        token = _sign(
            intruder.key,
            attester.attestation_payload(),
            typ=CLIENT_ATTESTATION_TYPE,
            kid="attester-key",
        )
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "attestation client invalide" in reason

    def test_refuses_wrong_typ(self) -> None:
        attester = _Attester()
        token = _sign(
            attester.key,
            attester.attestation_payload(),
            typ="vjwt+jwt",
            kid="attester-key",
        )
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "typ" in reason

    def test_refuses_symmetric_algorithm(self) -> None:
        attester = _Attester()
        token = pyjwt.encode(
            attester.attestation_payload(),
            b"secret-partage",
            algorithm="HS256",
            headers={"typ": CLIENT_ATTESTATION_TYPE, "kid": "attester-key"},
        )
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "alg" in reason

    def test_refuses_expired_attestation(self) -> None:
        attester = _Attester()
        token = attester.attestation(exp=_now() - 600)
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason == "attestation client expirée (§5.1)"

    def test_refuses_sub_different_from_client_id(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(client_id="autre-client"),
                pop=attester.pop(),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is not None
        assert "sub" in reason

    def test_refuses_attestation_from_other_issuer(self) -> None:
        attester = _Attester()
        token = _sign(
            attester.key,
            {**attester.attestation_payload(), "iss": "https://autre-attester.example"},
            typ=CLIENT_ATTESTATION_TYPE,
            kid="attester-key",
        )
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "attestation client invalide" in reason

    def test_accepts_attester_issuer_with_trailing_slash(self) -> None:
        """L'``iss`` de l'attester se compare en égalité stricte (§5.1) : la barre finale compte."""
        attester = _Attester()
        reason = run(
            _verifier(attester, issuer=_ATTESTER).verify(
                attestation=attester.attestation(),
                pop=attester.pop(),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is None

    def test_refuses_attestation_without_cnf(self) -> None:
        attester = _Attester()
        payload = attester.attestation_payload()
        payload.pop("cnf")
        token = _sign(attester.key, payload, typ=CLIENT_ATTESTATION_TYPE, kid="attester-key")
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason is not None
        assert "attestation client invalide" in reason

    def test_refuses_cnf_without_jwk(self) -> None:
        attester = _Attester()
        token = attester.attestation(cnf={"kid": "wallet-key"})
        reason = run(
            _verifier(attester).verify(attestation=token, pop=attester.pop(), client_id=_CLIENT_ID)
        )
        assert reason == "claim cnf.jwk absente de l'attestation client (§5.1)"

    def test_refuses_cnf_with_private_key(self) -> None:
        attester = _Attester()
        private_jwk = {**attester.wallet_jwk, "d": "Gkmh-vjcuC8QStQqLqM_PhJQUp8KepSGGL2-stl79Bs"}
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(cnf={"jwk": private_jwk}),
                pop=attester.pop(),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is not None
        assert "clé privée" in reason

    def test_refuses_pop_with_wrong_audience(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(),
                pop=attester.pop(aud="https://autre-as.example"),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is not None
        assert "PoP" in reason

    def test_accepts_as_issuer_without_trailing_slash(self) -> None:
        """L'``aud`` du PoP admet l'issuer AS avec ou sans barre finale."""
        attester = _Attester()
        reason = run(
            _verifier(attester, as_issuer=f"{_ISSUER}/").verify(
                attestation=attester.attestation(),
                pop=attester.pop(),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is None

    def test_refuses_pop_with_wrong_issuer(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(),
                pop=attester.pop(iss="autre-client"),
                client_id=_CLIENT_ID,
            )
        )
        assert reason is not None
        assert "PoP" in reason

    def test_refuses_pop_with_wrong_typ(self) -> None:
        attester = _Attester()
        token = _sign(
            attester.wallet_key,
            attester.pop_payload(),
            typ=CLIENT_ATTESTATION_TYPE,
            kid="wallet-key",
        )
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=token, client_id=_CLIENT_ID
            )
        )
        assert reason is not None
        assert "typ" in reason

    def test_refuses_pop_signed_by_intruder(self) -> None:
        attester = _Attester()
        intruder = _Attester()
        token = _sign(
            intruder.wallet_key,
            attester.pop_payload(),
            typ=CLIENT_ATTESTATION_POP_TYPE,
            kid="wallet-key",
        )
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=token, client_id=_CLIENT_ID
            )
        )
        assert reason is not None
        assert "PoP" in reason

    def test_refuses_pop_bound_to_unknown_key(self) -> None:
        attester = _Attester()
        intruder = _Attester()
        token = _sign(
            intruder.wallet_key,
            attester.pop_payload(),
            typ=CLIENT_ATTESTATION_POP_TYPE,
            kid="autre-clef",
        )
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=token, client_id=_CLIENT_ID
            )
        )
        assert reason == "cnf.jwk de l'attestation illisible (§9-7)"

    def test_refuses_pop_with_stale_iat(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(),
                pop=attester.pop(iat=_now() - 600),
                client_id=_CLIENT_ID,
            )
        )
        assert reason == "claim iat du PoP trop ancienne (§9-9)"

    def test_refuses_pop_with_boolean_iat(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(),
                pop=attester.pop(iat=True),
                client_id=_CLIENT_ID,
            )
        )
        assert reason == "claim iat absente ou invalide du PoP (§5.2)"

    def test_refuses_pop_without_jti(self) -> None:
        attester = _Attester()
        payload = attester.pop_payload()
        payload.pop("jti")
        token = _sign(
            attester.wallet_key, payload, typ=CLIENT_ATTESTATION_POP_TYPE, kid="wallet-key"
        )
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(), pop=token, client_id=_CLIENT_ID
            )
        )
        assert reason is not None
        assert "PoP" in reason

    def test_refuses_pop_with_empty_jti(self) -> None:
        attester = _Attester()
        reason = run(
            _verifier(attester).verify(
                attestation=attester.attestation(),
                pop=attester.pop(jti=""),
                client_id=_CLIENT_ID,
            )
        )
        assert reason == "claim jti absente ou vide du PoP (§5.2)"

    def test_refuses_replayed_pop(self) -> None:
        attester = _Attester()
        verifier = _verifier(attester)
        attestation = attester.attestation()
        pop = attester.pop(jti="jti-fixe")
        assert run(verifier.verify(attestation=attestation, pop=pop, client_id=_CLIENT_ID)) is None
        reason = run(verifier.verify(attestation=attestation, pop=pop, client_id=_CLIENT_ID))
        assert reason == "jti du PoP déjà présenté (anti-replay, §9-12)"

    def test_subject_of_reads_unverified_sub(self) -> None:
        """§6.3 : le ``sub`` non vérifié sert à localiser le client sans ``client_id``."""
        attester = _Attester()
        verifier = _verifier(attester)
        assert verifier.subject_of(attester.attestation()) == _CLIENT_ID

    def test_subject_of_returns_empty_when_unreadable(self) -> None:
        attester = _Attester()
        verifier = _verifier(attester)
        assert verifier.subject_of("not.a-jwt") == ""
        assert (
            verifier.subject_of(pyjwt.encode({"client_id": "x"}, attester.key, algorithm="ES256"))
            == ""
        )

    def test_instance_key_is_thumbprint_of_cnf_jwk(self) -> None:
        """§10.3 : l'instance client est l'empreinte RFC 7638 de ``cnf.jwk``."""
        attester = _Attester()
        verifier = _verifier(attester)
        assert verifier.instance_key_of(attester.attestation()) == jwk_thumbprint(
            attester.wallet_jwk
        )
        assert verifier.instance_key_of("not.a-jwt") == ""
        payload = attester.attestation_payload()
        del payload["cnf"]
        without_cnf = _sign(attester.key, payload, typ=CLIENT_ATTESTATION_TYPE, kid="attester-key")
        assert verifier.instance_key_of(without_cnf) == ""


class TestDispatch:
    """Câblage de la méthode ``attest_jwt_client_auth`` dans authenticate_client."""

    def test_accepts_valid_pair(self) -> None:
        attester = _Attester()
        client = _attest_client(TokenEndpointAuthMethod.ATTEST_JWT_CLIENT_AUTH)
        reason = run(
            authenticate_client(
                client,
                attestation_verifier=_verifier(attester),
                attestation=attester.attestation(),
                attestation_pop=attester.pop(),
            )
        )
        assert reason is None

    def test_refuses_when_verifier_not_configured(self) -> None:
        attester = _Attester()
        client = _attest_client(TokenEndpointAuthMethod.ATTEST_JWT_CLIENT_AUTH)
        reason = run(
            authenticate_client(
                client,
                attestation=attester.attestation(),
                attestation_pop=attester.pop(),
            )
        )
        assert reason is not None
        assert "non configurée" in reason

    def test_refuses_missing_headers(self) -> None:
        attester = _Attester()
        client = _attest_client(TokenEndpointAuthMethod.ATTEST_JWT_CLIENT_AUTH)
        reason = run(
            authenticate_client(
                client,
                attestation_verifier=_verifier(attester),
                attestation=attester.attestation(),
            )
        )
        assert reason is not None
        assert "OAuth-Client-Attestation" in reason

    def test_ignores_attestation_for_other_method(self) -> None:
        """La méthode enregistrée du client prime : l'attestation n'est pas un chemin de repli."""
        attester = _Attester()
        client = _attest_client(TokenEndpointAuthMethod.PRIVATE_KEY_JWT)
        reason = run(
            authenticate_client(
                client,
                attestation_verifier=_verifier(attester),
                attestation=attester.attestation(),
                attestation_pop=attester.pop(),
            )
        )
        assert reason == ASSERTION_INVALID_ERROR


class TestSettings:
    """Chargement des settings ``client_attestation_*``."""

    def test_accepts_env_jwks_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        jwks = json.dumps({"keys": [_public_jwk(_new_key(), "env-key")]})
        monkeypatch.setenv("PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS", jwks)
        settings = Settings(_env_file=None)
        assert settings.client_attestation_jwks[0]["kid"] == "env-key"

    def test_rejects_env_jwks_without_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS", '{"kty": "EC"}')
        with pytest.raises(ValueError, match="objet JWKS"):
            Settings(_env_file=None)

    def test_rejects_env_jwks_invalid_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS", "pas-du-json")
        with pytest.raises(ValueError):
            Settings(_env_file=None)


class TestDiscovery:
    """Publication des métadonnées d'attestation (§10.1)."""

    def test_publishes_method_and_algorithms_when_configured(self) -> None:
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
        assert "attest_jwt_client_auth" in metadata["token_endpoint_auth_methods_supported"]
        assert metadata["client_attestation_signing_alg_values_supported"] == ["ES256"]
        assert metadata["client_attestation_pop_signing_alg_values_supported"] == ["ES256"]

    def test_omits_method_and_algorithms_by_default(self) -> None:
        with TestClient(_app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
        assert "attest_jwt_client_auth" not in metadata["token_endpoint_auth_methods_supported"]
        assert "client_attestation_signing_alg_values_supported" not in metadata
        assert "client_attestation_pop_signing_alg_values_supported" not in metadata

    def test_publishes_default_algorithms_without_alg_on_keys(self) -> None:
        key = _public_jwk(_new_key(), "sans-alg")
        key.pop("alg")
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=(key,))
        ) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
        assert metadata["client_attestation_signing_alg_values_supported"] == [
            "ES256",
            "PS256",
            "RS256",
        ]


class TestParEndpoint:
    """Authentification par attestation au endpoint ``/par`` (§6.4)."""

    def test_push_succeeds_with_attestation_headers(self) -> None:
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            resp = client.post("/par", data=_PAR_DATA, headers=attester.headers())
        assert resp.status_code == 201
        assert resp.json()["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")

    def test_push_refuses_missing_attestation_headers(self) -> None:
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            resp = client.post("/par", data=_PAR_DATA)
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"

    def test_push_refuses_replayed_pop(self) -> None:
        attester = _Attester()
        headers = {
            ATTESTATION_HEADER: attester.attestation(),
            ATTESTATION_POP_HEADER: attester.pop(jti="jti-fixe"),
        }
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            first = client.post("/par", data=_PAR_DATA, headers=headers)
            second = client.post("/par", data=_PAR_DATA, headers=headers)
        assert first.status_code == 201
        assert second.status_code == 401
        assert second.json()["error"] == "invalid_client"

    def test_push_refuses_duplicate_header(self) -> None:
        attester = _Attester()
        headers: list[tuple[str, str]] = [
            (ATTESTATION_HEADER, attester.attestation()),
            (ATTESTATION_HEADER, attester.attestation()),
            (ATTESTATION_POP_HEADER, attester.pop()),
        ]
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            resp = client.post("/par", data=_PAR_DATA, headers=headers)
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


class TestTokenEndpoint:
    """Authentification par attestation au endpoint ``/token`` (§6.4)."""

    def test_code_exchange_succeeds_with_attestation_headers(self) -> None:
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            code = _code_of(client, attester)
            resp = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": _REDIRECT_URI,
                    "client_id": _CLIENT_ID,
                },
                headers=attester.headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"]

    def test_code_exchange_without_client_id_in_body(self) -> None:
        """§6.3 : ``client_id`` optionnel au /token, le ``sub`` identifie le client."""
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            code = _code_of(client, attester)
            resp = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": _REDIRECT_URI,
                },
                headers=attester.headers(),
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"]

    def test_code_exchange_refuses_missing_attestation_headers(self) -> None:
        attester = _Attester()
        with TestClient(
            _app(client_attestation_issuer=_ATTESTER, client_attestation_jwks=attester.jwks)
        ) as client:
            code = _code_of(client, attester)
            resp = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": _REDIRECT_URI,
                    "client_id": _CLIENT_ID,
                },
            )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_client"


class TestRefreshTokenInstanceKey:
    """Liaison du refresh token à l'instance client (OAuth2-ATCA §10.3)."""

    @staticmethod
    def _exchange(client: TestClient, attester: _Attester) -> dict[str, Any]:
        """Échange un code d'autorisation et retourne la réponse ``/token``."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": _code_of(client, attester),
                "redirect_uri": _REDIRECT_URI,
            },
            headers=attester.headers(),
        )
        assert resp.status_code == 200
        return resp.json()

    @staticmethod
    def _refresh(client: TestClient, refresh_token: str, headers: dict[str, str]) -> httpx.Response:
        """Renouvelle à partir de ``refresh_token`` avec les ``headers`` donnés."""
        return client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers=headers,
        )

    @staticmethod
    def _app_with(attester: _Attester, **settings: object) -> FastAPI:
        return _app(
            client_attestation_issuer=_ATTESTER,
            client_attestation_jwks=attester.jwks,
            **settings,
        )

    def test_code_exchange_emits_refresh_token_for_registered_offline_access(self) -> None:
        """Le client enregistré ``offline_access`` reçoit un RT sans le demander.

        Dans le flux OpenID4VCI la suite de certification remplace le scope
        de la demande par celui de la credential configuration : le client
        enregistré fait alors foi pour l'émission (OIDC Core §12).
        """
        attester = _Attester()
        with TestClient(self._app_with(attester, scopes="openid offline_access")) as client:
            body = self._exchange(client, attester)
        assert body["refresh_token"]

    def test_code_exchange_omits_refresh_token_without_offline_access(self) -> None:
        attester = _Attester()
        with TestClient(self._app_with(attester)) as client:
            body = self._exchange(client, attester)
        assert "refresh_token" not in body

    def test_refresh_rejects_other_instance_then_accepts_issuing_instance(self) -> None:
        """§10.3 : seul le détenteur de la ``cnf.jwk`` d'émission renouvelle.

        Le refus ne consomme pas le jeton : le renouvellement par la même
        instance qui suit doit encore réussir (la rotation FAPI2 n'est pas
        active sur ce harnais, l'ancien RT est donc tourné à ce moment-là).
        """
        attester = _Attester()
        rogue_key = _new_key()
        rogue_headers = {
            ATTESTATION_HEADER: attester.attestation(
                wallet_jwk=_public_jwk(rogue_key, "rogue-key")
            ),
            ATTESTATION_POP_HEADER: attester.pop(key=rogue_key, kid="rogue-key"),
        }
        with TestClient(self._app_with(attester, scopes="openid offline_access")) as client:
            refresh_token = self._exchange(client, attester)["refresh_token"]
            rogue = self._refresh(client, refresh_token, rogue_headers)
            own = self._refresh(client, refresh_token, attester.headers())
        assert rogue.status_code == 400
        assert rogue.json()["error"] == "invalid_client_attestation"
        assert own.status_code == 200
        assert own.json()["access_token"]
