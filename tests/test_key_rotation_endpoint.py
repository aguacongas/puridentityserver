"""Tests de l'endpoint d'administration de rotation des clés de signature.

Couvre l'autorisation (un jeton d'administration est exigé), l'effet de la
rotation (une nouvelle clé est publiée, l'ancienne reste publiée pendant la
rétention — OIDC Core 1.0 §10.1) et le refus des jetons non habilités.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_ADMIN_CLIENT = {
    "client_id": "admin-app",
    "client_secret": "admin-secret",
    "scopes": "openid",
    "client_type": "confidential",
}

_OTHER_CLIENT = {
    "client_id": "other-app",
    "client_secret": "other-secret",
    "scopes": "openid",
    "client_type": "confidential",
}


def _app() -> FastAPI:
    """Application dont l'API d'administration est protegee par ``client_id``."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            jwks_key_size=2048,
            clients_seed=(_ADMIN_CLIENT, _OTHER_CLIENT),
            admin_required_claim="client_id",
            admin_required_claim_values=("admin-app",),
        )
    )


def _token(client: TestClient, client_id: str, secret: str) -> str:
    """Access token client_credentials du client donne."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def _kids(client: TestClient) -> set[str]:
    """Kids publies au JWKS."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200, response.text
    return {key["kid"] for key in response.json()["keys"]}


def test_rotate_endpoint_requires_a_token() -> None:
    """Sans jeton, l'endpoint refuse la rotation (401)."""
    with TestClient(_app()) as client:
        response = client.post("/signing-keys/rotate")

    assert response.status_code == 401


def test_rotate_endpoint_refuses_a_token_without_the_admin_claim() -> None:
    """Un jeton valide mais non habilite ne fait pas pivoter les cles."""
    with TestClient(_app()) as client:
        token = _token(client, "other-app", "other-secret")
        before = _kids(client)

        response = client.post("/signing-keys/rotate", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 401
        assert _kids(client) == before


def test_rotate_endpoint_publishes_a_new_key_and_keeps_the_previous_one() -> None:
    """OIDC Core 1.0 §10.1 : nouvelle clé publiée, ancienne clé conservée."""
    with TestClient(_app()) as client:
        token = _token(client, "admin-app", "admin-secret")
        before = _kids(client)

        response = client.post("/signing-keys/rotate", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200, response.text
        rotated = response.json()["rotated"]
        assert [entry["alg"] for entry in rotated] == ["RS256"]
        after = _kids(client)
        assert after - before, "aucune nouvelle clé publiée"
        assert before & after, "l'ancienne clé de signature a disparu du JWKS"


def _seed_client_settings(secret: str) -> Settings:
    """Settings dont le client seed porte le secret donné."""
    return Settings(
        _env_file=None,
        issuer=_ISSUER,
        base_url=_ISSUER,
        clients_seed=(
            {
                "client_id": "certification-admin",
                "client_secret": secret,
                "scopes": "openid",
                "client_type": "confidential",
            },
        ),
    )


def test_seed_client_secret_can_be_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Un secret de seed peut etre reference par l'environnement (jamais commite)."""
    monkeypatch.setenv("CERTIFICATION_ADMIN_CLIENT_SECRET", "s3cr3t-de-lenvironnement")

    referenced = _seed_client_settings("${CERTIFICATION_ADMIN_CLIENT_SECRET}").seed_clients[0]
    literal = _seed_client_settings("s3cr3t-de-lenvironnement").seed_clients[0]

    assert referenced.client_secret_hash == literal.client_secret_hash


def test_seed_client_secret_unresolved_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un placeholder non resolu donne un secret vide : il n'est jamais devine."""
    monkeypatch.delenv("CERTIFICATION_ADMIN_CLIENT_SECRET", raising=False)

    unresolved = _seed_client_settings("${CERTIFICATION_ADMIN_CLIENT_SECRET}").seed_clients[0]
    empty = _seed_client_settings("").seed_clients[0]

    assert unresolved.client_secret_hash == empty.client_secret_hash
