"""Tests minimaux OpenID4VP (slice 0, issue #223)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app


def test_flag_off_exposes_no_oid4vp_routes() -> None:
    client = TestClient(create_app(settings=Settings(oid4vp_enabled=False)))
    response = client.post("/presentation_requests")
    assert response.status_code == 404


def test_flag_on_creates_presentation_request() -> None:
    client = TestClient(create_app(settings=Settings(oid4vp_enabled=True)))
    response = client.post("/presentation_requests", json={})
    assert response.status_code == 200
    body = response.json()
    assert "request" in body
    assert "nonce" in body


def test_vp_response_requires_vp_token() -> None:
    client = TestClient(create_app(settings=Settings(oid4vp_enabled=True)))
    response = client.post("/vp_response")
    assert response.status_code == 400


def test_vp_response_http() -> None:
    import jwt as pyjwt

    client = TestClient(create_app(settings=Settings(oid4vp_enabled=True)))

    # Corps vide : 400.
    assert client.post("/vp_response").status_code == 400

    request = client.post("/presentation_requests", json={})
    assert request.status_code == 200
    nonce = request.json()["nonce"]

    vp_token = pyjwt.encode(
        {"nonce": nonce}, "secret123456789012345678901234567890", algorithm="HS256"
    )

    form_response = client.post("/vp_response", data={"vp_token": vp_token})
    assert form_response.status_code == 200
    assert form_response.json()["status"] == "received"

    json_response = client.post("/vp_response", json={"vp_token": vp_token})
    # nonce deja consomme.
    assert json_response.status_code == 400
