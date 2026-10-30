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
    """Couvre la route direct_post avec un vp_token signe."""
    import time

    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    settings = Settings(oid4vp_enabled=True)
    client = TestClient(create_app(settings=settings), base_url="http://127.0.0.1:8000")

    # Corps vide : 400.
    assert client.post("/vp_response").status_code == 400

    # Emet une demande pour obtenir un nonce.
    request = client.post("/presentation_requests", json={})
    assert request.status_code == 200
    nonce = request.json()["nonce"]

    # vp_token signe avec JWK embarque.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["alg"] = "RS256"
    now = int(time.time())
    vp_token = pyjwt.encode(
        {
            "iss": "did:example:holder",
            "aud": settings.issuer,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"typ": "JWT", "alg": "RS256", "jwk": public_jwk},
    )

    form_response = client.post("/vp_response", data={"vp_token": vp_token})
    assert form_response.status_code == 200
    assert form_response.json()["status"] == "received"

    # Nonce consomme : replay -> 400.
    replay = client.post("/vp_response", data={"vp_token": vp_token})
    assert replay.status_code == 400

    # Jeton arbitraire -> 400.
    bogus = client.post("/vp_response", data={"vp_token": "not-a-jwt"})
    assert bogus.status_code == 400

    # Corps JSON -> chemin _read_json_fields.
    json_response = client.post("/vp_response", json={"vp_token": "not-a-jwt"})
    assert json_response.status_code == 400
