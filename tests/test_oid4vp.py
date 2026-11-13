"""Tests des routes FastAPI OpenID4VP : montage, round-trip et rejets (issue #224)."""

from __future__ import annotations

import jwt as pyjwt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from oid4vp_wallet import SimulatedWallet

from puridentityserver.application.oid4vp import (
    REQUEST_OBJECT_MEDIA_TYPE,
    OID4VPVerifierUseCase,
)
from puridentityserver.infrastructure.oid4vp_pki import InMemoryVerifierPKIRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.oid4vp import oid4vp_router
from puridentityserver.server import create_app

ISSUER = "https://id.example"


def _usecase() -> OID4VPVerifierUseCase:
    """Construit un verifier en memoire pour les tests de routes."""
    return OID4VPVerifierUseCase(
        issuer=ISSUER,
        pki_repository=InMemoryVerifierPKIRepository(),
    )


def _client(usecase: OID4VPVerifierUseCase | None = None) -> TestClient:
    """Monte le routeur oid4vp seul sur une application minimale."""
    app = FastAPI()
    app.include_router(oid4vp_router(oid4vp_usecase=usecase))
    return TestClient(app)


def test_flag_off_exposes_no_oid4vp_routes() -> None:
    """Desactivee, la feature ne monte aucune route : 404 partout."""
    client = TestClient(create_app(settings=Settings(oid4vp_enabled=False)))
    assert client.post("/oid4vp/presentation_requests", json={}).status_code == 404
    assert client.get("/oid4vp/request_uri/abc").status_code == 404
    assert client.post("/oid4vp/vp_response/abc", data={"response": "x"}).status_code == 404
    assert client.get("/oid4vp/result/abc").status_code == 404


def test_flag_on_mounts_routes_and_creates_request() -> None:
    """Activee, la route de creation repond 201 avec la demande signee."""
    client = TestClient(create_app(settings=Settings(oid4vp_enabled=True)))
    response = client.post("/oid4vp/presentation_requests", json={})
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {
        "request_id",
        "client_id",
        "request_uri",
        "nonce",
        "request_object",
    }
    assert body["client_id"].startswith("x509_hash:")
    assert body["request_uri"].endswith(f"/oid4vp/request_uri/{body['request_id']}")


def test_router_without_usecase_returns_501() -> None:
    """Un routeur monte sans cas d'utilisation repond 501 sur chaque route."""
    client = _client()
    assert client.post("/oid4vp/presentation_requests", json={}).status_code == 501
    assert client.get("/oid4vp/request_uri/abc").status_code == 501
    assert client.post("/oid4vp/request_uri/abc", data={"wallet_nonce": "n"}).status_code == 501
    assert client.post("/oid4vp/vp_response/abc", data={"response": "x"}).status_code == 501
    assert client.get("/oid4vp/result/abc").status_code == 501


def test_presentation_requests_rejects_invalid_json() -> None:
    """Un corps non JSON ou non objet est refuse en 400."""
    client = _client(_usecase())
    response = client.post(
        "/oid4vp/presentation_requests",
        content=b"not-json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    response = client.post(
        "/oid4vp/presentation_requests",
        content=b"[1, 2]",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


def test_presentation_requests_rejects_non_object_dcql() -> None:
    """Un dcql_query qui n'est pas un objet JSON est refuse."""
    client = _client(_usecase())
    response = client.post("/oid4vp/presentation_requests", json={"dcql_query": ["x"]})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_presentation_requests_accepts_empty_body() -> None:
    """Un corps vide cree une demande avec le DCQL par defaut."""
    client = _client(_usecase())
    response = client.post(
        "/oid4vp/presentation_requests",
        content=b"",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 201
    assert response.json()["nonce"]


def test_request_uri_serves_signed_object() -> None:
    """Le GET du request_uri rend le JWT avec le media type OAuth autorise."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    response = client.get(f"/oid4vp/request_uri/{created['request_id']}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(REQUEST_OBJECT_MEDIA_TYPE)
    assert response.text == created["request_object"]
    again = client.get(f"/oid4vp/request_uri/{created['request_id']}")
    assert again.text == response.text


def test_request_uri_unknown_id_is_404() -> None:
    """Un request_uri inconnu repond 404 en JSON OAuth."""
    client = _client(_usecase())
    response = client.get("/oid4vp/request_uri/missing")
    assert response.status_code == 404
    assert response.json()["error"] == "invalid_request"


def test_request_uri_post_wallet_nonce_resigns_document() -> None:
    """Le POST du wallet ajoute wallet_nonce et re-signe le document."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    response = client.post(
        f"/oid4vp/request_uri/{created['request_id']}", data={"wallet_nonce": "w-nonce"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(REQUEST_OBJECT_MEDIA_TYPE)
    claims = _claims(response.text)
    assert claims["wallet_nonce"] == "w-nonce"

    without_nonce = client.post(f"/oid4vp/request_uri/{created['request_id']}", data={})
    assert without_nonce.text == created["request_object"]


def test_request_uri_post_unknown_id_is_404() -> None:
    """Un POST sur un request_uri inconnu repond 404."""
    client = _client(_usecase())
    response = client.post("/oid4vp/request_uri/missing", data={"wallet_nonce": "n"})
    assert response.status_code == 404


def test_vp_response_requires_form_field() -> None:
    """Le parametre de formulaire response est obligatoire (400)."""
    client = _client(_usecase())
    response = client.post("/oid4vp/vp_response/anything", data={})
    assert response.status_code == 400
    assert response.json()["error_description"] == "paramètre de formulaire response manquant"


def test_vp_response_unknown_request_is_404() -> None:
    """Une presentation sur une demande inconnue repond 404."""
    client = _client(_usecase())
    response = client.post("/oid4vp/vp_response/missing", data={"response": "x"})
    assert response.status_code == 404
    assert response.json()["error"] == "invalid_request"


def test_vp_response_accepts_valid_wallet_presentation() -> None:
    """Round-trip : 200 avec exactement le corps redirect_uri attendu."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    wallet = SimulatedWallet()
    response = wallet.respond(created["request_object"])
    result = client.post(
        f"/oid4vp/vp_response/{created['request_id']}", data={"response": response}
    )
    assert result.status_code == 200
    assert result.json() == {"redirect_uri": f"{ISSUER}/oid4vp/result/{created['request_id']}"}


def test_vp_response_rejects_invalid_presentation() -> None:
    """Une presentation invalide repond 400 avec le motif OAuth."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    wallet = SimulatedWallet()
    response = wallet.respond(created["request_object"], overrides={"nonce": "bad"})
    result = client.post(
        f"/oid4vp/vp_response/{created['request_id']}", data={"response": response}
    )
    assert result.status_code == 400
    body = result.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "nonce du kb-jwt invalide"


def test_result_page_renders_outcomes() -> None:
    """La page de resultat s'affiche apres acceptation comme apres rejet."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    pending = client.get(f"/oid4vp/result/{created['request_id']}")
    assert pending.status_code == 200
    assert "Presentation refusee" in pending.text
    assert "<dl>" not in pending.text

    wallet = SimulatedWallet()
    response = wallet.respond(created["request_object"])
    client.post(f"/oid4vp/vp_response/{created['request_id']}", data={"response": response})
    accepted = client.get(f"/oid4vp/result/{created['request_id']}")
    assert accepted.status_code == 200
    assert "Presentation acceptee" in accepted.text
    assert created["request_id"] in accepted.text
    # Les claims du credential accepte sont rendus en liste echappee HTML.
    assert "<dl>" in accepted.text
    assert "<dt>vct</dt>" in accepted.text
    assert "<dd>urn:eudi:pid:1</dd>" in accepted.text


def test_result_page_escapes_claim_values() -> None:
    """Les claims affiches sont echappes HTML (anti-XSS, regle S5131)."""
    client = _client(_usecase())
    created = client.post("/oid4vp/presentation_requests", json={}).json()
    wallet = SimulatedWallet()
    credential = wallet.credential(extra_claims={"evil": "<script>alert(1)</script>"})
    response = wallet.respond(created["request_object"], credential=credential)
    client.post(f"/oid4vp/vp_response/{created['request_id']}", data={"response": response})
    page = client.get(f"/oid4vp/result/{created['request_id']}")
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text


def test_result_page_unknown_request_is_404() -> None:
    """Une page de resultat pour une demande inconnue repond 404."""
    client = _client(_usecase())
    response = client.get("/oid4vp/result/missing")
    assert response.status_code == 404


def _claims(document: str) -> dict[str, object]:
    """Decode les claims d'un JWT sans verifier sa signature."""
    claims: dict[str, object] = pyjwt.decode(document, options={"verify_signature": False})
    return claims
