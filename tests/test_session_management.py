"""Tests du Session Management OIDC 1.0 — usecase, iframe et endpoint de statut.

- Unitaires : ``SessionManagementUseCase`` (calcul/format/liens), helper
  ``origin_of_url`` (RFC 6454 §4 : ports par défaut omis, hôte normalisé).
- Intégration HTTP : métadonnées ``check_session_iframe``, page ``/session_state``
  (script postMessage), ``GET /check_session`` (erreurs 400, ``ok``,
  ``changed``) et présence du paramètre ``session_state`` dans la réponse
  d'``/authorize`` (query du code flow, fragment des flows à jeton).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.session_management import (
    SessionManagementUseCase,
    origin_of_url,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"
_CLIENT_ORIGIN = "https://app.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile email",
    "client_type": "confidential",
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}

_HTTP_CLIENT_JSON = {
    "client_id": "spa-app",
    "client_secret": "spa-secret",
    "redirect_uris": ["http://127.0.0.1:5177/callback"],
    "scopes": "openid profile",
    "client_type": "public",
}


def _app(**settings: object) -> FastAPI:
    merged: dict[str, object] = {
        "issuer": _ISSUER,
        "base_url": _ISSUER,
        "jwks_algorithms": ("RS256",),
        "clients_seed": (_CLIENT_JSON,),
        "identity_seed_users": _IDENTITY_SEED,
    }
    merged.update(settings)
    return create_app(Settings(**merged))


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


def _login(client: TestClient) -> None:
    """Se connecte au serveur (cookie de session + ``sid`` posé)."""
    response = client.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def _authorize(
    client: TestClient,
    *,
    redirect_uri: str = _REDIRECT_URI,
    response_type: str = "code",
) -> dict[str, list[str]]:
    """Exécute une demande d'autorisation et retourne les paramètres de réponse."""
    params: dict[str, str] = {
        "response_type": response_type,
        "client_id": "web-app",
        "redirect_uri": redirect_uri,
        "scope": "openid profile",
        "nonce": "n-session",
    }
    response = client.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    fragment = urlparse(location).fragment
    return parse_qs(fragment) if fragment else _redirect_query(location)


# ───── Unitaires : calcul et vérification du session_state ───────────────── #


def test_origin_of_url_omits_default_ports_and_normalizes_host() -> None:
    assert origin_of_url("https://app.example/callback") == "https://app.example"
    assert origin_of_url("http://127.0.0.1:5177/cb") == "http://127.0.0.1:5177"
    assert origin_of_url("http://127.0.0.1:80/cb") == "http://127.0.0.1"
    assert origin_of_url("https://app.example:443/x") == "https://app.example"
    assert origin_of_url("HTTP://APP.Example:8443/path") == "http://app.example:8443"


def test_origin_of_url_malformed_port_is_empty() -> None:
    assert origin_of_url("https://app.example:not-a-port/cb") == ""


def test_create_session_state_format_and_roundtrip() -> None:
    usecase = SessionManagementUseCase()
    value = usecase.create_session_state(
        client_id="web-app", origin=_CLIENT_ORIGIN, session_id="sid-1"
    )

    assert " " not in value
    assert re.fullmatch(r"[A-Za-z0-9_\-]{43}\.[A-Za-z0-9_\-]+", value)
    assert usecase.verify_session_state(
        client_id="web-app", origin=_CLIENT_ORIGIN, session_id="sid-1", session_state=value
    )


def test_session_state_is_bound_to_client_origin_and_session() -> None:
    usecase = SessionManagementUseCase()
    value = usecase.create_session_state(
        client_id="web-app", origin=_CLIENT_ORIGIN, session_id="sid-1"
    )

    assert not usecase.verify_session_state(
        client_id="other-app", origin=_CLIENT_ORIGIN, session_id="sid-1", session_state=value
    )
    assert not usecase.verify_session_state(
        client_id="web-app", origin="https://other.example", session_id="sid-1", session_state=value
    )
    assert not usecase.verify_session_state(
        client_id="web-app", origin=_CLIENT_ORIGIN, session_id="sid-2", session_state=value
    )
    assert value != usecase.create_session_state(
        client_id="web-app", origin=_CLIENT_ORIGIN, session_id="sid-1"
    )


def test_verify_rejects_malformed_session_state() -> None:
    usecase = SessionManagementUseCase()
    for bad in ("", "with space.salt", "hashonly", "hash.", ".salt", "hash..salt", "hash.salt!"):
        assert not usecase.verify_session_state(
            client_id="web-app",
            origin=_CLIENT_ORIGIN,
            session_id="sid-1",
            session_state=bad,
        )


# ───── Intégration HTTP : discovery + iframe + endpoint de statut ────────── #


def test_discovery_publishes_check_session_iframe() -> None:
    with TestClient(_app()) as client:
        document = client.get("/.well-known/openid-configuration").json()

    assert document["check_session_iframe"] == f"{_ISSUER}/session_state"


def test_check_session_iframe_page_serves_monitoring_script() -> None:
    with TestClient(_app()) as client:
        response = client.get("/session_state")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "postMessage" in response.text
    assert "/check_session" in response.text


def test_check_session_rejects_malformed_or_unknown_requests() -> None:
    with TestClient(_app()) as client:
        assert client.get("/check_session").status_code == 400
        assert (
            client.get(
                "/check_session",
                params={"client_id": "", "session_state": "x.y", "origin": _CLIENT_ORIGIN},
            ).status_code
            == 400
        )
        assert (
            client.get(
                "/check_session",
                params={
                    "client_id": "web-app",
                    "session_state": "with space.salt",
                    "origin": _CLIENT_ORIGIN,
                },
            ).status_code
            == 400
        )
        assert (
            client.get(
                "/check_session",
                params={"client_id": "web-app", "session_state": "x.y", "origin": "not-an-origin"},
            ).status_code
            == 400
        )
        assert (
            client.get(
                "/check_session",
                params={
                    "client_id": "unknown-app",
                    "session_state": "x.y",
                    "origin": _CLIENT_ORIGIN,
                },
            ).status_code
            == 400
        )


def test_check_session_reports_changed_without_active_session() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/check_session",
            params={
                "client_id": "web-app",
                "session_state": "dummy.dummy",
                "origin": _CLIENT_ORIGIN,
            },
        )

    assert response.status_code == 200
    assert response.text == "changed"


def test_check_session_reports_ok_for_live_session_session_state() -> None:
    with TestClient(_app()) as client:
        _login(client)
        params = _authorize(client)
        session_state = params["session_state"][0]

        response = client.get(
            "/check_session",
            params={
                "client_id": "web-app",
                "session_state": session_state,
                "origin": _CLIENT_ORIGIN,
            },
        )

    assert response.status_code == 200
    assert response.text == "ok"


def test_check_session_reports_changed_for_stale_session_state() -> None:
    with TestClient(_app()) as client:
        _login(client)
        params = _authorize(client)
        session_state = params["session_state"][0]
        stale = session_state + "tampered"

        response = client.get(
            "/check_session",
            params={"client_id": "web-app", "session_state": stale, "origin": _CLIENT_ORIGIN},
        )

    assert response.status_code == 200
    assert response.text == "changed"


def test_check_session_reports_changed_after_logout() -> None:
    with TestClient(_app()) as client:
        _login(client)
        params = _authorize(client)
        session_state = params["session_state"][0]
        client.get("/end_session", follow_redirects=False)

        response = client.get(
            "/check_session",
            params={
                "client_id": "web-app",
                "session_state": session_state,
                "origin": _CLIENT_ORIGIN,
            },
        )

    assert response.status_code == 200
    assert response.text == "changed"


# ───── Intégration HTTP : session_state dans la réponse /authorize ───────── #


def test_authorize_code_flow_includes_session_state() -> None:
    with TestClient(_app()) as client:
        _login(client)
        params = _authorize(client)

    assert re.fullmatch(r"[A-Za-z0-9_\-]{43}\.[A-Za-z0-9_\-]+", params["session_state"][0])


def test_authorize_hybrid_flow_puts_session_state_in_fragment() -> None:
    with TestClient(_app()) as client:
        _login(client)
        response = client.get(
            "/authorize",
            params={
                "response_type": "code id_token token",
                "client_id": "web-app",
                "redirect_uri": _REDIRECT_URI,
                "scope": "openid profile",
                "nonce": "n-session",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    fragment = parse_qs(urlparse(response.headers["location"]).fragment)
    assert re.fullmatch(r"[A-Za-z0-9_\-]{43}\.[A-Za-z0-9_\-]+", fragment["session_state"][0])
    assert "code" in fragment and "id_token" in fragment and "access_token" in fragment


def test_authorize_omits_session_state_when_not_logged_in() -> None:
    with TestClient(_app()) as client:
        params = _authorize(client)

    assert "session_state" not in params
    assert "code" in params


def test_authorize_matches_spa_http_origin() -> None:
    app = _app(clients_seed=(_CLIENT_JSON, _HTTP_CLIENT_JSON))
    with TestClient(app) as client:
        _login(client)
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "spa-app",
                "redirect_uri": "http://127.0.0.1:5177/callback",
                "scope": "openid profile",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        session_state = _redirect_query(response.headers["location"])["session_state"][0]
        status = client.get(
            "/check_session",
            params={
                "client_id": "spa-app",
                "session_state": session_state,
                "origin": "http://127.0.0.1:5177",
            },
        )

    assert status.text == "ok"
