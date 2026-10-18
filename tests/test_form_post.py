"""Tests de la feature form_post (Form Post Response Mode 1.0, RFC 9207 §2).

- transport de succès : page 200 auto-soumise ``POST`` vers la ``redirect_uri``
  nue (action sans query ni fragment), champs ``code`` / ``state`` / ``iss``
  échappés ``html``, en-têtes ``no-store``, repli ``<noscript>`` ;
- erreurs redirigeables même transport : ``login_required`` (``prompt=none``),
  ``access_denied`` (consentement), ``unsupported_response_type``,
  ``invalid_request`` (PAR exigé, ``response_type`` absent — CA 4) toutes
  portant ``iss`` (RFC 9207 §2) ;
- combinaisons autorisées (jetons + ``form_post``), garde-fous sans
  ``form_post`` (page 400 classique), aller-retour PAR, discovery publiée.
"""

import asyncio
import base64
import hashlib
import html
import re
from collections.abc import Awaitable
from typing import TypeVar

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import AuthorizeRedirect
from puridentityserver.domain.authorization import ResponseMode
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.form_post import authorization_response
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"

_CLIENT_JSON: dict[str, object] = {
    "client_id": "formpost-app",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "public",
}

_CONSENT_CLIENT_JSON: dict[str, object] = {
    **_CLIENT_JSON,
    "client_id": "formpost-consent-app",
    "require_consent": True,
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}

_FORM_TAG = re.compile(r'<form method="post" action="([^"]*)"')
_INPUT_TAG = re.compile(r'name="([^"]*)" value="([^"]*)"')


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _app(seed: tuple[dict[str, object], ...] | None = None, **settings: object) -> FastAPI:
    """Construit l'application complète avec les clients de form_post."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=seed or (_CLIENT_JSON,),
            identity_seed_users=_IDENTITY_SEED,
            **settings,
        )
    )


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(
    client_id: str = "formpost-app",
    **extra: str,
) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation ``form_post`` valide (code + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-formpost",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
        "response_mode": "form_post",
    }
    params.update(extra)
    return params


def _form_action(body: str) -> str:
    """Extrait l'``action`` dé-échappée du formulaire de la page servie."""
    match = _FORM_TAG.search(body)
    assert match is not None, "aucun formulaire POST dans la page"
    return html.unescape(match.group(1))


def _form_inputs(body: str) -> dict[str, str]:
    """Extrait les champs cachés dé-échappés du formulaire de la page servie."""
    return {html.unescape(name): html.unescape(value) for name, value in _INPUT_TAG.findall(body)}


def _assert_form_post_page(response: Response, action: str = _REDIRECT_URI) -> dict[str, str]:
    """Contrôles communs d'une page ``form_post`` : statut, en-têtes, action nue.

    Retourne les champs du formulaire dé-échappés pour vérifications ciblées.
    """
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-cache, no-store"
    assert response.headers["pragma"] == "no-cache"
    assert "location" not in response.headers, "aucune redirection 302 en form_post"
    body = response.text
    assert _form_action(body) == action
    assert "document.forms[0].submit()" in body
    assert "<noscript>" in body
    return _form_inputs(body)


def _login(client: TestClient) -> None:
    """Établit une session utilisateur (``POST /login``) pour consentement."""
    response = client.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302


# ─────────────────────────────────────────────────────────────────────────────
# Transport de succès
# ─────────────────────────────────────────────────────────────────────────────


def test_authorize_success_renders_auto_submitted_form() -> None:
    """Le code flow + ``form_post`` rend une page 200 POSTant code, state et iss."""
    with TestClient(_app()) as client:
        response = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        inputs = _assert_form_post_page(response)

    assert inputs["code"]
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER
    assert "error" not in inputs


def test_form_post_escapes_param_values() -> None:
    """Les valeurs hostiles sont échappées ``html`` sans altération à la relecture."""
    hostile_state = "st\"&<&'1"
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(state=hostile_state),
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(response)

    assert "&quot;" in response.text
    assert "&lt;" in response.text
    assert inputs["state"] == hostile_state


def test_form_post_allowed_with_implicit_tokens() -> None:
    """``form_post`` reste valide avec ``id_token token`` (Form Post §4, jetons inclus)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(
                response_type="id_token token",
                nonce="nonce-165",
            ),
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(response)

    assert inputs["id_token"]
    assert inputs["access_token"]
    assert inputs["token_type"] == "Bearer"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER


# ─────────────────────────────────────────────────────────────────────────────
# Erreurs redirigeables dans le même transport
# ─────────────────────────────────────────────────────────────────────────────


def test_prompt_none_posts_login_required_with_iss() -> None:
    """``prompt=none`` sans session renvoie ``login_required`` dans le ``POST``."""
    with TestClient(_app(require_login=True)) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(prompt="none"),
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(response)

    assert inputs["error"] == "login_required"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER
    assert "code" not in inputs


def test_consent_deny_posts_access_denied() -> None:
    """Le refus du consentement part dans le ``POST`` avec ``iss`` (RFC 9207 §2)."""
    with TestClient(_app(seed=(_CONSENT_CLIENT_JSON,))) as client:
        _login(client)
        decision = client.post(
            "/consent",
            data={**_authorize_params(client_id="formpost-consent-app"), "action": "deny"},
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(decision)

    assert inputs["error"] == "access_denied"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER
    assert "code" not in inputs


def test_consent_approval_posts_issued_code() -> None:
    """L'approbation du consentement émet le code dans le ``POST`` de succès."""
    with TestClient(_app(seed=(_CONSENT_CLIENT_JSON,))) as client:
        _login(client)
        decision = client.post(
            "/consent",
            data={**_authorize_params(client_id="formpost-consent-app"), "action": "authorize"},
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(decision)

    assert inputs["code"]
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER
    assert "error" not in inputs


def test_unsupported_response_type_posts_error() -> None:
    """Un ``response_type`` non supporté part dans le même transport ``form_post``."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(response_type="foo"),
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(response)

    assert inputs["error"] == "unsupported_response_type"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER


def test_par_requirement_refusal_posts_invalid_request() -> None:
    """Le refus PAR du serveur voyage en ``form_post`` (mode résolu côté client)."""
    with TestClient(_app(par_required=True)) as client:
        response = client.get("/authorize", params=_authorize_params(), follow_redirects=False)
        inputs = _assert_form_post_page(response)

    assert inputs["error"] == "invalid_request"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER


# ─────────────────────────────────────────────────────────────────────────────
# CA 4 : response_type absent en form_post
# ─────────────────────────────────────────────────────────────────────────────


def test_missing_response_type_posts_invalid_request() -> None:
    """``response_type`` absent + ``form_post`` + callback sûr : refus dans le ``POST``."""
    params = {
        "client_id": "formpost-app",
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-missing",
        "response_mode": "form_post",
    }
    with TestClient(_app()) as client:
        response = client.get("/authorize", params=params, follow_redirects=False)
        inputs = _assert_form_post_page(response)

    assert inputs["error"] == "invalid_request"
    assert "response_type" in inputs["error_description"]
    assert inputs["state"] == "st-missing"
    assert inputs["iss"] == _ISSUER
    assert "code" not in inputs


def test_missing_response_type_without_form_post_keeps_error_page() -> None:
    """Sans ``response_mode=form_post``, l'absence de paramètre rend la page 400."""
    params = {
        "client_id": "formpost-app",
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-missing",
    }
    with TestClient(_app()) as client:
        response = client.get("/authorize", params=params, follow_redirects=False)

    assert response.status_code == 400
    assert "Paramètres requis manquants" in response.text


def test_missing_response_type_with_unregistered_redirect_keeps_error_page() -> None:
    """``form_post`` + callback non enregistré : jamais de redirection, page 400."""
    params = {
        "client_id": "formpost-app",
        "redirect_uri": "https://other.example/cb",
        "scope": "openid profile",
        "state": "st-missing",
        "response_mode": "form_post",
    }
    with TestClient(_app()) as client:
        response = client.get("/authorize", params=params, follow_redirects=False)

    assert response.status_code == 400
    assert "Paramètres requis manquants" in response.text


# ─────────────────────────────────────────────────────────────────────────────
# PAR et discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_par_round_trip_keeps_form_post() -> None:
    """Le ``response_mode`` poussé revient en ``POST`` après résolution du ``request_uri``."""
    with TestClient(_app(par_enabled=True)) as client:
        push = client.post("/par", data=_authorize_params())
        assert push.status_code == 201
        request_uri = push.json()["request_uri"]

        response = client.get(
            "/authorize",
            params={"client_id": "formpost-app", "request_uri": request_uri},
            follow_redirects=False,
        )
        inputs = _assert_form_post_page(response)

    assert inputs["code"]
    assert inputs["state"] == "st-formpost"


def test_consumed_par_reference_posts_invalid_request_uri() -> None:
    """L'erreur de résolution d'une référence consommée suit ``form_post``."""
    with TestClient(_app(par_enabled=True)) as client:
        push = client.post("/par", data=_authorize_params())
        assert push.status_code == 201
        request_uri = push.json()["request_uri"]
        authorize_params = {"client_id": "formpost-app", "request_uri": request_uri}
        first = client.get("/authorize", params=authorize_params, follow_redirects=False)
        _assert_form_post_page(first)

        second = client.get("/authorize", params=authorize_params, follow_redirects=False)
        inputs = _assert_form_post_page(second)

    assert inputs["error"] == "invalid_request_uri"
    assert inputs["state"] == "st-formpost"
    assert inputs["iss"] == _ISSUER


def test_discovery_publishes_form_post() -> None:
    """``response_modes_supported`` publie ``form_post`` (CA 3)."""
    with TestClient(_app()) as client:
        response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    assert "form_post" in response.json()["response_modes_supported"]


# ─────────────────────────────────────────────────────────────────────────────
# Délégation du transport
# ─────────────────────────────────────────────────────────────────────────────


def test_authorization_response_dispatches_on_response_mode() -> None:
    """``form_post`` rend la page 200 auto-soumise, ``query`` la redirection 302."""
    redirect = AuthorizeRedirect(
        redirect_uri=_REDIRECT_URI,
        code="c-165",
        state="st-165",
        response_mode=ResponseMode.FORM_POST,
        form_params={"code": "c-165"},
    )
    page = authorization_response(redirect)
    clear = authorization_response(
        AuthorizeRedirect(
            redirect_uri=_REDIRECT_URI + "?code=c-165",
            code="c-165",
            state="st-165",
            response_mode=ResponseMode.QUERY,
        )
    )

    assert isinstance(page, HTMLResponse)
    assert page.status_code == 200
    assert isinstance(clear, RedirectResponse)
    assert clear.status_code == 302
