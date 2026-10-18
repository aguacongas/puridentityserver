"""Tests du prompt=create (Initiating User Registration via OIDC 1.0, issue #166).

- ``prompt=create`` sans session redirige vers la page d'inscription ``/signup``
  (pas de redirection d'erreur) ; le compte créé ouvre une session fraîche et
  la demande rejouée émet un code dont l'``id_token`` porte le ``sub`` du
  nouvel utilisateur (spec §2) ;
- ``create`` + ``none`` renvoie ``login_required`` redirigeable (spec §3) ;
- création refusée (email existant, politique de mot de passe) ou annulée via
  le lien de la page → ``access_denied`` redirigeable avec ``state`` réfléchi ;
- utilisateur déjà connecté + ``prompt=create`` → page d'inscription (création
  directe, comportement §2 documenté) ;
- discovery publie ``prompt_values_supported`` (CA 4, convention non mandate) ;
- le marqueur ``register=`` est ignoré sans ``prompt=create`` (paramètre
  inconnu, RFC 6749 §3.1) ; aller-retour PAR conservé.
"""

import base64
import hashlib
import uuid
from urllib.parse import parse_qs, unquote, urlparse

import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"

_CLIENT_JSON: dict[str, object] = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile email",
    "client_type": "confidential",
}

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}


def _app(**settings: object) -> FastAPI:
    """Construit l'application complète (client ``web-app`` + compte ``alice``)."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT_JSON,),
            identity_seed_users=_IDENTITY_SEED,
            **settings,
        )
    )


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(**extra: str) -> dict[str, str]:
    """Paramètres d'une demande valide (Authorization Code + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": "web-app",
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile email",
        "state": "st-create",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
    }
    params.update(extra)
    return params


def _redirect_query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(location).query)


def _signup_next(location: str) -> str:
    """Extrait le ``next`` (URL d'autorisation complète) d'une redirection /signup."""
    return unquote(_redirect_query(location)["next"][0])


def _replay(client: TestClient, target: str) -> str:
    """Rejoue une URL absolue d'autorisation en chemin relatif (cookie conservé)."""
    parsed = urlparse(target)
    response = client.get(f"{parsed.path}?{parsed.query}", follow_redirects=False)
    assert response.status_code == 302, response.text
    return response.headers["location"]


def test_prompt_create_redirects_anonymous_to_signup_page() -> None:
    """CA 1 : sans session, ``prompt=create`` ouvre la page d'inscription (pas d'erreur)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("/signup?next=")
    next_target = _signup_next(location)
    assert next_target.startswith(f"{_ISSUER}/authorize?")
    assert "prompt=create" in next_target
    assert "state=st-create" in next_target


def test_signup_page_renders_form_and_cancel_link() -> None:
    """Le formulaire expose email / mot de passe, le ``next`` et le lien d'annulation."""
    next_target = f"{_ISSUER}/authorize?prompt=create&state=st-create"
    with TestClient(_app()) as client:
        page = client.get("/signup", params={"next": next_target})

    assert page.status_code == 200
    assert 'action="/signup"' in page.text
    assert 'name="email"' in page.text
    assert 'name="password"' in page.text
    escaped_next = "https://id.example/authorize?prompt=create&amp;state=st-create"
    assert f'value="{escaped_next}"' in page.text
    assert "register=cancelled" in page.text


def test_signup_completes_flow_with_new_subject() -> None:
    """CA 1 : compte créé -> session fraîche -> code -> id_token au nouveau ``sub``."""
    verifier = "verifier-verifier"
    with TestClient(_app()) as client:
        start = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )
        assert start.status_code == 302
        next_target = _signup_next(start.headers["location"])

        signup = client.post(
            "/signup",
            data={
                "email": "carol@example.com",
                "password": "motdepasse123",
                "next": next_target,
            },
            follow_redirects=False,
        )
        assert signup.status_code == 302, signup.text
        assert signup.headers["location"] == next_target

        location = _replay(client, next_target)
        assert location.startswith(f"{_REDIRECT_URI}?")
        query = _redirect_query(location)
        assert query["state"] == ["st-create"]
        assert "error" not in query

        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": _REDIRECT_URI,
                "client_id": "web-app",
                "client_secret": "super-secret",
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200, token.text
        body = token.json()
        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        assert str(uuid.UUID(claims["sub"])) == claims["sub"], "sub du nouvel utilisateur (UUID)"

        userinfo = client.get(
            "/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
        )
        assert userinfo.status_code == 200, userinfo.text
        assert userinfo.json()["sub"] == claims["sub"]


def test_prompt_create_none_returns_login_required() -> None:
    """Spec §3 : ``create`` + ``none`` -> ``login_required`` redirigeable avec ``state``."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(prompt="create none"),
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["login_required"]
    assert query["state"] == ["st-create"]


def test_prompt_create_login_redirects_to_signup() -> None:
    """``create`` + ``login`` : la création fonde l'authentification -> formulaire."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(prompt="create login"),
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/signup?next=")


def test_signup_with_existing_email_returns_access_denied() -> None:
    """CA 3 : email déjà inscrit -> ``access_denied`` redirigeable (transport résolu)."""
    with TestClient(_app()) as client:
        start = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )
        next_target = _signup_next(start.headers["location"])

        refused = client.post(
            "/signup",
            data={
                "email": "alice@example.com",
                "password": "motdepasse123",
                "next": next_target,
            },
            follow_redirects=False,
        )
        assert refused.status_code == 302
        assert _redirect_query(refused.headers["location"])["register"] == ["refused"]

        location = _replay(client, refused.headers["location"])
        query = _redirect_query(location)
        assert query["error"] == ["access_denied"]
        assert query["state"] == ["st-create"]


def test_signup_with_weak_password_returns_access_denied() -> None:
    """CA 3 : politique de mot de passe serveur (8 caractères min.) -> refus."""
    with TestClient(_app()) as client:
        start = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )
        next_target = _signup_next(start.headers["location"])

        refused = client.post(
            "/signup",
            data={"email": "dave@example.com", "password": "court", "next": next_target},
            follow_redirects=False,
        )
        assert refused.status_code == 302
        assert _redirect_query(refused.headers["location"])["register"] == ["refused"]

        location = _replay(client, refused.headers["location"])
        assert _redirect_query(location)["error"] == ["access_denied"]


def test_signup_cancel_returns_access_denied() -> None:
    """CA 3 : le lien « Refuser l'inscription » émet ``access_denied`` redirigeable."""
    with TestClient(_app()) as client:
        start = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )
        next_target = _signup_next(start.headers["location"])
        cancel = f"{next_target}&register=cancelled"

        location = _replay(client, cancel)
        query = _redirect_query(location)
        assert query["error"] == ["access_denied"]
        assert query["state"] == ["st-create"]


def test_connected_user_prompt_create_shows_signup_page() -> None:
    """§2 : un utilisateur déjà connecté est conduit à la création directe d'un compte."""
    with TestClient(_app()) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302

        response = client.get(
            "/authorize", params=_authorize_params(prompt="create"), follow_redirects=False
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/signup?next=")


def test_register_marker_ignored_without_prompt_create() -> None:
    """Le marqueur ``register=`` est un paramètre inconnu sans ``prompt=create``."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params=_authorize_params(register="cancelled"),
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{_REDIRECT_URI}?")
    assert _redirect_query(location)["state"] == ["st-create"]
    assert "error" not in _redirect_query(location)


def test_par_round_trip_keeps_prompt_create() -> None:
    """Le ``prompt=create`` poussé revient après résolution du ``request_uri``."""
    with TestClient(_app(par_enabled=True)) as client:
        push = client.post(
            "/par",
            data={**_authorize_params(prompt="create"), "client_secret": "super-secret"},
        )
        assert push.status_code == 201, push.text
        request_uri = push.json()["request_uri"]

        response = client.get(
            "/authorize",
            params={"client_id": "web-app", "request_uri": request_uri},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/signup?next=")
    assert "request_uri=" in unquote(response.headers["location"])


def test_discovery_publishes_prompt_values_supported() -> None:
    """CA 4 : discovery publie ``prompt_values_supported`` avec ``create``."""
    with TestClient(_app()) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    values = metadata["prompt_values_supported"]
    assert "create" in values, values
    assert {"none", "login", "consent"} <= set(values), values
