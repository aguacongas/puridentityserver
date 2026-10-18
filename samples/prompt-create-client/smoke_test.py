r"""Test manuel du prompt=create (Initiating User Registration via OIDC 1.0).

Smoke test du sample ``prompt-create-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8123,
client seed public ``sample-prompt-create-client``) et joue le flow
d'autorisation demandant la création d'un compte à la volée. Aucun serveur
RP n'est nécessaire : la redirection sortante est lue côté ``Location``
(flow query, PKCE). Scénario :

1. discovery publie ``create`` dans ``prompt_values_supported`` ;
2. ``/authorize`` + ``prompt=create`` (sans session) -> **302** vers la page
   d'inscription ``/signup`` (pas de redirection d'erreur, spec §2) ;
3. ``GET /signup`` -> formulaire email / mot de passe + lien d'annulation
   (``register=cancelled``) ;
4. ``POST /signup`` (nouveau compte) -> session fraîche, retour sur la
   demande -> **302** callback avec ``code`` ; l'``id_token`` échangé porte
   le ``sub`` (UUID) du compte créé et ``/userinfo`` le confirme ;
5. ``prompt=create none`` -> ``login_required`` redirigeable (spec §3) ;
6. création refusée (email déjà inscrit) -> ``access_denied`` redirigeable ;
7. annulation via le lien de la page -> ``access_denied`` redirigeable.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/prompt-create-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import httpx
import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8123
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-prompt-create-client"
REDIRECT_URI = f"http://{HOST}:8124/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENTS = (
    {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "scopes": "openid profile email",
        "client_type": "public",
    },
)


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_params(*, state: str, verifier: str, **extra: str) -> dict[str, str]:
    """Paramètres d'une demande d'autorisation valide (code + PKCE)."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
    }
    params.update(extra)
    return params


def _callback_query(location: str) -> dict[str, str]:
    """Paramètres portés par la query de la redirection callback."""
    parsed = urlparse(location)
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "http",
        parsed.netloc,
        "/callback",
    ), location
    return {name: values[0] for name, values in parse_qs(parsed.query).items()}


def _run_scenario() -> None:
    """Joue le scénario prompt=create (création de compte dans le flow)."""
    verifier = "promptcreate-verifier-0123456789"
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        values = metadata["prompt_values_supported"]
        assert "create" in values, sorted(metadata)
        print(f"  [1/7] discovery OK (prompt_values_supported={values})")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state="st-create", verifier=verifier, prompt="create"),
        )
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert location.startswith("/signup?next="), location
        next_target = unquote(parse_qs(urlparse(location).query)["next"][0])
        assert "prompt=create" in next_target
        print("  [2/7] prompt=create sans session -> 302 vers la page /signup OK")

        page = http.get(f"{SERVER_URL}{location}")
        assert page.status_code == 200, page.text
        assert 'action="/signup"' in page.text
        assert 'name="email"' in page.text
        assert 'name="password"' in page.text
        assert "register=cancelled" in page.text
        print("  [3/7] GET /signup -> formulaire email/mot de passe + annulation OK")

        signup = http.post(
            f"{SERVER_URL}/signup",
            data={
                "email": "carol@example.com",
                "password": "motdepasse123",
                "next": next_target,
            },
        )
        assert signup.status_code == 302, signup.text
        assert signup.headers["location"] == next_target, signup.headers["location"]

        replay = http.get(signup.headers["location"])
        assert replay.status_code == 302, replay.text
        received = _callback_query(replay.headers["location"])
        assert received["code"], sorted(received)
        assert received["state"] == "st-create"
        assert "error" not in received

        token = http.post(
            f"{SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": received["code"],
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200, token.text
        body = token.json()
        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        subject = str(uuid.UUID(claims["sub"]))

        userinfo = http.get(
            f"{SERVER_URL}/userinfo",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert userinfo.status_code == 200, userinfo.text
        assert userinfo.json()["sub"] == subject
        print(f"  [4/7] POST /signup (carol) -> code + id_token au sub={subject} + userinfo OK")

        response = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state="st-none", verifier=verifier, prompt="create none"),
        )
        assert response.status_code == 302, response.text
        received = _callback_query(response.headers["location"])
        assert received["error"] == "login_required", sorted(received)
        assert received["state"] == "st-none"
        print("  [5/7] prompt=create none -> login_required redirigeable (spec §3) OK")

        start = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state="st-exists", verifier=verifier, prompt="create"),
        )
        next_target = unquote(parse_qs(urlparse(start.headers["location"]).query)["next"][0])
        refused = http.post(
            f"{SERVER_URL}/signup",
            data={
                "email": "carol@example.com",
                "password": "motdepasse123",
                "next": next_target,
            },
        )
        assert refused.status_code == 302, refused.text
        assert "register=refused" in refused.headers["location"]
        denied = http.get(refused.headers["location"])
        assert denied.status_code == 302, denied.text
        received = _callback_query(denied.headers["location"])
        assert received["error"] == "access_denied", sorted(received)
        assert received["state"] == "st-exists"
        print("  [6/7] création refusée (email existant) -> access_denied redirigeable OK")

        start = http.get(
            f"{SERVER_URL}/authorize",
            params=_authorize_params(state="st-cancel", verifier=verifier, prompt="create"),
        )
        next_target = unquote(parse_qs(urlparse(start.headers["location"]).query)["next"][0])
        cancelled = http.get(
            f"{SERVER_URL}/authorize",
            params=dict(
                {name: values[0] for name, values in parse_qs(urlparse(next_target).query).items()},
                register="cancelled",
            ),
        )
        assert cancelled.status_code == 302, cancelled.text
        received = _callback_query(cancelled.headers["location"])
        assert received["error"] == "access_denied", sorted(received)
        assert received["state"] == "st-cancel"
        print("  [7/7] annulation (register=cancelled) -> access_denied redirigeable OK")
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis tout termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=_CLIENTS,
        ),
    ):
        print(
            f"\nScénario prompt=create (Initiating User Registration via OIDC 1.0) "
            f"(deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
