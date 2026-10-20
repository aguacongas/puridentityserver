r"""Test manuel de la rotation des clés de signature (OIDC Core 1.0 §10.1).

Smoke test du sample ``key-rotation-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8122, une
paire de clés RSA 2048, une **rotation proactive** d'une seconde) puis joue
le scénario :

1. le discovery annonce le ``jwks_uri`` ;
2. premier relevé du JWKS : la clé de signature courante ;
3. login + ``/authorize`` + ``/token`` : un ``id_token`` est signé par la clé
   courante ;
4. après la période de rotation, second relevé du JWKS : une **nouvelle** clé
   de signature est publiée et l'ancienne est **conservée** (transition en
   douceur, OIDC Core 1.0 §10.1) ;
5. l'``id_token`` obtenu avant la rotation reste vérifiable avec le JWKS
   publié ;
6. troisième relevé : le magasin de clés reste borné (les clés retirées au
  -delà de la rétention sont purgées).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/key-rotation-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8122
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-key-rotation-client"
REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"

#: Période de rotation proactive des clés de signature (secondes) : assez
#: courte pour observer la rotation pendant le test.
ROTATION_SECONDS = 1.0

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "public",
}

#: Client d'administration de la demonstration : il obtient un access token
#: (grant client_credentials) dont le claim ``client_id`` satisfait la regle
#: d'autorisation de l'API d'administration.
_ADMIN_CLIENT = {
    "client_id": "sample-key-rotation-admin",
    "client_secret": "sample-admin-secret",
    "scopes": "openid",
    "client_type": "confidential",
}

_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}

#: Réglages serveur du test : une rotation proactive courte - la rotation est
#: déclenchée par la publication du JWKS (OIDC Core 1.0 §10.1) - et
#: l'API d'administration branchee sur le claim ``client_id``.
_EXTRA_SETTINGS = {
    "jwks_key_size": 2048,
    "jwks_rotation_seconds": ROTATION_SECONDS,
    "jwks_rotation_algorithms": ["RS256"],
    "jwks_retained_keys": 1,
    "admin_required_claim": "client_id",
    "admin_required_claim_values": ["sample-key-rotation-admin"],
}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _jwks(http: httpx.Client) -> list[dict[str, str]]:
    """Relève le JWKS publié par l'OP."""
    response = http.get(f"{SERVER_URL}/.well-known/jwks.json")
    assert response.status_code == 200, response.text
    keys: list[dict[str, str]] = response.json()["keys"]
    return keys


def _id_token(http: httpx.Client) -> str:
    """Login + authorize + token : renvoie l'``id_token`` signé par l'OP."""
    verifier = "rotation-verifier-0123456789"
    response = http.post(
        f"{SERVER_URL}/login",
        data={
            "username": "alice@example.com",
            "password": "password",
            "next": f"{SERVER_URL}/authorize",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile",
            "state": "st-rotation",
            "nonce": "n-rotation-0123456789",
            "code_challenge": _s256_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    response = http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["id_token"])


def _verifiable(id_token: str, keys: list[dict[str, str]]) -> bool:
    """Indique si l'``id_token`` est vérifiable avec le JWKS publié."""
    for key in keys:
        try:
            public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(key)
        except (ValueError, TypeError):
            continue
        try:
            pyjwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=CLIENT_ID,
                options={"verify_exp": False},
            )
        except pyjwt.PyJWTError:
            continue
        return True
    return False


def _admin_token(http: httpx.Client) -> str:
    """Access token d'administration (client seed, grant client_credentials)."""
    response = http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "sample-key-rotation-admin",
            "client_secret": "sample-admin-secret",
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def _run_scenario() -> None:
    """Joue le scénario de rotation des clés de signature."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["jwks_uri"].endswith("/.well-known/jwks.json")
        print(f"  [1/7] discovery OK (jwks_uri={metadata['jwks_uri']})")

        before = _jwks(http)
        assert before
        print(f"  [2/7] premier relevé du JWKS : {len(before)} clé(s) publiée(s)")

        id_token = _id_token(http)
        print("  [3/7] id_token obtenu (signé par la clé de signature courante)")

        time.sleep(ROTATION_SECONDS + 0.2)
        after = _jwks(http)
        before_kids = {key["kid"] for key in before}
        after_kids = {key["kid"] for key in after}
        assert after_kids - before_kids, "aucune nouvelle clé de signature publiée"
        assert before_kids & after_kids, "l'ancienne clé de signature a disparu du JWKS"
        print(
            "  [4/7] rotation : nouvelle clé publiée, ancienne clé conservée (OIDC Core 1.0 §10.1)"
        )

        assert _verifiable(id_token, after), "l'id_token n'est plus vérifiable"
        print("  [5/7] l'id_token signé avant la rotation reste vérifiable")

        time.sleep(ROTATION_SECONDS + 0.2)
        final = _jwks(http)
        assert len(final) <= len(after), "le JWKS croît sans borne"
        print(f"  [6/7] le JWKS reste borné ({len(final)} clé(s) publiée(s))")

        token = _admin_token(http)
        response = http.post(
            f"{SERVER_URL}/signing-keys/rotate",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, response.text
        rotated = response.json()["rotated"]
        assert rotated, "aucune clé pivotée"
        on_demand = _jwks(http)
        on_demand_kids = {key["kid"] for key in on_demand}
        final_kids = {key["kid"] for key in final}
        assert on_demand_kids - final_kids, "la rotation à la demande n'a rien changé"
        assert final_kids & on_demand_kids, "l'ancienne clé a disparu du JWKS"
        print(
            "  [7/7] rotation à la demande (POST /signing-keys/rotate) : "
            f"{len(rotated)} clé(s) pivotée(s), ancienne conservée"
        )
    print()


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(_CLIENT, _ADMIN_CLIENT),
            users=_USERS,
            jwks_algorithms=("RS256",),
            extra_settings=_EXTRA_SETTINGS,
        ),
    ):
        print(
            "\nScénario rotation des clés de signature (OIDC Core 1.0 §10.1) "
            f"(deadline={_DEADLINE}s)..."
        )
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
