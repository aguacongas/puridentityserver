r"""Test manuel de la migration OpenID 2.0 vers OpenID Connect (spec finale).

Smoke test du sample ``openid20-migration-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8124, un
client demanding le scope ``openid2``, la **migration OpenID 2.0 activée**)
puis joue le scénario de la spec « OpenID 2.0 to OpenID Connect Migration
1.0 » :

1. ``checkid_setup`` : le RP ouvre une authentification OpenID 2.0, l'agent
   utilisateur est redirigé vers la page de connexion de l'OP ;
2. connexion puis ``/openid20/continue`` : le RP reçoit le fragment de
   réponse OpenID 2.0 (``openid.assoc_handle`` et ``openid.claimed_id``) ;
3. ``check_authentication`` : le RP obtient l'assertion OpenID 2.0 de
   l'utilisateur (``claimed_id``) ;
4. flux OpenID Connect avec ``scope=openid openid2`` et ``openid2_realm`` :
   l'``id_token`` porte le claim ``openid2_id`` (spec §4) ;
5. vérification d'autorité (spec §6) : un ``GET`` sur l'identifiant OpenID
   2.0 avec ``Accept: application/json`` renvoie le même ``iss`` que
   l'``id_token`` ;
6. export des associations : l'API d'administration liste l'identifiant
   migré du compte.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/openid20-migration-client/smoke_test.py
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

SERVER_PORT = 8124
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-openid20-client"
REDIRECT_URI = f"{SERVER_URL}/callback"

#: Realm du RP OpenID 2.0 : préfixe de l'URI de redirection enregistrée du
#: client (l'OP vérifie le realm, spec §3 / OpenID 2.0 §9.2).
REALM = SERVER_URL

#: URL de retour du RP OpenID 2.0 (fragment de réponse 2.0).
RETURN_TO = f"{SERVER_URL}/rp-callback"

ADMIN_CLIENT_ID = "sample-openid20-admin"
ADMIN_CLIENT_SECRET = "sample-openid20-admin-secret"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid openid2",
    "client_type": "public",
}

_ADMIN_CLIENT = {
    "client_id": ADMIN_CLIENT_ID,
    "client_secret": ADMIN_CLIENT_SECRET,
    "scopes": "openid",
    "client_type": "confidential",
}

_USERS = {"alice": {"email": "alice@example.com", "password": "password"}}

#: Réglages serveur du test : la migration OpenID 2.0 est **activée** (le
#: support est désactivé par défaut) et l'API d'administration est branchée
#: sur le claim ``client_id``.
_EXTRA_SETTINGS = {
    "jwks_key_size": 2048,
    "openid20_migration_enabled": True,
    "admin_required_claim": "client_id",
    "admin_required_claim_values": [ADMIN_CLIENT_ID],
}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _id_token(http: httpx.Client) -> str:
    """Login + authorize (scope ``openid2``) + token : renvoie l'``id_token``."""
    verifier = "openid20-verifier-0123456789"
    response = http.post(
        f"{SERVER_URL}/login",
        data={
            "username": "alice@example.com",
            "password": "password",
            "next": f"{SERVER_URL}/authorize",
        },
    )
    assert response.status_code == 302, response.text
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid openid2",
            "state": "st-openid20",
            "nonce": "n-openid20-0123456789",
            "code_challenge": _s256_challenge(verifier),
            "code_challenge_method": "S256",
            "openid2_realm": REALM,
        },
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


def _admin_token(http: httpx.Client) -> str:
    """Access token d'administration (client seed, grant client_credentials)."""
    response = http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": ADMIN_CLIENT_ID,
            "client_secret": ADMIN_CLIENT_SECRET,
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def _run_scenario() -> None:
    """Joue le scénario de migration OpenID 2.0 vers OpenID Connect."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        setup = http.get(
            f"{SERVER_URL}/openid20/checkid_setup",
            params={
                "openid.ns": SERVER_URL,
                "openid.mode": "id_2",
                "openid.realm": REALM,
                "openid.return_to": RETURN_TO,
            },
        )
        assert setup.status_code == 302, setup.text
        print("  [1/6] checkid_setup : l'agent utilisateur est redirigé vers /login")

        login = http.post(
            f"{SERVER_URL}/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": parse_qs(urlparse(setup.headers["location"]).query)["next"][0],
            },
        )
        assert login.status_code == 302, login.text
        continued = http.get(f"{SERVER_URL}{login.headers['location']}")
        assert continued.status_code == 302, continued.text
        fragment = parse_qs(urlparse(continued.headers["location"]).fragment)
        handle = fragment["openid.assoc_handle"][0]
        claimed_id = fragment["openid.claimed_id"][0]
        print(f"  [2/6] fragment OpenID 2.0 reçu (claimed_id={claimed_id})")

        assertion = http.get(
            f"{SERVER_URL}/openid20/check_authentication",
            params={"checkid_handle": handle},
        )
        assert assertion.status_code == 200, assertion.text
        assert f"claimed_id:{claimed_id}" in assertion.text
        print("  [3/6] check_authentication : l'assertion OpenID 2.0 est valide")

        id_token = _id_token(http)
        claims = pyjwt.decode(id_token, options={"verify_signature": False})
        assert claims.get("openid2_id") == claimed_id, claims
        print("  [4/6] id_token : le claim openid2_id porte l'identifiant 2.0")

        authority = http.get(claimed_id, headers={"Accept": "application/json"})
        assert authority.status_code == 200, authority.text
        assert authority.json()["iss"] == claims["iss"], authority.text
        print("  [5/6] autorité vérifiée (spec §6) : iss identique à l'id_token")

        token = _admin_token(http)
        exported = http.get(
            f"{SERVER_URL}/openid20-identifiers",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert exported.status_code == 200, exported.text
        identifiers = exported.json()
        assert [item["identifier"] for item in identifiers] == [claimed_id], identifiers
        print("  [6/6] export d'administration : l'identifiant migré est listé")


def main() -> int:
    """Lance le serveur de test puis joue le scénario."""
    started = time.perf_counter()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(_CLIENT, _ADMIN_CLIENT),
            users=_USERS,
            extra_settings=_EXTRA_SETTINGS,
        ),
    ):
        _run_scenario()
    elapsed = time.perf_counter() - started
    print(f"\n=== SCENARIO OK en {elapsed:.1f}s ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
