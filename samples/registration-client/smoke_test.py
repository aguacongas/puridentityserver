r"""Test manuel de la Dynamic Client Registration (RFC 7591) et du client management (RFC 7592).

Smoke test du sample ``registration-client``.

Lance un serveur PurIdentityServer en sous-processus avec une
configuration **spécifique à ce test** (générée par ``smoke_common.py`` :
port 8104, registration activée avec un initial access token de démo —
aucun client seed : le client est créé dynamiquement), puis joue le
scénario :

1. le discovery annonce ``registration_endpoint`` (``/register``) ;
2. ``POST /register`` sans initial access token -> ``401 invalid_client`` ;
3. ``POST /register`` avec une redirect_uri invalide -> ``400 invalid_redirect_uri`` ;
4. ``POST /register`` profil CIBA (``grant_types`` sans flow de redirection)
   sans ``redirect_uris`` -> ``201`` (RFC 7591 §2 : ``redirect_uris`` omissible) ;
5. ``POST /register`` avec un initial access token -> ``201`` + ``Location``,
   ``client_id`` + ``client_secret`` + ``registration_access_token`` émis une seule fois ;
6. ``GET /register/{client_id}`` avec le registration access token -> ``200``
   (métadonnées, ni secret ni registration token dans la réponse) ;
7. flow OIDC complet avec le client **dynamique** : ``/authorize`` puis
   ``/token`` avec le secret émis à la registration -> ``200`` access_token ;
8. ``PUT /register/{client_id}`` avec un nouveau ``client_secret`` (rotation)
   -> ``200`` + nouveau secret, émis une seule fois ;
9. ``/token`` avec l'ancien secret -> ``400 invalid_client`` (rotation) ;
10. ``/token`` avec le nouveau secret -> ``200`` access_token ;
11. ``DELETE /register/{client_id}`` -> ``204`` ;
12. ``GET /register/{client_id}`` -> ``404`` (suppression effective) ;
13. discovery publie ``subject_types_supported`` = public, pairwise, ephemeral ;
14. deux clients pairwise (secteurs distincts) -> ``sub`` différentes, non corrélables ;
15. un même client pairwise -> ``sub`` stable entre deux sessions ;
16. ``/userinfo`` expose la même ``sub`` que l'``id_token`` ;
17. un client ephemeral -> ``sub`` jamais réutilisée entre deux sessions ;
18. un client public (défaut) -> ``sub`` réelle (non dérivée) ;
19. ``sector_identifier_uri`` incohérent -> ``400 invalid_client_metadata`` ;
20. le discovery annonce ``userinfo_signing_alg_values_supported`` = ``["RS256"]`` ;
21. ``POST /register`` avec ``userinfo_signed_response_alg=RS256`` -> ``201`` + écho
    (RFC 7591 §3.2) ;
22. ``userinfo_signed_response_alg=HS256`` (non publié) -> ``400 invalid_client_metadata`` ;
23. ``/userinfo`` de ce client -> ``application/jwt``, signature RS256 vérifiée sur
    le JWKS, claims ``iss`` / ``aud`` / ``sub`` (OIDC Core 1.0 §5.3.2) ;
24. un client sans la métadonnée -> ``/userinfo`` reste ``application/json`` non signé.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/registration-client/smoke_test.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8104
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

# même valeur que la configuration par défaut du serveur (config.toml) :
# le même token fonctionne sur le port 8000 et sur le serveur de test.
INITIAL_ACCESS_TOKEN = "dev-registrar-token"

# seed de dérivation des sub pairwise/ephemeral (OIDC Core 1.0 §8.1).
SUBJECT_PAIRWISE_SEED = "smoke-subject-seed-8104"

REGISTRATION_URL = f"{SERVER_URL}/register"

REDIRECT_URI = f"http://{HOST}:{SERVER_PORT}/callback"
POST_LOGOUT_URI = f"http://{HOST}:{SERVER_PORT}/post-logout"

_METADATA = {
    "redirect_uris": [REDIRECT_URI],
    "post_logout_redirect_uris": [POST_LOGOUT_URI],
    "scope": "openid profile email",
}

_HTTP_TIMEOUT = 10
_DEADLINE = 90


def _authorize(
    http: httpx.Client,
    *,
    client_id: str,
    scope: str = "openid profile email",
    redirect_uri: str = REDIRECT_URI,
) -> str:
    """Émet un code d'autorisation pour ``client_id`` (appel anonyme)."""
    response = http.get(
        f"{SERVER_URL}/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        },
    )
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def _exchange_code(
    http: httpx.Client,
    *,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str = REDIRECT_URI,
) -> httpx.Response:
    """Échange le code contre un access_token via ``/token``."""
    return http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )


def _register(
    http: httpx.Client,
    metadata: dict[str, object],
    *,
    initial_access_token: str = INITIAL_ACCESS_TOKEN,
) -> httpx.Response:
    """Appelle ``POST /register`` avec (ou sans) l'initial access token."""
    headers = {"authorization": f"Bearer {initial_access_token}"} if initial_access_token else {}
    return http.post(REGISTRATION_URL, json=metadata, headers=headers)


def _id_token_sub(
    http: httpx.Client, *, client_id: str, client_secret: str, scope: str, redirect_uri: str
) -> str:
    """Flow complet (authorize + token) et retourne la ``sub`` de l'id_token.

    La ``sub`` est dérivée selon le ``subject_type`` du client : publiée
    dans l'``id_token``, elle sert à vérifier la non-corrélabilité entre
    clients pairwise et l'unicité éphémère entre sessions.
    """
    code = _authorize(http, client_id=client_id, scope=scope, redirect_uri=redirect_uri)
    response = _exchange_code(
        http,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )
    assert response.status_code == 200, response.text
    id_token = response.json()["id_token"]
    return str(pyjwt.decode(id_token, options={"verify_signature": False})["sub"])


def _userinfo_sub(http: httpx.Client, access_token: str) -> str:
    """Appelle ``/userinfo`` et retourne la ``sub`` exposée au resource owner."""
    response = http.get(
        f"{SERVER_URL}/userinfo", headers={"authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, response.text
    return str(response.json()["sub"])


def _exchange_for_tokens(
    http: httpx.Client,
    *,
    client_id: str,
    client_secret: str,
    scope: str,
    redirect_uri: str,
) -> dict[str, object]:
    """Flow complet et retourne le corps ``/token`` (id_token, access_token)."""
    code = _authorize(http, client_id=client_id, scope=scope, redirect_uri=redirect_uri)
    response = _exchange_code(
        http,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _run_scenario() -> None:
    """Joue le scénario de registration dynamique (RFC 7591 + 7592) de bout en bout."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["registration_endpoint"] == f"{SERVER_URL}/register"
        print(f"  [1/12] discovery OK (registration_endpoint={metadata['registration_endpoint']})")

        response = _register(http, _METADATA, initial_access_token="")
        assert response.status_code == 401, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [2/12] POST /register sans initial access token -> 401 invalid_client OK")

        response = _register(http, {**_METADATA, "redirect_uris": ["javascript:alert(1)"]})
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_redirect_uri"
        print("  [3/12] redirect_uri invalide -> 400 invalid_redirect_uri OK")

        response = _register(
            http,
            {
                "grant_types": ["urn:openid:params:grant-type:ciba"],
                "response_types": [],
                "scope": "openid",
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["redirect_uris"] == []
        print("  [4/12] DCR sans redirect_uris (grant CIBA, RFC 7591 §2) -> 201 OK")

        response = _register(http, _METADATA)
        assert response.status_code == 201, response.text
        registration = response.json()
        client_id = registration["client_id"]
        client_secret = registration["client_secret"]
        registration_access_token = registration["registration_access_token"]
        registration_client_uri = registration["registration_client_uri"]
        assert client_id
        assert client_secret
        assert registration_access_token
        assert registration["token_endpoint_auth_method"] == "client_secret_basic"
        assert registration["grant_types"] == ["authorization_code"]
        assert registration["response_types"] == ["code"]
        assert registration["scope"] == "email openid profile"
        assert registration["redirect_uris"] == [REDIRECT_URI]
        assert registration["post_logout_redirect_uris"] == [POST_LOGOUT_URI]
        assert response.headers["location"] == registration_client_uri
        assert registration_client_uri == f"{REGISTRATION_URL}/{client_id}"
        print(
            f"  [5/12] POST /register -> 201 (client_id={client_id[:8]}..., "
            f"secret + registration_access_token émis une seule fois)"
        )

        auth = {
            "authorization": f"Bearer {registration_access_token}",
        }
        response = http.get(registration_client_uri, headers=auth)
        assert response.status_code == 200, response.text
        read = response.json()
        assert read["client_id"] == client_id
        assert "client_secret" not in read
        assert "registration_access_token" not in read
        print("  [6/12] GET /register/{{client_id}} -> 200 (ni secret ni token réémis) OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=client_secret)
        assert response.status_code == 200, response.text
        assert response.json()["token_type"] == "Bearer"
        assert response.json()["access_token"]
        print("  [7/12] flow OIDC complet via le client dynamique (secret de registration) OK")

        new_secret = "rotated-secret-8chars"
        response = http.put(
            registration_client_uri,
            json={**_METADATA, "client_secret": new_secret},
            headers=auth,
        )
        assert response.status_code == 200, response.text
        updated = response.json()
        assert updated["client_secret"] == new_secret
        assert updated["scope"] == "email openid profile"
        print("  [8/12] PUT /register/{{client_id}} (rotation du secret) -> 200 OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=client_secret)
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_client"
        print("  [9/12] ancien secret après rotation -> 400 invalid_client OK")

        code = _authorize(http, client_id=client_id)
        response = _exchange_code(http, code=code, client_id=client_id, client_secret=new_secret)
        assert response.status_code == 200, response.text
        assert response.json()["access_token"]
        print("  [10/12] nouveau secret (après rotation) -> 200 access_token OK")

        response = http.delete(registration_client_uri, headers=auth)
        assert response.status_code == 204, response.text
        assert response.content == b""
        print("  [11/12] DELETE /register/{{client_id}} -> 204 corps vide OK")

        response = http.get(registration_client_uri, headers=auth)
        assert response.status_code == 404, response.text
        print("  [12/12] GET /register/{{client_id}} après suppression -> 404 OK")

        _run_subject_types_scenario(http)
        _run_signed_userinfo_scenario(http)
    print()


def _run_subject_types_scenario(http: httpx.Client) -> None:
    """Vérifie les subject types pairwise / ephemeral (OIDC Core 1.0 §8.1, ESID §4).

    Scénario :
    1. discovery publie ``subject_types_supported`` = public, pairwise, ephemeral ;
    2. deux clients pairwise (secteurs distincts) -> ``sub`` différentes pour le
       même utilisateur, non corrélables entre elles ;
    3. un même client pairwise -> ``sub`` stable entre deux sessions ;
    4. ``/userinfo`` expose la même ``sub`` que l'``id_token`` ;
    5. un client ephemeral -> ``sub`` jamais réutilisée entre deux sessions ;
    6. un client public (défaut) -> ``sub`` réelle, non dérivée ;
    7. ``POST /register`` sans ``subject_pairwise_seed`` -> ``subject_type``
       rejeté ; avec le seed, ``pairwise`` accepté et ``sector_identifier_uri``
       vérifié par fetch (refus ``invalid_client_metadata`` si incohérent).
    """
    metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
    assert metadata["subject_types_supported"] == ["public", "pairwise", "ephemeral"]
    print("  [1/7] discovery subject_types_supported = public, pairwise, ephemeral OK")

    login = http.post(
        f"{SERVER_URL}/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
    )
    assert login.status_code == 302, login.text

    uri_a = f"https://sector-a.example/{SERVER_PORT}/callback"
    uri_b = f"https://sector-b.example/{SERVER_PORT}/callback"
    uri_e = f"https://ephemeral.example/{SERVER_PORT}/callback"
    pair_a = _register(
        http,
        {**_METADATA, "redirect_uris": [uri_a], "subject_type": "pairwise"},
    )
    assert pair_a.status_code == 201, pair_a.text
    pair_b = _register(
        http,
        {**_METADATA, "redirect_uris": [uri_b], "subject_type": "pairwise"},
    )
    assert pair_b.status_code == 201, pair_b.text
    ra, rb = pair_a.json(), pair_b.json()
    assert ra["subject_type"] == "pairwise"
    assert rb["subject_type"] == "pairwise"
    sub_a = _id_token_sub(
        http,
        client_id=ra["client_id"],
        client_secret=ra["client_secret"],
        scope="openid",
        redirect_uri=uri_a,
    )
    sub_b = _id_token_sub(
        http,
        client_id=rb["client_id"],
        client_secret=rb["client_secret"],
        scope="openid",
        redirect_uri=uri_b,
    )
    assert sub_a and sub_b and sub_a != sub_b, (sub_a, sub_b)
    assert sub_a != ra["client_id"] and sub_b != rb["client_id"]
    print("  [2/7] deux clients pairwise -> sub distinctes (secteurs différents) OK")

    sub_a2 = _id_token_sub(
        http,
        client_id=ra["client_id"],
        client_secret=ra["client_secret"],
        scope="openid",
        redirect_uri=uri_a,
    )
    assert sub_a2 == sub_a
    print("  [3/7] même client pairwise -> sub stable entre deux sessions OK")

    tokens = _exchange_for_tokens(
        http,
        client_id=ra["client_id"],
        client_secret=ra["client_secret"],
        scope="openid profile",
        redirect_uri=uri_a,
    )
    userinfo_sub = _userinfo_sub(http, str(tokens["access_token"]))
    assert userinfo_sub == sub_a, (userinfo_sub, sub_a)
    print("  [4/7] /userinfo expose la sub de l'id_token OK")

    eph = _register(
        http,
        {**_METADATA, "redirect_uris": [uri_e], "subject_type": "ephemeral"},
    )
    assert eph.status_code == 201, eph.text
    eph_json = eph.json()
    eph_sub_1 = _id_token_sub(
        http,
        client_id=eph_json["client_id"],
        client_secret=eph_json["client_secret"],
        scope="openid",
        redirect_uri=uri_e,
    )
    eph_sub_same = _id_token_sub(
        http,
        client_id=eph_json["client_id"],
        client_secret=eph_json["client_secret"],
        scope="openid",
        redirect_uri=uri_e,
    )
    assert eph_sub_1 and eph_sub_same == eph_sub_1, (eph_sub_1, eph_sub_same)

    login2 = http.post(
        f"{SERVER_URL}/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
    )
    assert login2.status_code == 302, login2.text
    eph_sub_2 = _id_token_sub(
        http,
        client_id=eph_json["client_id"],
        client_secret=eph_json["client_secret"],
        scope="openid",
        redirect_uri=uri_e,
    )
    assert eph_sub_2 != eph_sub_1, (eph_sub_1, eph_sub_2)
    print("  [5/7] client ephemeral -> sub constante en session, nouvelle jamais réutilisée OK")

    pub = _register(http, _METADATA)
    assert pub.status_code == 201, pub.text
    pub_json = pub.json()
    pub_sub = _id_token_sub(
        http,
        client_id=pub_json["client_id"],
        client_secret=pub_json["client_secret"],
        scope="openid profile email",
        redirect_uri=REDIRECT_URI,
    )
    assert pub_sub and pub_sub != sub_a and pub_sub != sub_b, pub_sub
    print("  [6/7] client public (défaut) -> sub réelle non dérivée OK")

    bad = _register(
        http,
        {
            **_METADATA,
            "redirect_uris": [f"https://sector-c.example/{SERVER_PORT}/callback"],
            "subject_type": "pairwise",
            "sector_identifier_uri": f"https://sector-c.example/{SERVER_PORT}/missing.json",
        },
    )
    assert bad.status_code == 400, bad.text
    assert bad.json()["error"] == "invalid_client_metadata"
    print("  [7/7] sector_identifier_uri incohérent -> 400 invalid_client_metadata OK")


def _run_signed_userinfo_scenario(http: httpx.Client) -> None:
    """Vérifie les réponses UserInfo signées RS256 (OIDC Core 1.0 §5.3.1, §5.3.2).

    1. le discovery annonce ``userinfo_signing_alg_values_supported=["RS256"]`` ;
    2. un client déclarant ``userinfo_signed_response_alg=RS256`` voit la
       métadonnée échoée à l'enregistrement (RFC 7591 §3.2) ;
    3. ``userinfo_signed_response_alg=HS256`` (non publié par l'OP) ->
       ``400 invalid_client_metadata`` ;
    4. ``/userinfo`` de ce client -> ``application/jwt``, signature RS256
       vérifiée contre le JWKS, claims ``iss`` / ``aud`` / ``sub`` (§5.3.2) ;
    5. un client sans la métadonnée -> ``/userinfo`` reste ``application/json``.
    """
    metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
    assert metadata["userinfo_signing_alg_values_supported"] == ["PS256", "ES256", "RS256"]
    print("  [1/5] discovery userinfo_signing_alg_values_supported = [PS256, ES256, RS256] OK")

    login = http.post(
        f"{SERVER_URL}/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
    )
    assert login.status_code == 302, login.text

    signed = _register(http, {**_METADATA, "userinfo_signed_response_alg": "RS256"})
    assert signed.status_code == 201, signed.text
    signed_json = signed.json()
    assert signed_json["userinfo_signed_response_alg"] == "RS256"
    signed_client_id = str(signed_json["client_id"])
    print("  [2/5] POST /register userinfo_signed_response_alg=RS256 -> 201 + écho OK")

    bad = _register(http, {**_METADATA, "userinfo_signed_response_alg": "HS256"})
    assert bad.status_code == 400, bad.text
    assert bad.json()["error"] == "invalid_client_metadata"
    print("  [3/5] userinfo_signed_response_alg=HS256 (non publié) -> 400 OK")

    tokens = _exchange_for_tokens(
        http,
        client_id=signed_client_id,
        client_secret=str(signed_json["client_secret"]),
        scope="openid profile",
        redirect_uri=REDIRECT_URI,
    )
    response = http.get(
        f"{SERVER_URL}/userinfo", headers={"authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/jwt")
    header = pyjwt.get_unverified_header(response.text)
    assert header["alg"] == "RS256"
    jwks = http.get(f"{SERVER_URL}/.well-known/jwks.json").json()
    jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
    claims = pyjwt.decode(
        response.text,
        RSAAlgorithm.from_jwk(json.dumps(jwk)),
        algorithms=["RS256"],
        audience=signed_client_id,
        issuer=str(metadata["issuer"]),
    )
    assert claims["sub"]
    print("  [4/5] /userinfo -> application/jwt RS256 vérifiée au JWKS (iss/aud/sub) OK")

    plain = _register(http, _METADATA)
    assert plain.status_code == 201, plain.text
    plain_json = plain.json()
    assert "userinfo_signed_response_alg" not in plain_json
    tokens = _exchange_for_tokens(
        http,
        client_id=str(plain_json["client_id"]),
        client_secret=str(plain_json["client_secret"]),
        scope="openid profile",
        redirect_uri=REDIRECT_URI,
    )
    response = http.get(
        f"{SERVER_URL}/userinfo", headers={"authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["sub"]
    print("  [5/5] client sans métadonnée -> /userinfo reste application/json OK")


def main() -> None:
    """Lance le serveur de test (config spécifique), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(),
            users={"alice": {"email": "alice@example.com", "password": "password"}},
            users_seed={"alice": {"name": "Alice Martin"}},
            registration_enabled=True,
            registration_initial_access_tokens=(INITIAL_ACCESS_TOKEN,),
            extra_settings={"subject_pairwise_seed": SUBJECT_PAIRWISE_SEED},
        ),
    ):
        print(f"\nScénario de registration dynamique (deadline={_DEADLINE}s)...")
        _run_scenario()
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
