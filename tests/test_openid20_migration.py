"""Tests de la migration OpenID 2.0 vers OpenID Connect (spec finale).

La spec « OpenID 2.0 to OpenID Connect Migration 1.0 » permet à un RP
OpenID 2.0 de relier l'identifiant historique d'un utilisateur à son `sub`
OpenID Connect : le RP demande le scope `openid2`, l'OP renvoie alors
l'identifiant OpenID 2.0 dans le claim `openid2_id` de l'ID Token.

Le support est désactivé par défaut : sans le drapeau
``openid20_migration_enabled``, le scope est refusé, aucune route OpenID 2.0
n'est exposée et aucun claim n'est émis.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from urllib.parse import parse_qs, unquote, urlparse

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.openid20_migration import OpenID20MigrationUseCase
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.openid20 import OPENID20_ID_CLAIM
from puridentityserver.infrastructure.persistence.memory.openid20_identifiers import (
    InMemoryOpenID20IdentifierRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

#: Realm des RP de test : préfixe des URI de redirection enregistrées.
_REALM = "https://app.example"

_CLIENT = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid openid2",
    "client_type": "confidential",
}

_ADMIN_CLIENT = {
    "client_id": "admin-app",
    "client_secret": "admin-secret",
    "scopes": "openid admin",
    "client_type": "confidential",
}

_ADMIN_API = {"name": "management", "scopes": ["admin"]}

_SEED_USER = {"alice": {"email": "alice@example.com", "password": "password"}}


def _app(*, enabled: bool) -> FastAPI:
    """Application de test, support de la migration activé ou non."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT, _ADMIN_CLIENT),
            api_resources_seed=(_ADMIN_API,),
            identity_seed_users=_SEED_USER,
            openid20_migration_enabled=enabled,
        )
    )


def _s256_challenge(verifier: str) -> str:
    """Challenge PKCE S256 du verifier donné (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _login(client: TestClient) -> None:
    """Authentifie l'utilisateur de test (session cookie)."""
    response = client.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def _code(client: TestClient, *, realm: str = "") -> str:
    """Lance une demande d'autorisation et renvoie le code émis."""
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "web-app",
            "redirect_uri": "https://app.example/callback",
            "scope": "openid openid2",
            "nonce": "n-0S6_WzA2Mj",
            "code_challenge": _s256_challenge("verifier-verifier"),
            "openid2_realm": realm,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert "code" in query, query
    return str(query["code"][0])


def _id_token(client: TestClient, code: str) -> dict[str, object]:
    """Échange le code contre des jetons et renvoie les claims de l'ID Token."""
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/callback",
            "client_id": "web-app",
            "client_secret": "super-secret",
            "code_verifier": "verifier-verifier",
        },
    )
    assert response.status_code == 200, response.text
    token = str(response.json()["id_token"])
    claims = pyjwt.decode(token, options={"verify_signature": False})
    return dict(claims)


def _admin_token(client: TestClient) -> str:
    """Access token d'administration (grant client_credentials)."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "admin-app",
            "client_secret": "admin-secret",
            "scope": "admin",
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


def test_migration_use_case_is_disabled_by_default() -> None:
    """Sans activation, aucune association n'est enregistrée ni restituée."""
    usecase = OpenID20MigrationUseCase(InMemoryOpenID20IdentifierRepository())

    assert not usecase.enabled
    asyncio.run(usecase.link("subject-1", "https://openid2.example.com/user-1"))
    assert asyncio.run(usecase.identifier_for("subject-1")) == ""
    assert asyncio.run(usecase.all_identifiers()) == []


def test_migration_use_case_links_and_returns_the_identifier() -> None:
    """L'association enregistrée est restituée pour le même compte et realm."""
    repository = InMemoryOpenID20IdentifierRepository()
    usecase = OpenID20MigrationUseCase(repository, enabled=True)

    asyncio.run(usecase.link("subject-1", "https://openid2.example.com/user-1", "realm-1"))

    assert asyncio.run(usecase.identifier_for("subject-1", "realm-1")) == (
        "https://openid2.example.com/user-1"
    )
    # Le realm doit correspondre (spec §2, §3).
    assert asyncio.run(usecase.identifier_for("subject-1", "realm-2")) == ""
    assert len(asyncio.run(usecase.all_identifiers())) == 1


def test_scope_registry_accepts_openid2_only_when_enabled() -> None:
    """Le scope `openid2` n'est connu que si le support est activé."""
    without = ScopeRegistry()
    with_scope = ScopeRegistry(extra_scopes=frozenset({Scope.OPENID20}))

    assert asyncio.run(without.unknown_scopes(frozenset({Scope.OPENID20}))) == ("openid2",)
    assert asyncio.run(with_scope.unknown_scopes(frozenset({Scope.OPENID20}))) == ()


def test_scope_openid2_is_refused_when_the_support_is_disabled() -> None:
    """Drapeau OFF : le scope `openid2` est traité comme inconnu."""
    with TestClient(_app(enabled=False)) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid openid2",
                "nonce": "n-0S6_WzA2Mj",
                "code_challenge": _s256_challenge("verifier-verifier"),
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_scope"]


def test_scope_openid2_is_accepted_when_the_support_is_enabled() -> None:
    """Drapeau ON : le scope est accepté et le claim est omis sans association."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        claims = _id_token(client, _code(client))

    assert claims["iss"] == _ISSUER
    assert OPENID20_ID_CLAIM not in claims


def test_openid2_id_claim_carries_the_linked_identifier() -> None:
    """Avec une association, l'ID Token porte le claim `openid2_id` (spec §4)."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        claims = _id_token(client, _code(client))
        subject = str(claims["sub"])
        token = _admin_token(client)

        linked = client.post(
            "/openid20-identifiers",
            json={
                "subject": subject,
                "identifier": "https://openid2.example.com/user-1",
                "realm": "",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert linked.status_code == 201, linked.text

        claims = _id_token(client, _code(client))

    assert claims[OPENID20_ID_CLAIM] == "https://openid2.example.com/user-1"


def test_openid2_realm_selects_the_association() -> None:
    """Le `openid2_realm` demandé sélectionne l'association (spec §2)."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        claims = _id_token(client, _code(client))
        subject = str(claims["sub"])
        token = _admin_token(client)
        linked = client.post(
            "/openid20-identifiers",
            json={
                "subject": subject,
                "identifier": "https://openid2.example.com/u",
                "realm": _REALM,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert linked.status_code == 201, linked.text

        claims = _id_token(client, _code(client, realm=_REALM))

    assert claims[OPENID20_ID_CLAIM] == "https://openid2.example.com/u"


def test_openid2_realm_must_match_a_registered_redirect_uri() -> None:
    """Un realm hors des URI enregistrées est refusé (spec §3, OpenID 2.0 §9.2)."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid openid2",
                "nonce": "n-0S6_WzA2Mj",
                "code_challenge": _s256_challenge("verifier-verifier"),
                "openid2_realm": "https://autre.example",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["invalid_request"]


def test_openid2_realm_survives_the_par_flow() -> None:
    """Le `openid2_realm` est porté par la requête poussée (RFC 9126)."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        claims = _id_token(client, _code(client))
        subject = str(claims["sub"])
        token = _admin_token(client)
        linked = client.post(
            "/openid20-identifiers",
            json={
                "subject": subject,
                "identifier": "https://openid2.example.com/u",
                "realm": _REALM,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert linked.status_code == 201, linked.text

        pushed = client.post(
            "/par",
            data={
                "response_type": "code",
                "client_id": "web-app",
                "client_secret": "super-secret",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid openid2",
                "state": "st-par",
                "nonce": "n-0S6_WzA2Mj",
                "code_challenge": _s256_challenge("verifier-verifier"),
                "openid2_realm": _REALM,
            },
        )
        assert pushed.status_code == 201, pushed.text

        response = client.get(
            "/authorize",
            params={
                "client_id": "web-app",
                "request_uri": str(pushed.json()["request_uri"]),
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, response.text
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        claims = _id_token(client, code)

    assert claims[OPENID20_ID_CLAIM] == "https://openid2.example.com/u"


def test_admin_routes_are_absent_when_the_support_is_disabled() -> None:
    """Drapeau OFF : aucune route d'administration n'est exposée (404)."""
    with TestClient(_app(enabled=False)) as client:
        response = client.get("/openid20-identifiers")

    assert response.status_code == 404


def test_admin_routes_require_an_admin_token() -> None:
    """La consultation des associations exige le jeton d'administration."""
    with TestClient(_app(enabled=True)) as client:
        anonymous = client.get("/openid20-identifiers")
        assert anonymous.status_code == 401

        token = _admin_token(client)
        allowed = client.get("/openid20-identifiers", headers={"Authorization": f"Bearer {token}"})
        assert allowed.status_code == 200
        assert allowed.json() == []


def test_openid20_flow_returns_the_assertion_and_the_claim() -> None:
    """Parcours complet : setup 2.0, assertion, claim `openid2_id`, autorité."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        setup = client.get(
            "/openid20/checkid_setup",
            params={
                "openid.ns": "https://rp.example",
                "openid.mode": "id_2",
                "openid.realm": _REALM,
                "openid.return_to": "https://app.example/rp-callback",
            },
            follow_redirects=False,
        )
        assert setup.status_code == 302, setup.text
        next_url = parse_qs(urlparse(setup.headers["location"]).query)["next"][0]

        login = client.post(
            "/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": next_url,
            },
            follow_redirects=False,
        )
        assert login.status_code == 302, login.text

        continued = client.get(login.headers["location"], follow_redirects=False)
        assert continued.status_code == 302, continued.text
        location = continued.headers["location"]
        assert location.startswith("https://app.example/rp-callback#")
        fragment = parse_qs(urlparse(location).fragment)
        handle = fragment["openid.assoc_handle"][0]
        claimed_id = fragment["openid.claimed_id"][0]

        assertion = client.get("/openid20/check_authentication", params={"checkid_handle": handle})
        assert assertion.status_code == 200, assertion.text
        assert f"claimed_id:{claimed_id}" in assertion.text

        claims = _id_token(client, _code(client, realm=_REALM))
        assert claims[OPENID20_ID_CLAIM] == claimed_id

        authority = client.get(
            claimed_id.replace("https://id.example", ""),
            headers={"Accept": "application/json"},
        )
        assert authority.status_code == 200, authority.text
        assert authority.json() == {"iss": _ISSUER}


def test_openid20_check_authentication_refuses_an_invalid_handle() -> None:
    """Un handle falsifié ou expiré ne rend aucune assertion."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get("/openid20/check_authentication", params={"checkid_handle": "forge"})

    assert response.status_code == 400
    assert "error:invalid_request" in response.text


def test_openid20_routes_are_absent_when_the_support_is_disabled() -> None:
    """Drapeau OFF : aucune route OpenID 2.0 n'est exposée (404)."""
    with TestClient(_app(enabled=False)) as client:
        assert client.get("/openid20/checkid_setup").status_code == 404
        assert client.get("/openid20/check_authentication").status_code == 404
        assert client.get("/openid20/id/inconnu").status_code == 404


def test_openid20_authority_endpoint_rejects_an_unknown_identifier() -> None:
    """Un identifiant inconnu ne vaut pas preuve d'autorité."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get("/openid20/id/inconnu")

    assert response.status_code == 404


def test_openid20_setup_refuses_a_return_url_outside_the_realm() -> None:
    """L'URI de retour doit être sous le realm (OpenID 2.0 §9.2)."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get(
            "/openid20/checkid_setup",
            params={
                "openid.ns": "https://rp.example",
                "openid.mode": "id_2",
                "openid.realm": _REALM,
                "openid.return_to": "https://autre.example/cb",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "error:invalid_request" in response.text


def test_openid20_setup_requires_the_return_url() -> None:
    """``openid.return_to`` est obligatoire (OpenID 2.0 §3.1)."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get("/openid20/checkid_setup", follow_redirects=False)

    assert response.status_code == 400


@pytest.mark.parametrize("realm", ["", _REALM])
def test_openid20_continue_requires_an_authenticated_user(realm: str) -> None:
    """Sans session, la fin de flux renvoie vers la page de connexion."""
    with TestClient(_app(enabled=True)) as client:
        setup = client.get(
            "/openid20/checkid_setup",
            params={
                "openid.ns": "https://rp.example",
                "openid.realm": realm,
                "openid.return_to": "https://app.example/rp-callback",
            },
            follow_redirects=False,
        )
        state = parse_qs(urlparse(setup.headers["location"]).query)["next"][0]
        response = client.get(state, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")


def test_openid20_state_cannot_be_forged() -> None:
    """Un état falsifié est refusé (signature de l'OP)."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get(
            "/openid20/continue", params={"state": "forge"}, follow_redirects=False
        )

    assert response.status_code == 400
    assert "error:invalid_request" in response.text


def test_openid20_claim_uses_the_associated_identifier() -> None:
    """Le claim reprend l'identifiant associé, pas l'identifiant revendiqué."""
    with TestClient(_app(enabled=True)) as client:
        _login(client)
        token = _admin_token(client)
        claims = _id_token(client, _code(client))
        linked = client.post(
            "/openid20-identifiers",
            json={
                "subject": str(claims["sub"]),
                "identifier": "https://openid2.example.com/u",
                "realm": "",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert linked.status_code == 201, linked.text

        exported = client.get("/openid20-identifiers", headers={"Authorization": f"Bearer {token}"})
        assert exported.status_code == 200
        assert exported.json() == [
            {
                "subject": str(claims["sub"]),
                "identifier": "https://openid2.example.com/u",
                "realm": "",
                "created_at": exported.json()[0]["created_at"],
            }
        ]
        assert unquote(exported.json()[0]["identifier"]) == "https://openid2.example.com/u"
