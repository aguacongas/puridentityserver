"""Tests de la garde same-origin des formulaires HTML (issue #184).

``SameOriginFormGuardMiddleware`` refuse (403) les POST cross-site vers
``/login``, ``/signup``, ``/consent`` et ``/device`` : ``Sec-Fetch-Site``
en priorité (allow-liste ``same-origin`` / ``none``), ``Origin`` en repli
(normalisé et comparé à l'origin publique de la requête), en-têtes
absents = passage (clients machine, ``TestClient``, suite de
conformité). Les en-têtes ``X-Forwarded-*`` ne sont crus qu'avec
``trust_proxy_headers`` ; les GET ne sont jamais vérifiés.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.same_origin import _normalized_origin
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_FORMS: dict[str, dict[str, str]] = {
    "/login": {"username": "dave@example.com", "password": "Motdepasse123!", "next": "/"},
    "/signup": {"email": "csrf@example.com", "password": "court", "next": "/"},
    "/consent": {"action": "deny"},
    "/device": {"user_code": "ABCD-EFGH"},
}

_FORWARDED = {
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "id.example",
}


def _app(*, trust_proxy_headers: bool = False) -> FastAPI:
    """Application de test minimal montant les quatre formulaires HTML."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            trust_proxy_headers=trust_proxy_headers,
        )
    )


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """Client de test partagé (connexion directe, proxy non cru)."""
    with TestClient(_app()) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def proxy_client() -> Iterator[TestClient]:
    """Client de test derrière un proxy de confiance (``X-Forwarded-*``)."""
    with TestClient(_app(trust_proxy_headers=True)) as test_client:
        yield test_client


@pytest.mark.parametrize("path", sorted(_FORMS))
def test_cross_site_post_is_rejected(client: TestClient, path: str) -> None:
    """``Sec-Fetch-Site: cross-site`` → 403 sur les quatre formulaires."""
    response = client.post(path, data=_FORMS[path], headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert "protection CSRF" in response.text


def test_same_site_post_is_rejected(client: TestClient) -> None:
    """``same-site`` (sous-domaine voisin) est refusé : aucun initiateur légitime."""
    response = client.post("/login", data=_FORMS["/login"], headers={"Sec-Fetch-Site": "same-site"})
    assert response.status_code == 403


def test_unknown_sec_fetch_value_is_rejected(client: TestClient) -> None:
    """Valeur inconnue de ``Sec-Fetch-Site`` → refuse (fail-closed)."""
    response = client.post("/login", data=_FORMS["/login"], headers={"Sec-Fetch-Site": "nawak"})
    assert response.status_code == 403


def test_sec_fetch_wins_over_matching_origin(client: TestClient) -> None:
    """``Sec-Fetch-Site`` présent : il prime sur un ``Origin`` apparemment conforme."""
    response = client.post(
        "/login",
        data=_FORMS["/login"],
        headers={"Sec-Fetch-Site": "cross-site", "Origin": "http://testserver"},
    )
    assert response.status_code == 403


def test_divergent_origin_is_rejected(client: TestClient) -> None:
    """Sans ``Sec-Fetch-Site``, un ``Origin`` divergent est refusé."""
    response = client.post(
        "/login", data=_FORMS["/login"], headers={"Origin": "https://evil.example"}
    )
    assert response.status_code == 403


def test_null_origin_is_rejected(client: TestClient) -> None:
    """``Origin: null`` (contexte sandboxé) n'est pas une origine digne de confiance."""
    response = client.post("/login", data=_FORMS["/login"], headers={"Origin": "null"})
    assert response.status_code == 403


@pytest.mark.parametrize("site", ("same-origin", "none"))
def test_accepted_sec_fetch_site_passes(client: TestClient, site: str) -> None:
    """``same-origin`` et ``none`` (navigation utilisateur) traversent le garde."""
    response = client.post(
        "/login",
        data=_FORMS["/login"],
        headers={"Sec-Fetch-Site": site},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login")


def test_matching_origin_passes_without_sec_fetch(client: TestClient) -> None:
    """Repli ``Origin`` : origine conforme (hors ``Sec-Fetch``) → traitement normal."""
    response = client.post(
        "/login",
        data=_FORMS["/login"],
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_no_navigation_headers_pass(client: TestClient) -> None:
    """Aucun en-tête de navigation (``curl``, ``TestClient``) → laissé passer."""
    for path, data in _FORMS.items():
        assert client.post(path, data=data).status_code != 403


def test_signup_form_passes_when_same_origin(client: TestClient) -> None:
    """``/signup`` conforme → refus inline du handler (mot de passe faible), pas 403."""
    response = client.post(
        "/signup",
        data=_FORMS["/signup"],
        headers={"Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("/signup")


def test_device_form_redirects_to_login_when_same_origin(client: TestClient) -> None:
    """``/device`` conforme → le handler sans session redirige vers ``/login``."""
    response = client.post(
        "/device",
        data=_FORMS["/device"],
        headers={"Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login")


def test_get_is_not_checked(client: TestClient) -> None:
    """Seuls les POST sont vérifiés : un GET ``cross-site`` rend la page (200)."""
    response = client.get("/login", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200


def test_forwarded_origin_is_trusted_with_flag(proxy_client: TestClient) -> None:
    """Avec ``trust_proxy_headers``, l'origin publique suit ``X-Forwarded-*``."""
    response = proxy_client.post(
        "/login",
        data=_FORMS["/login"],
        headers={**_FORWARDED, "Origin": "https://id.example"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_forwarded_divergent_origin_is_rejected(proxy_client: TestClient) -> None:
    """Même derrière proxy, une origine divergente reste refusée."""
    response = proxy_client.post(
        "/login",
        data=_FORMS["/login"],
        headers={**_FORWARDED, "Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_forwarded_headers_ignored_without_trust(client: TestClient) -> None:
    """Sans ``trust_proxy_headers``, les en-têtes proxy sont forgeables : ignorés."""
    response = client.post(
        "/login",
        data=_FORMS["/login"],
        headers={**_FORWARDED, "Origin": "https://id.example"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("url", "expected"),
    (
        ("https://id.example:443/callback", "https://id.example"),
        ("http://id.example:80", "http://id.example"),
        ("HTTPS://ID.Example", "https://id.example"),
        ("https://id.example:8443", "https://id.example:8443"),
        ("null", "null"),
        ("", ""),
    ),
)
def test_origin_normalization(url: str, expected: str) -> None:
    """Normalisation d'origine : minuscules, port par défaut écarté, path ignoré."""
    assert _normalized_origin(url) == expected
