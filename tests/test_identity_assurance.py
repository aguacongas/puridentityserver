"""Tests de l'identité assurance (OpenID Identity Assurance 1.0).

La spec « OpenID Identity Assurance Schema Definition 1.0 » (version finale)
définit le claim ``verified_claims`` : un conteneur portant les claims vérifiés
d'un utilisateur et les métadonnées du processus de vérification.

L'OP rend ce membre **sur demande** (paramètre OIDC ``claims`` §5.5) et
**seulement** dans la localisation demandée (``id_token`` ou ``userinfo``).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Coroutine
from typing import Any, TypeVar
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.claims_request import parse_claims_parameter
from puridentityserver.application.identity_assurance import (
    VERIFIED_CLAIMS_MEMBER,
    IdentityAssuranceUseCase,
    verified_claims_request,
)
from puridentityserver.domain.identity_assurance import (
    VerifiedClaimsError,
    parse_verified_claims,
    parse_verified_claims_request,
)
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

_SEED_USER = {"alice": {"email": "alice@example.com", "password": "password"}}

#: Profil `verified_claims` conforme au schéma de la spec.
_VERIFIED_CLAIMS: dict[str, Any] = {
    "verification": {
        "trust_framework": "de_aml",
        "assurance_level": "substantial",
        "evidence": [
            {
                "type": "document",
                "check_details": [{"check_method": "pvp"}],
                "document_details": {"type": "de_erp_replacement_idcard"},
            }
        ],
    },
    "claims": {"given_name": "Alice", "family_name": "Martin"},
}


def run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    """Exécute une coroutine de façon synchrone (pattern du dépôt)."""
    return asyncio.run(awaitable)


def _app(*, with_verified_claims: bool = True) -> FastAPI:
    """Application de test, avec ou sans profil `verified_claims`."""
    users_seed: dict[str, dict[str, object]] = {
        "alice": {
            "name": "Alice Martin",
            "given_name": "Alice",
            "family_name": "Martin",
            "email": "alice.martin@example.com",
        }
    }
    if with_verified_claims:
        users_seed["alice"]["verified_claims"] = _VERIFIED_CLAIMS
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT,),
            users_seed=users_seed,
            identity_seed_users=_SEED_USER,
        )
    )


def _usecase(claims: dict[str, object] | None) -> IdentityAssuranceUseCase:
    """Cas d'usage d'identité assurance adossé à un profil utilisateur."""
    users = InMemoryUserRepository()
    run(users.save(UserClaims(subject="subject-1", claims=claims or {})))
    return IdentityAssuranceUseCase(UserStoreClaimsProvider(users), users)


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


def _claims_parameter(location: str, member: object) -> str:
    """Paramètre `claims` JSON demandant un membre `verified_claims`."""
    return json.dumps({location: {VERIFIED_CLAIMS_MEMBER: member}})


def _flow(
    client: TestClient, claims_parameter: str, *, want_userinfo: bool = False
) -> tuple[dict[str, object], dict[str, object]]:
    """Flux code complet : renvoie les claims de l'id_token et du userinfo."""
    _login(client)
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "web-app",
            "redirect_uri": "https://app.example/callback",
            "scope": "openid profile",
            "nonce": "n-0S6_WzA2Mj",
            "code_challenge": _s256_challenge("verifier-verifier"),
            "claims": claims_parameter,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token = client.post(
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
    assert token.status_code == 200, token.text
    id_token_claims = pyjwt.decode(
        str(token.json()["id_token"]), options={"verify_signature": False}
    )
    userinfo: dict[str, object] = {}
    if want_userinfo:
        info = client.get(
            "/userinfo", headers={"Authorization": f"Bearer {token.json()['access_token']}"}
        )
        assert info.status_code == 200, info.text
        userinfo = dict(info.json())
    return dict(id_token_claims), userinfo


def test_parse_verified_claims_requires_the_schema_members() -> None:
    """`verification` et `claims` sont obligatoires (spec §5.2)."""
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims({"verification": {"trust_framework": "de_aml"}})
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims({"claims": {}})


def test_parse_verified_claims_requires_a_trust_framework() -> None:
    """`trust_framework` est une chaîne non vide (spec §5.4.2.3.1)."""
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims({"verification": {}, "claims": {}})
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims({"verification": {"trust_framework": ""}, "claims": {}})


def test_parse_verified_claims_rejects_unknown_members() -> None:
    """Les membres hors schéma sont rejetés (le profil est stocké, pas jeté)."""
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims(
            {"verification": {"trust_framework": "de_aml"}, "claims": {}, "extra": 1}
        )
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims(
            {"verification": {"trust_framework": "de_aml", "inconnu": 1}, "claims": {}}
        )


def test_parse_verified_claims_rejects_an_unknown_evidence_type() -> None:
    """Le type d'evidence doit appartenir à l'énumération de la spec."""
    with pytest.raises(VerifiedClaimsError):
        parse_verified_claims(
            {
                "verification": {
                    "trust_framework": "de_aml",
                    "evidence": [{"type": "inconnu"}],
                },
                "claims": {},
            }
        )


def test_parse_verified_claims_accepts_a_conformant_profile() -> None:
    """Un profil conforme est converti et expose ses métadonnées."""
    profile = parse_verified_claims(_VERIFIED_CLAIMS)

    assert profile.trust_framework == "de_aml"
    assert profile.assurance_level == "substantial"
    assert profile.claim_names == ("family_name", "given_name")
    assert profile.evidence_types == ("document",)
    assert profile.document_types == ("de_erp_replacement_idcard",)
    assert profile.check_methods == ("pvp",)
    assert profile.to_payload()["verification"]["trust_framework"] == "de_aml"


def test_parse_verified_claims_request_keeps_the_constraints() -> None:
    """La demande conserve les contraintes de la spec (value/values/essential)."""
    request = parse_verified_claims_request(
        {
            "verification": {"trust_framework": {"value": "de_aml"}},
            "claims": {
                "given_name": None,
                "family_name": {"essential": True},
                "birthdate": {"value": "1990-04-12"},
            },
        }
    )

    assert request.trust_framework == "de_aml"
    assert request.claim_names == ("given_name", "family_name", "birthdate")
    assert request.claim_values == {"birthdate": "1990-04-12"}
    assert request.essential_claims == frozenset({"family_name"})
    assert request.accepts_trust_framework("de_aml")
    assert not request.accepts_trust_framework("eidas")


def test_resolve_returns_the_requested_claims_only() -> None:
    """Seuls les claims demandés sont rendus (spec §5.3)."""
    usecase = _usecase({"verified_claims": _VERIFIED_CLAIMS})

    resolved = run(
        usecase.resolve(
            parse_verified_claims_request({"claims": {"given_name": None}}), "subject-1"
        )
    )

    assert resolved is not None
    assert resolved["claims"] == {"given_name": "Alice"}
    assert resolved["verification"]["trust_framework"] == "de_aml"


def test_resolve_omits_a_claim_whose_value_is_not_satisfied() -> None:
    """Un claim demandé avec une `value` non satisfaite est omis (IA-5.7.4)."""
    usecase = _usecase({"verified_claims": _VERIFIED_CLAIMS})

    resolved = run(
        usecase.resolve(
            parse_verified_claims_request({"claims": {"given_name": {"value": "Bob"}}}),
            "subject-1",
        )
    )

    assert resolved is not None
    assert resolved["claims"] == {}


def test_resolve_omits_the_whole_member_on_a_framework_mismatch() -> None:
    """Un `trust_framework` non satisfait conduit à l'omission complète."""
    usecase = _usecase({"verified_claims": _VERIFIED_CLAIMS})

    resolved = run(
        usecase.resolve(
            parse_verified_claims_request(
                {"verification": {"trust_framework": {"value": "eidas"}}}
            ),
            "subject-1",
        )
    )

    assert resolved is None


def test_resolve_without_profile_returns_nothing() -> None:
    """Sans profil vérifié, le membre n'est jamais rendu."""
    usecase = _usecase({})

    assert run(usecase.resolve(parse_verified_claims_request(None), "subject-1")) is None


def test_metadata_is_derived_from_the_known_profiles() -> None:
    """La metadata eKYC décrit les profils vérifiés connus."""
    usecase = _usecase({"verified_claims": _VERIFIED_CLAIMS})

    metadata = run(usecase.metadata())

    assert metadata["trust_frameworks_supported"] == ("de_aml",)
    assert metadata["claims_in_verified_claims_supported"] == ("family_name", "given_name")
    assert metadata["evidence_supported"] == ("document",)
    assert metadata["documents_supported"] == ("de_erp_replacement_idcard",)
    assert metadata["documents_check_methods_supported"] == ("pvp",)


def test_discovery_publishes_the_ekyc_metadata() -> None:
    """Le discovery publie la metadata eKYC (elle est dérivée des profils)."""
    with TestClient(_app()) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    assert "de_aml" in metadata["trust_frameworks_supported"]
    assert "given_name" in metadata["claims_in_verified_claims_supported"]
    assert "document" in metadata["evidence_supported"]
    assert "de_erp_replacement_idcard" in metadata["documents_supported"]
    assert "pvp" in metadata["documents_check_methods_supported"]


def test_metadata_is_empty_without_any_verified_profile() -> None:
    """Sans profil vérifié, l'OP n'expose aucune capacité eKYC."""
    usecase = _usecase({})

    metadata = run(usecase.metadata())

    assert all(values == () for values in metadata.values())


def test_verified_claims_are_rendered_in_the_id_token() -> None:
    """Le membre `verified_claims` est rendu dans l'id_token sur demande."""
    with TestClient(_app()) as client:
        id_token_claims, _ = _flow(
            client, _claims_parameter("id_token", {"claims": {"given_name": None}})
        )

    rendered = id_token_claims[VERIFIED_CLAIMS_MEMBER]
    assert rendered["verification"]["trust_framework"] == "de_aml"
    assert rendered["claims"] == {"given_name": "Alice"}


def test_verified_claims_are_not_rendered_without_a_request() -> None:
    """Sans demande, le membre `verified_claims` est absent de l'id_token."""
    with TestClient(_app()) as client:
        id_token_claims, _ = _flow(client, json.dumps({"id_token": {"email": None}}))

    assert VERIFIED_CLAIMS_MEMBER not in id_token_claims


def test_verified_claims_are_rendered_in_the_userinfo() -> None:
    """Le membre `verified_claims` est rendu dans le userinfo sur demande."""
    with TestClient(_app()) as client:
        _, userinfo = _flow(
            client,
            _claims_parameter("userinfo", {"claims": {"given_name": None}}),
            want_userinfo=True,
        )

    assert userinfo[VERIFIED_CLAIMS_MEMBER]["claims"] == {"given_name": "Alice"}


def test_verified_claims_are_absent_from_the_userinfo_when_requested_in_id_token() -> None:
    """La localisation demandée fait foi : rien ne fuit dans l'autre."""
    with TestClient(_app()) as client:
        id_token_claims, userinfo = _flow(
            client,
            _claims_parameter("id_token", {"claims": {"given_name": None}}),
            want_userinfo=True,
        )

    assert VERIFIED_CLAIMS_MEMBER in id_token_claims
    assert VERIFIED_CLAIMS_MEMBER not in userinfo


def test_verified_claims_are_absent_from_the_id_token_when_requested_in_userinfo() -> None:
    """La localisation demandée fait foi, dans les deux sens."""
    with TestClient(_app()) as client:
        id_token_claims, userinfo = _flow(
            client,
            _claims_parameter("userinfo", {"claims": {"given_name": None}}),
            want_userinfo=True,
        )

    assert VERIFIED_CLAIMS_MEMBER not in id_token_claims
    assert VERIFIED_CLAIMS_MEMBER in userinfo


def test_verified_claims_request_is_kept_out_of_the_userinfo_payload() -> None:
    """Le profil brut n'est jamais servi : seule la version résolue l'est."""
    with TestClient(_app()) as client:
        id_token_claims, userinfo = _flow(
            client,
            _claims_parameter("id_token", {"claims": {"family_name": None, "given_name": None}}),
            want_userinfo=True,
        )

    assert id_token_claims[VERIFIED_CLAIMS_MEMBER]["claims"] == {
        "family_name": "Martin",
        "given_name": "Alice",
    }
    assert VERIFIED_CLAIMS_MEMBER not in userinfo


def test_verified_claims_request_helper_reads_the_raw_member() -> None:
    """Le helper lit le member `verified_claims` d'une localisation."""
    request = parse_claims_parameter(
        _claims_parameter("id_token", {"claims": {"given_name": None}})
    )
    assert request is not None

    id_token_request = verified_claims_request(request, "id_token")
    assert id_token_request is not None
    assert id_token_request.claim_names == ("given_name",)
    # Absent de la localisation userinfo : rien ne doit y être rendu.
    assert verified_claims_request(request, "userinfo") is None
