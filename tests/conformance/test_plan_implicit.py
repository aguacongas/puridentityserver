"""Rejeu local des modules du plan Implicit (issue #71).

``oidcc-implicit-certification-test-plan`` (release-v5.2.4) : 31 classes de
modules rejouées en ``response_type=id_token`` puis ``id_token token`` (58
exécutions dans la suite). Tout le callback arrive en **fragment**
(RFC 6749 §4.2.2.1), ``nonce`` est obligatoire et ``at_hash`` accompagne
l'access_token (OIDC Core 1.0 §3.3.2.1).

Les checks sont ceux de ``checks.py`` (extraits des fichiers Java de la
suite) ; les modules dont l'observable est identique au plan Basic
(``oidcc-response-type-missing``, les 3 ``request``/``request_uri``) restent
rejoués par ``test_plan_basic.py`` — voir ``TRACEABILITY.md``.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

import pytest
from checks import (
    check_acr_claim,
    check_at_hash,
    check_scope_claims_in_id_token,
    check_scope_claims_returned,
    check_second_auth_time_is_later,
    check_second_id_token_consistent,
    check_userinfo_response,
    expect_authorization_error,
    expect_id_token_signature,
    expect_implicit_callback,
    expect_redirect_uri_error_page,
    expect_second_login_page,
    validate_id_token,
)
from harness import (
    ConformanceHarness,
    FlowResult,
    decode_id_token_claims,
    decode_id_token_header,
)

_ISSUER = "https://id.example"
_CLIENT_ID = "web-app"

# Variantes ``ResponseType`` du plan (``OIDCCImplicitTestPlan``).
_IMPLICIT_TYPES = ("id_token", "id_token token")
# La suite ne rappelle le userinfo que quand un access_token existe
# (commentaires du plan : « 3 x userinfo tests aren't applicable for
# response_type=id_token »).
_TOKEN_TYPE = "id_token token"

# Erreurs exigées par ``CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface``.
_PROMPT_NONE_ERRORS = (
    "login_required",
    "interaction_required",
    "account_selection_required",
    "consent_required",
)

# Modules dont le seul check FAILURE est « ce paramètre ne casse pas le flux ».
# ``acr_values=1 2`` + ``scope=openid`` sont repris des logs de certification
# (OIDCC-3.1.2.1 / OIDCC-5.5) ; le member ``claims`` passe en ``id_token``
# quand ``response_type`` vaut exactement ``id_token`` (OIDCCClaimsEssential).
_PARAMETER_MODULES: tuple[tuple[str, dict[str, str]], ...] = (
    ("oidcc-display-page", {"display": "page"}),
    ("oidcc-display-popup", {"display": "popup"}),
    ("oidcc-login-hint", {"login_hint": "alice@example.com"}),
    ("oidcc-ui-locales", {"ui_locales": "fr"}),
    ("oidcc-claims-locales", {"claims_locales": "se"}),
    ("oidcc-ensure-request-with-unknown-parameter-succeeds", {"extra": "foobar"}),
    ("oidcc-ensure-request-with-acr-values-succeeds", {"acr_values": "1 2", "scope": "openid"}),
    (
        "oidcc-claims-essential",
        {
            "claims": json.dumps({"userinfo": {"name": {"essential": True}}}),
            "scope": "openid",
        },
    ),
)

_SCOPE_MODULES: tuple[tuple[str, str], ...] = (
    ("oidcc-scope-profile", "openid profile"),
    ("oidcc-scope-email", "openid email"),
    ("oidcc-scope-address", "openid address"),
    ("oidcc-scope-phone", "openid phone"),
    ("oidcc-scope-all", "openid profile email address phone"),
)

_USERINFO_MODULES: tuple[tuple[str, str], ...] = (
    ("oidcc-userinfo-get", "get"),
    ("oidcc-userinfo-post-header", "post_header"),
    ("oidcc-userinfo-post-body", "post_body"),
)

# Modules en double autorisation (``AbstractOIDCCSameAuthTwiceServerTest``).
_DOUBLE_AUTH_MODULES = (
    "oidcc-prompt-none-logged-in",
    "oidcc-id-token-hint",
    "oidcc-max-age-10000",
)


def _params(harness: ConformanceHarness, response_type: str, **extra: str) -> dict[str, str]:
    """Paramètres d'une demande implicite : pas de PKCE (inutile sans code)."""
    params = {
        "response_type": response_type,
        "client_id": harness._client_id,
        "redirect_uri": harness._redirect_uri,
        "scope": "openid profile",
        "state": secrets.token_urlsafe(8),
        "nonce": secrets.token_urlsafe(8),
    }
    params.update(extra)
    return params


def _implicit_flow(
    harness: ConformanceHarness, response_type: str, **extra: str
) -> tuple[dict[str, str], FlowResult, dict[str, Any]]:
    """Parcours implicite heureux : callback fragment + id_token validé."""
    params = _params(harness, response_type, **extra)
    result = harness.run_flow(**params)
    with_token = "token" in response_type.split()
    expect_implicit_callback(result, params["state"], with_token=with_token)
    claims = decode_id_token_claims(result.id_token)
    validate_id_token(claims, issuer=_ISSUER, client_id=_CLIENT_ID, nonce=params["nonce"])
    return params, result, claims


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_happy_flow(harness: ConformanceHarness, response_type: str) -> None:
    """``oidcc-server`` en implicite : callback fragment + id_token (+ at_hash).

    ``OIDCCServerTest`` : ``CheckMatchingCallbackParameters``,
    ``CheckStateInAuthorizationResponse``, ``ExtractIdTokenFromAuthorizationResponse``,
    ``PerformStandardIdTokenChecks`` ; ``ExtractAtHash``/``ValidateAtHash`` quand
    ``token`` figure dans le ``response_type``. L'instance
    ``oidcc-idtoken-signature`` partage la même passe (``EnsureIdTokenContainsKid``
    + ``EnsureIdTokenSignatureIsRS256``).
    """
    _params_used, result, claims = _implicit_flow(harness, response_type)
    expect_id_token_signature(decode_id_token_header(result.id_token))
    if "token" in response_type.split():
        check_at_hash(claims, result.access_token)
    else:
        assert "at_hash" not in claims, (
            f"at_hash ne doit pas figurer sans access_token : {sorted(claims)}"
        )


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_without_nonce_is_rejected(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-ensure-request-without-nonce-fails`` : nonce absent → invalid_request.

    ``AddNonceToAuthorizationEndpointRequest`` sauté + validation générique de
    l'erreur : ``error=invalid_request`` (fragment), ``state`` repris, aucun code
    — OIDC Core 1.0 §3.2.2.1 / §3.3.2.11. Variante non applicable à
    ``code``/``code token`` (``@VariantNotApplicable`` du module Java).
    """
    params = _params(harness, response_type)
    params.pop("nonce")
    result = harness.run_flow(**params)
    expect_authorization_error(result, params["state"], ("invalid_request",))


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "extra"),
    _PARAMETER_MODULES,
    ids=[alias for alias, _ in _PARAMETER_MODULES],
)
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_authorize_parameter_is_accepted(
    harness: ConformanceHarness, response_type: str, alias: str, extra: dict[str, str]
) -> None:
    """Paramètre d'autorisation accepté en implicite (8 modules x 2 variantes).

    ``oidcc-display-page``/``-popup``, ``oidcc-login-hint``, ``oidcc-ui-locales``,
    ``oidcc-claims-locales``, ``oidcc-ensure-request-with-unknown-parameter-succeeds``,
    ``oidcc-ensure-request-with-acr-values-succeeds``, ``oidcc-claims-essential`` :
    le serveur accepte le paramètre et le flux se termine sur un callback valide.

    ``acr_values`` → ``ValidateIdTokenACRClaimAgainstAcrValuesRequest`` (id_token
    du fragment). ``claims`` → member ``id_token`` pour ``response_type=id_token``
    (``EnsureIdTokenContainsName``), member ``userinfo`` sinon
    (``EnsureUserInfoContainsName`` + ``EnsureIdTokenDoesNotContainName``).
    """
    extra = dict(extra)
    if alias == "oidcc-claims-essential":
        member = "id_token" if response_type == "id_token" else "userinfo"
        extra["claims"] = json.dumps({member: {"name": {"essential": True}}})
    _params_used, result, claims = _implicit_flow(harness, response_type, **extra)
    assert claims["sub"], f"sub absent pour {alias}"
    if "acr_values" in extra:
        check_acr_claim(claims, extra["acr_values"])
    if alias == "oidcc-claims-essential":
        if response_type == "id_token":
            assert "name" in claims, "EnsureIdTokenContainsName : name absent de l'id_token"
        else:
            userinfo = check_userinfo_response(
                harness.userinfo("get", result.access_token), str(claims["sub"])
            )
            assert "name" in userinfo, "EnsureUserInfoContainsName : name absent du userinfo"
            assert "name" not in claims, (
                "EnsureIdTokenDoesNotContainName : name ne doit pas figurer dans l'id_token"
            )


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "scope"), _SCOPE_MODULES, ids=[alias for alias, _ in _SCOPE_MODULES]
)
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_scope_claims_returned(
    harness: ConformanceHarness, response_type: str, alias: str, scope: str
) -> None:
    """``oidcc-scope-*`` en implicite : userinfo avec token, id_token sinon.

    ``AbstractOIDCCReturnedClaimsServerTest.onPostAuthorizationFlowComplete`` :
    ``response_type`` contenant ``code`` ou ``token`` → ``CallUserInfoEndpoint``
    + ``ValidateUserInfoStandardClaims`` + ``VerifyScopesReturnedInUserInfoClaims`` ;
    pour ``response_type=id_token`` seul → ``VerifyScopesReturnedInAuthorizationEndpointIdToken``
    en **WARNING** de la suite, assertion ici : les claims des scopes doivent
    figurer dans l'id_token du fragment (OIDC Core 1.0 §5.4, sans UserInfo).
    """
    _params_used, result, claims = _implicit_flow(harness, response_type, scope=scope)
    if "token" not in response_type.split():
        assert claims["sub"], f"sub absent pour {alias}"
        check_scope_claims_in_id_token(claims, scope)
        return
    response = harness.userinfo("get", result.access_token)
    userinfo = check_userinfo_response(response, str(claims["sub"]))
    check_scope_claims_returned(userinfo, scope)


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "method"), _USERINFO_MODULES, ids=[alias for alias, _ in _USERINFO_MODULES]
)
def test_implicit_userinfo_endpoint_method(
    harness: ConformanceHarness, alias: str, method: str
) -> None:
    """``oidcc-userinfo-*`` en ``id_token token`` : access_token du fragment.

    ``CallUserInfoEndpoint`` / ``SetResourceMethodToPost`` /
    ``CallUserInfoEndpointWithBearerTokenInBody`` (token en corps form —
    RFC 6750 §2.1.2 ; WARNING `UserInfoEndpointWithAccessTokenInBodyNotSupported`
    évité, assertion ici).
    """
    _params_used, result, claims = _implicit_flow(harness, _TOKEN_TYPE)
    response = harness.userinfo(method, result.access_token)
    check_userinfo_response(response, str(claims["sub"]))


@pytest.mark.conformance
@pytest.mark.parametrize("module", _DOUBLE_AUTH_MODULES)
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_second_authorization(
    harness: ConformanceHarness, response_type: str, module: str
) -> None:
    """Double autorisation en implicite (``AbstractOIDCCSameAuthTwiceServerTest``).

    ``oidcc-prompt-none-logged-in`` : seconde passe ``prompt=none`` sans
    reconnexion ; ``oidcc-id-token-hint`` : ``id_token_hint`` + ``prompt=none`` ;
    ``oidcc-max-age-10000`` : ``max_age`` 15000 puis 10000 avec ``auth_time``
    stable — mêmes ``CheckIdTokenAuthTimeClaimsSameIfPresent`` et
    ``CheckIdTokenSubConsistentForSecondAuthorization``.
    """
    first_extra = {"max_age": "15000"} if module == "oidcc-max-age-10000" else {}
    _first_params, first_result, first_claims = _implicit_flow(
        harness, response_type, **first_extra
    )
    if module == "oidcc-max-age-10000":
        assert first_claims.get("auth_time"), "auth_time absent avec max_age=15000"

    second_extra: dict[str, str] = {"prompt": "none"}
    if module == "oidcc-id-token-hint":
        second_extra["id_token_hint"] = first_result.id_token
    elif module == "oidcc-max-age-10000":
        second_extra = {"max_age": "10000"}

    _second_params, second_result, second_claims = _implicit_flow(
        harness, response_type, **second_extra
    )
    assert second_result.login_pages == 0, (
        f"{module} a présenté une page de connexion : {second_result.hops}"
    )
    if module == "oidcc-max-age-10000":
        assert second_claims.get("auth_time"), "auth_time absent avec max_age=10000"
    check_second_id_token_consistent(first_claims, second_claims)


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_prompt_none_without_session(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-prompt-none-not-logged-in`` en implicite : erreur en fragment.

    ``CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface`` :
    ``error`` ∈ {login_required, …} porté par le fragment avec ``state`` repris.
    """
    harness.reset_session()
    params = _params(harness, response_type, prompt="none")
    result = harness.run_flow(**params)
    expect_authorization_error(result, params["state"], _PROMPT_NONE_ERRORS)


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_registered_redirect_uri_is_rejected(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-ensure-registered-redirect-uri`` en implicite : page d'erreur 400.

    ``CreateBadRedirectUriByAppending`` + ``ExpectRedirectUriErrorPage`` :
    aucune redirection ne part vers l'URI inconnue (OIDCC-3.1.2.1).
    """
    params = _params(harness, response_type, redirect_uri="https://evil.example/callback")
    result = harness.run_flow(**params)
    expect_redirect_uri_error_page(result)


@pytest.mark.conformance
@pytest.mark.parametrize("module", ("oidcc-prompt-login", "oidcc-max-age-1"))
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_second_login_reprompts(
    harness: ConformanceHarness, response_type: str, module: str
) -> None:
    """Seconde connexion exigée en implicite (``oidcc-prompt-login``, ``oidcc-max-age-1``).

    ``ExpectSecondLoginPage`` + ``CheckSecondIdTokenAuthTimeIsLaterIfPresent`` :
    la seconde passe présente une page de connexion et son ``auth_time`` est
    strictement postérieur (attentes de la suite : ``WaitForOneSecond`` /
    ``WaitFor2Seconds`` avant la relance).
    """
    _params_used, _first_result, first_claims = _implicit_flow(harness, response_type)
    assert first_claims.get("auth_time"), "auth_time absent du premier id_token"

    time.sleep(1 if module == "oidcc-prompt-login" else 2)
    extra = {"prompt": "login"} if module == "oidcc-prompt-login" else {"max_age": "1"}
    _second_params, second_result, second_claims = _implicit_flow(harness, response_type, **extra)
    expect_second_login_page(second_result)
    assert second_claims.get("auth_time"), "auth_time absent du second id_token"
    check_second_auth_time_is_later(int(first_claims["auth_time"]), int(second_claims["auth_time"]))


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _IMPLICIT_TYPES, ids=lambda value: f"rt-{value}")
def test_implicit_alternate_happy_flow(harness: ConformanceHarness, response_type: str) -> None:
    """``oidcc-alternate-happy-flow`` en implicite : scopes inversés.

    ``ReverseScopeOrderInAuthorizationEndpointRequest`` : l'ordre des scopes ne
    doit rien changer — avec ``token``, les checks ``oidcc-scope-email``
    (userinfo + ``EnsureIdTokenDoesNotContainEmailForScopeEmail``) ; pour
    ``response_type=id_token`` seul, ``VerifyScopesReturnedInAuthorizationEndpointIdToken``
    exige l'email dans l'id_token (OIDC Core 1.0 §5.4 : sans access_token,
    ``/userinfo`` n'est pas joignable).
    """
    _params_used, result, claims = _implicit_flow(harness, response_type, scope="email openid")
    if "token" not in response_type.split():
        assert "email" in claims, (
            "VerifyScopesReturnedInAuthorizationEndpointIdToken : email absent de l'id_token "
            f"(claims : {sorted(claims)})"
        )
        assert "email_verified" in claims, f"email_verified absent de l'id_token : {sorted(claims)}"
        return
    userinfo = check_userinfo_response(
        harness.userinfo("get", result.access_token), str(claims["sub"])
    )
    check_scope_claims_returned(userinfo, "email")
    assert "email" not in claims, "email ne doit pas figurer dans l'id_token (OIDC-5.1)"
