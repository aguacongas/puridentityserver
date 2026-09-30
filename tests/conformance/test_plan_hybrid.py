"""Rejeu local des modules du plan Hybrid (issue #71).

``oidcc-hybrid-certification-test-plan`` (release-v5.2.4) : 37 classes de
modules rejouées en ``code id_token``, ``code token`` et ``code id_token token``
(104 exécutions dans la suite). Le ``response_mode`` par défaut étant le
fragment (OIDC Core 1.0 §3.3.2.1), le code, l'id_token et l'access_token y
figurent — ``c_hash`` accompagne le code, ``at_hash`` l'access_token.

Les modules dont l'observable est identique au plan Basic
(``oidcc-response-type-missing``, les 3 ``request``/``request_uri``) restent
rejoués par ``test_plan_basic.py`` — voir ``TRACEABILITY.md``.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

import pytest
from checks import (
    check_acr_claim,
    check_at_hash,
    check_authorization_code_quality,
    check_c_hash,
    check_refreshed_id_token_claims,
    check_scope_claims_returned,
    check_second_auth_time_is_later,
    check_second_id_token_consistent,
    check_token_endpoint_success,
    check_userinfo_response,
    expect_authorization_error,
    expect_hybrid_callback,
    expect_id_token_signature,
    expect_invalid_grant,
    expect_redirect_uri_error_page,
    expect_second_login_page,
    validate_id_token,
)
from conftest import build_app
from harness import (
    ConformanceHarness,
    FlowResult,
    decode_id_token_claims,
    decode_id_token_header,
    new_verifier,
)

_ISSUER = "https://id.example"
_CLIENT_ID = "web-app"

# Variantes ``ResponseType`` du plan (``OIDCCHybridTestPlan``).
_HYBRID_TYPES = ("code id_token", "code token", "code id_token token")
# Variante porteuse de code + id_token + access_token (PKCE, alternate-happy-flow,
# codereuse-30 et refresh n'existent qu'en ``code id_token`` dans le plan).
_PRIMARY_TYPE = "code id_token"
# ``OIDCCEnsureRequestWithoutNonceFails`` : ``@VariantNotApplicable`` sur
# ``code`` et ``code token`` — seules ces 2 variantes exigent le nonce.
_NONCE_REQUIRED_TYPES = ("code id_token", "code id_token token")

_PROMPT_NONE_ERRORS = (
    "login_required",
    "interaction_required",
    "account_selection_required",
    "consent_required",
)

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

_DOUBLE_AUTH_MODULES = (
    "oidcc-prompt-none-logged-in",
    "oidcc-id-token-hint",
    "oidcc-max-age-10000",
)


@dataclass
class _Outcome:
    """Issue d'une passe hybride : callback fragment, jetons et claims."""

    params: dict[str, str]
    result: FlowResult
    claims: dict[str, Any]
    access_token: str
    payload: dict[str, Any]


def _params(harness: ConformanceHarness, response_type: str, **extra: str) -> dict[str, str]:
    """Paramètres d'une demande hybride (PKCE absent, module dédié mis à part)."""
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


def _exchange(harness: ConformanceHarness, result: FlowResult, auth_method: str) -> dict[str, Any]:
    """Échange le code du fragment (sans PKCE) et valide la réponse ``/token``."""
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": harness._redirect_uri,
        },
        auth_method,
    )
    check_token_endpoint_success(response)
    return dict(response.json())


def _hybrid_flow(
    harness: ConformanceHarness,
    response_type: str,
    *,
    auth_method: str = "basic",
    exchange: bool = True,
    **extra: str,
) -> _Outcome:
    """Parcours hybride heureux : fragment validé + échange du code.

    Reproduit ``OIDCCServerTest`` : ``CheckMatchingCallbackParameters``,
    ``CheckStateInAuthorizationResponse``, extraction code/id_token/access_token,
    ``ValidateAtHash``/``ValidateCHash`` sur l'id_token du fragment, puis
    ``PerformStandardIdTokenChecks`` sur la réponse ``/token``.
    """
    params = _params(harness, response_type, **extra)
    result = harness.run_flow(**params)
    with_id_token = "id_token" in response_type.split()
    with_token = "token" in response_type.split()
    expect_hybrid_callback(
        result, params["state"], with_id_token=with_id_token, with_token=with_token
    )

    claims: dict[str, Any] = {}
    if with_id_token:
        claims = decode_id_token_claims(result.id_token)
        validate_id_token(claims, issuer=_ISSUER, client_id=_CLIENT_ID, nonce=params["nonce"])
        expect_id_token_signature(decode_id_token_header(result.id_token))
        check_c_hash(claims, result.code)
        if with_token:
            check_at_hash(claims, result.access_token)
        else:
            assert "at_hash" not in claims, f"at_hash sans access_token : {sorted(claims)}"

    payload: dict[str, Any] = {}
    access_token = result.access_token
    if exchange and result.code:
        payload = _exchange(harness, result, auth_method)
        endpoint_claims = ConformanceHarness.id_token_claims(payload)
        validate_id_token(
            endpoint_claims, issuer=_ISSUER, client_id=_CLIENT_ID, nonce=params["nonce"]
        )
        claims = claims or endpoint_claims
        access_token = access_token or str(payload["access_token"])
    return _Outcome(params, result, claims, access_token, payload)


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_happy_flow(harness: ConformanceHarness, response_type: str) -> None:
    """``oidcc-server`` en hybride : fragment (code/id_token/access_token) + ``/token``.

    ``ExtractAtHash``/``ValidateAtHash`` et ``ExtractCHash``/``ValidateCHash``
    portés par l'id_token du fragment, puis échange du code et userinfo appelable
    (``CallProtectedResource``). L'instance ``oidcc-idtoken-signature`` partage
    cette passe (``EnsureIdTokenContainsKid`` + ``EnsureIdTokenSignatureIsRS256``).
    """
    outcome = _hybrid_flow(harness, response_type)
    response = harness.userinfo("get", outcome.access_token)
    check_userinfo_response(response, str(outcome.claims["sub"]))


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _NONCE_REQUIRED_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_without_nonce_is_rejected(harness: ConformanceHarness, response_type: str) -> None:
    """``oidcc-ensure-request-without-nonce-fails`` : nonce absent → invalid_request.

    ``AddNonceToAuthorizationEndpointRequest`` sauté puis validation générique
    de l'erreur (fragment ``error=invalid_request``, ``state`` repris, aucun
    code) — OIDC Core 1.0 §3.2.2.1 / §3.3.2.11.
    """
    params = _params(harness, response_type)
    params.pop("nonce")
    result = harness.run_flow(**params)
    expect_authorization_error(result, params["state"], ("invalid_request",))


@pytest.mark.conformance
def test_hybrid_code_token_without_nonce_succeeds(harness: ConformanceHarness) -> None:
    """``oidcc-ensure-request-without-nonce-succeeds-for-code-flow`` : ``code token``.

    Le module saute ``AddNonceToAuthorizationEndpointRequest`` : sans id_token
    renvoyé par l'autorisation, le nonce n'est pas exigé — callback valide avec
    code + access_token en fragment, aucun id_token.
    """
    params = _params(harness, "code token")
    params.pop("nonce")
    result = harness.run_flow(**params)
    expect_hybrid_callback(result, params["state"], with_id_token=False, with_token=True)


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "extra"),
    _PARAMETER_MODULES,
    ids=[alias for alias, _ in _PARAMETER_MODULES],
)
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_authorize_parameter_is_accepted(
    harness: ConformanceHarness, response_type: str, alias: str, extra: dict[str, str]
) -> None:
    """Paramètre d'autorisation accepté en hybride (8 modules x 3 variantes).

    Même observable que Basic/Implicite mais **en fragment** : le serveur
    accepte le paramètre et le flux se termine sur un callback valide puis un
    code échangeable.

    ``acr_values`` → ``ValidateIdTokenACRClaimAgainstAcrValuesRequest`` sur
    l'id_token du fragment **et** celui du token endpoint (2 WARNING pour
    ``code id_token token``). ``claims`` → member ``userinfo`` (le
    ``response_type`` n'est jamais un id_token pur) : ``name`` exigé par
    ``EnsureUserInfoContainsName``, interdit dans les deux id_tokens par
    ``EnsureIdTokenDoesNotContainName``.
    """
    outcome = _hybrid_flow(harness, response_type, **extra)
    assert outcome.claims["sub"], f"sub absent pour {alias}"
    if "acr_values" in extra:
        if "id_token" in response_type.split():
            check_acr_claim(outcome.claims, extra["acr_values"])
        check_acr_claim(ConformanceHarness.id_token_claims(outcome.payload), extra["acr_values"])
    if alias == "oidcc-claims-essential":
        userinfo = check_userinfo_response(
            harness.userinfo("get", outcome.access_token), str(outcome.claims["sub"])
        )
        assert "name" in userinfo, "EnsureUserInfoContainsName : name absent du userinfo"
        assert "name" not in outcome.claims, (
            "EnsureIdTokenDoesNotContainName : name ne doit pas figurer dans l'id_token (fragment)"
        )
        endpoint_claims = ConformanceHarness.id_token_claims(outcome.payload)
        assert "name" not in endpoint_claims, (
            "EnsureIdTokenDoesNotContainName : name ne doit pas figurer dans l'id_token (/token)"
        )


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "scope"), _SCOPE_MODULES, ids=[alias for alias, _ in _SCOPE_MODULES]
)
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_scope_claims_returned(
    harness: ConformanceHarness, response_type: str, alias: str, scope: str
) -> None:
    """``oidcc-scope-*`` en hybride : userinfo systematique (``code`` ou ``token``).

    ``AbstractOIDCCReturnedClaimsServerTest.onPostAuthorizationFlowComplete`` :
    tout ``response_type`` hybride expose un access_token (fragment ou ``/token``)
    → ``CallUserInfoEndpoint`` + ``ValidateUserInfoStandardClaims`` +
    ``VerifyScopesReturnedInUserInfoClaims``.
    """
    outcome = _hybrid_flow(harness, response_type, scope=scope)
    response = harness.userinfo("get", outcome.access_token)
    userinfo = check_userinfo_response(response, str(outcome.claims["sub"]))
    check_scope_claims_returned(userinfo, scope)


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "method"), _USERINFO_MODULES, ids=[alias for alias, _ in _USERINFO_MODULES]
)
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_userinfo_endpoint_method(
    harness: ConformanceHarness, response_type: str, alias: str, method: str
) -> None:
    """``oidcc-userinfo-*`` en hybride : GET, POST Bearer, POST token en corps."""
    outcome = _hybrid_flow(harness, response_type)
    response = harness.userinfo(method, outcome.access_token)
    check_userinfo_response(response, str(outcome.claims["sub"]))


@pytest.mark.conformance
@pytest.mark.parametrize("module", _DOUBLE_AUTH_MODULES)
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_second_authorization(
    harness: ConformanceHarness, response_type: str, module: str
) -> None:
    """Double autorisation en hybride (``AbstractOIDCCSameAuthTwiceServerTest``).

    ``prompt=none`` (avec ``id_token_hint`` le cas échéant) ou ``max_age``
    15000 → 10000 : même ``sub``, ``auth_time`` stable, aucune seconde
    connexion (``CheckIdTokenAuthTimeClaimsSameIfPresent`` +
    ``CheckIdTokenSubConsistentForSecondAuthorization``).
    """
    first_extra = {"max_age": "15000"} if module == "oidcc-max-age-10000" else {}
    first = _hybrid_flow(harness, response_type, **first_extra)
    if module == "oidcc-max-age-10000":
        assert first.claims.get("auth_time"), "auth_time absent avec max_age=15000"

    second_extra: dict[str, str] = {"prompt": "none"}
    if module == "oidcc-id-token-hint":
        second_extra["id_token_hint"] = first.result.id_token or str(
            first.payload.get("id_token", "")
        )
    elif module == "oidcc-max-age-10000":
        second_extra = {"max_age": "10000"}
    second = _hybrid_flow(harness, response_type, **second_extra)
    assert second.result.login_pages == 0, (
        f"{module} a présenté une page de connexion : {second.result.hops}"
    )
    if module == "oidcc-max-age-10000":
        assert second.claims.get("auth_time"), "auth_time absent avec max_age=10000"
    check_second_id_token_consistent(first.claims, second.claims)


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_prompt_none_without_session(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-prompt-none-not-logged-in`` en hybride : erreur en fragment."""
    harness.reset_session()
    params = _params(harness, response_type, prompt="none")
    result = harness.run_flow(**params)
    expect_authorization_error(result, params["state"], _PROMPT_NONE_ERRORS)


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_registered_redirect_uri_is_rejected(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-ensure-registered-redirect-uri`` en hybride : page d'erreur 400."""
    params = _params(harness, response_type, redirect_uri="https://evil.example/cb")
    result = harness.run_flow(**params)
    expect_redirect_uri_error_page(result)


@pytest.mark.conformance
@pytest.mark.parametrize("module", ("oidcc-prompt-login", "oidcc-max-age-1"))
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_second_login_reprompts(
    harness: ConformanceHarness, response_type: str, module: str
) -> None:
    """Seconde connexion exigée en hybride (``oidcc-prompt-login``, ``oidcc-max-age-1``).

    ``ExpectSecondLoginPage`` + ``CheckSecondIdTokenAuthTimeIsLaterIfPresent``
    (attentes ``WaitForOneSecond`` / ``WaitFor2Seconds`` de la suite).
    """
    first = _hybrid_flow(harness, response_type)
    assert first.claims.get("auth_time"), "auth_time absent du premier id_token"

    time.sleep(1 if module == "oidcc-prompt-login" else 2)
    extra = {"prompt": "login"} if module == "oidcc-prompt-login" else {"max_age": "1"}
    second = _hybrid_flow(harness, response_type, **extra)
    expect_second_login_page(second.result)
    assert second.claims.get("auth_time"), "auth_time absent du second id_token"
    check_second_auth_time_is_later(int(first.claims["auth_time"]), int(second.claims["auth_time"]))


@pytest.mark.conformance
def test_hybrid_alternate_happy_flow(harness: ConformanceHarness) -> None:
    """``oidcc-alternate-happy-flow`` : scopes inversés (variante ``code id_token``).

    ``ReverseScopeOrderInAuthorizationEndpointRequest`` + checks hérités
    ``oidcc-scope-email`` (userinfo + ``EnsureIdTokenDoesNotContainEmailForScopeEmail``).
    Le plan ne lance ce module qu'en ``code id_token``.
    """
    outcome = _hybrid_flow(harness, _PRIMARY_TYPE, scope="email openid")
    userinfo = check_userinfo_response(
        harness.userinfo("get", outcome.access_token), str(outcome.claims["sub"])
    )
    check_scope_claims_returned(userinfo, "email")
    assert "email" not in outcome.claims, "email ne doit pas figurer dans l'id_token (OIDC-5.1)"


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_authorization_code_cannot_be_reused(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-codereuse`` en hybride : réutilisation immédiate → ``invalid_grant``.

    ``CallTokenEndpointAndReturnFullResponse`` sur un code déjà échangé +
    ``CheckErrorFromTokenEndpointResponseErrorInvalidGrant`` (RFC 6749 §4.1.2).
    """
    outcome = _hybrid_flow(harness, response_type)
    assert outcome.payload.get("access_token"), "premier échange du code refusé"
    reused = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": outcome.result.code,
            "redirect_uri": harness._redirect_uri,
        }
    )
    expect_invalid_grant(reused)


@pytest.mark.conformance
def test_hybrid_authorization_code_quality(harness: ConformanceHarness) -> None:
    """``oidcc-server`` (qualité du code) : longueur/entropie minimales en fragment.

    ``EnsureMinimumAuthorizationCodeLength`` + ``EnsureMinimumAuthorizationCodeEntropy``
    — relevés sur le code du fragment en ``code id_token``.
    """
    params = _params(harness, _PRIMARY_TYPE)
    result = harness.run_flow(**params)
    expect_hybrid_callback(result, params["state"], with_id_token=True, with_token=False)
    check_authorization_code_quality(result.code)


@pytest.mark.conformance
def test_hybrid_authorization_code_reuse_after_30_seconds(
    harness: ConformanceHarness,
) -> None:
    """``oidcc-codereuse-30seconds`` : réutilisation après 30 s → ``invalid_grant``.

    ``WaitFor30Seconds`` puis rejeu du code (variante ``code id_token`` — le
    plan le lance aussi en ``code token`` et ``code id_token token``, observables
    identiques : voir ``TRACEABILITY.md``).
    """
    outcome = _hybrid_flow(harness, _PRIMARY_TYPE)
    assert outcome.payload.get("access_token"), "premier échange du code refusé"
    time.sleep(30)
    reused = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": outcome.result.code,
            "redirect_uri": harness._redirect_uri,
        }
    )
    expect_invalid_grant(reused)


@pytest.mark.conformance
def test_hybrid_refresh_token_grant_and_client_binding(harness: ConformanceHarness) -> None:
    """``oidcc-refresh-token`` en hybride (variante ``code id_token``).

    ``RefreshTokenRequestSteps`` (``WaitForOneSecond``,
    ``EnsureAccessTokenValuesAreDifferent``, ``CompareIdTokenClaims``) puis
    ``RefreshTokenRequestExpectingErrorSteps`` chez le second client
    (``AbstractOIDCCMultipleClient``) : ``invalid_grant``.
    """
    outcome = _hybrid_flow(harness, _PRIMARY_TYPE, scope="openid offline_access", prompt="consent")
    refresh = str(outcome.payload.get("refresh_token", ""))
    assert refresh, f"refresh_token absent : {sorted(outcome.payload)}"

    # ``RefreshTokenRequestSteps`` : ``WaitForOneSecond`` avant l'appel.
    time.sleep(1)
    refreshed = harness.token_request({"grant_type": "refresh_token", "refresh_token": refresh})
    payload = check_token_endpoint_success(refreshed)
    assert payload.get("refresh_token"), "nouveau refresh_token absent"
    assert payload["access_token"] != outcome.payload["access_token"], (
        "EnsureAccessTokenValuesAreDifferent : le refresh doit émettre un nouvel access token"
    )
    check_refreshed_id_token_claims(
        ConformanceHarness.id_token_claims(outcome.payload),
        ConformanceHarness.id_token_claims(payload),
    )

    # ``AbstractOIDCCMultipleClient`` : le second client présente le jeton d'autrui.
    with ConformanceHarness(
        build_app(),
        client_id="mobile-app",
        client_secret="mobile-secret",
        redirect_uri="https://mobile.example/callback",
    ) as other_client:
        crossed = other_client.token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh}
        )
    expect_invalid_grant(crossed)


@pytest.mark.conformance
def test_hybrid_request_with_valid_pkce_succeeds(harness: ConformanceHarness) -> None:
    """``oidcc-ensure-request-with-valid-pkce-succeeds`` (variante ``code id_token``).

    ``SetupPkceAndAddToAuthorizationRequest`` + ``AddCodeVerifierToTokenEndpointRequest``
    : le flux doit réussir de bout en bout. Le plan ne lance ce module qu'en
    ``code id_token``.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier, response_type=_PRIMARY_TYPE)
    result = harness.run_flow(**params)
    expect_hybrid_callback(result, params["state"], with_id_token=True, with_token=False)
    tokens = harness.exchange_code(result, verifier)
    claims = ConformanceHarness.id_token_claims(tokens)
    validate_id_token(claims, issuer=_ISSUER, client_id=_CLIENT_ID, nonce=params["nonce"])


@pytest.mark.conformance
@pytest.mark.parametrize("response_type", _HYBRID_TYPES, ids=lambda value: f"rt-{value}")
def test_hybrid_client_secret_post_authentication(
    harness: ConformanceHarness, response_type: str
) -> None:
    """``oidcc-server-client-secret-post`` en hybride : ``client_secret_post``.

    ``AddFormBasedClientSecretToRequest`` + ``EnsureServerConfigurationSupportsClientSecretPost``
    : ``client_id``/``client_secret`` en form-data au token endpoint pour
    échanger le code du fragment.
    """
    outcome = _hybrid_flow(harness, response_type, auth_method="post")
    assert outcome.payload.get("id_token"), "id_token absent de la réponse /token"
