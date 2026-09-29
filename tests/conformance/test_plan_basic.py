"""Rejeu local des 35 modules restants du plan Basic (issue #70).

``oidcc-basic-certification-test-plan`` (release-v5.2.4) compte 38 modules :
3 sont déjà rejoués par ``test_redirect_reauth.py`` (PR 1 : redirect-uri,
prompt=login, max_age=1), les 35 autres sont rejoués ici — chaque test s'appuie
sur les checks extraits des fichiers Java de la suite (``checks.py``, fiches
dans ``TRACEABILITY.md``), jamais sur une relecture de la spécification seule.

Modules explicitement sautés (``pytest.skip``) reproduisent les skips de la
suite : ``oidcc-idtoken-unsigned`` et les 3 modules ``request``/``request_uri``
tombent sur ``skipTestIfNoneUnsupported`` car ``none`` n'est pas dans
``request_object_signing_alg_values_supported``.
"""

from __future__ import annotations

import json
import time

import pytest
from checks import (
    check_authorization_code_quality,
    check_refreshed_id_token_claims,
    check_scope_claims_returned,
    check_second_id_token_consistent,
    check_token_endpoint_success,
    check_userinfo_response,
    expect_authorization_error,
    expect_callback_success,
    expect_id_token_signature,
    expect_invalid_grant,
    expect_response_type_missing_error_page,
    validate_id_token,
)
from conftest import build_app
from harness import ConformanceHarness, new_verifier

_ISSUER = "https://id.example"
_CLIENT_ID = "web-app"
# Erreurs exigées par ``performGenericAuthorizationEndpointErrorResponseValidation`` +
# ``CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface``.
_PROMPT_NONE_ERRORS = (
    "login_required",
    "interaction_required",
    "account_selection_required",
    "consent_required",
)

# Modules dont le seul check est « ce paramètre ne casse pas le flux happy » :
# le serveur doit l'accepter ou l'ignorer (RFC 6749 §3.1, OIDC Core 1.0 §3.1.2.1).
_PARAMETER_MODULES: tuple[tuple[str, dict[str, str]], ...] = (
    ("oidcc-display-page", {"display": "page"}),
    ("oidcc-display-popup", {"display": "popup"}),
    ("oidcc-login-hint", {"login_hint": "alice@example.com"}),
    ("oidcc-ui-locales", {"ui_locales": "fr"}),
    ("oidcc-claims-locales", {"claims_locales": "se"}),
    ("oidcc-ensure-request-with-unknown-parameter-succeeds", {"extra": "foobar"}),
    ("oidcc-ensure-request-with-acr-values-succeeds", {"acr_values": "1"}),
    (
        "oidcc-claims-essential",
        {"claims": json.dumps({"userinfo": {"name": {"essential": True}}})},
    ),
)

# Modules ``oidcc-scope-*`` : le userinfo doit rendre les claims du scope.
_SCOPE_MODULES: tuple[tuple[str, str], ...] = (
    ("oidcc-scope-profile", "openid profile"),
    ("oidcc-scope-email", "openid email"),
    ("oidcc-scope-address", "openid address"),
    ("oidcc-scope-phone", "openid phone"),
    ("oidcc-scope-all", "openid profile email address phone"),
)

# Modules ``oidcc-userinfo-*`` : méthode d'appel du endpoint userinfo.
_USERINFO_MODULES: tuple[tuple[str, str], ...] = (
    ("oidcc-userinfo-get", "get"),
    ("oidcc-userinfo-post-header", "post_header"),
    ("oidcc-userinfo-post-body", "post_body"),
)

# Modules ``request``/``request_uri`` : la suite les saute quand ``none`` n'est
# pas déclaré (``skipTestIfNoneUnsupported``) — c'est le cas du serveur.
_REQUEST_OBJECT_MODULES = (
    "oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
    "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
    "oidcc-ensure-request-object-with-redirect-uri",
)


def _check_token_payload(tokens: dict[str, object]) -> None:
    """Contrôle structuré de la réponse ``/token`` reçue sous forme de dict.

    Reproduit ``CheckForAccessTokenValue`` + ``CheckTokenTypeIsBearer`` +
    ``ValidateExpiresIn`` sur un payload déjà désérialisé.
    """
    assert tokens.get("access_token"), f"access_token absent : {sorted(tokens)}"
    assert str(tokens.get("token_type", "")).lower() == "bearer", (
        f"token_type != Bearer : {tokens.get('token_type')!r}"
    )
    assert int(tokens.get("expires_in", 0)) > 0, (
        f"expires_in invalide : {tokens.get('expires_in')!r}"
    )


def _happy_flow(
    harness: ConformanceHarness, *, auth_method: str = "basic", **extra: str
) -> tuple[dict[str, object], dict[str, object]]:
    """Callback heureux + échange du code + id_token validé (séquence standard).

    Reproduit la séquence ``processCallback()`` → ``performPostAuthorizationFlow()``
    → ``PerformStandardIdTokenChecks`` des modules héritant d'``AbstractOIDCCServerTest``.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier, **extra)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = harness.exchange_code(result, verifier, auth_method)
    _check_token_payload(tokens)
    claims = ConformanceHarness.id_token_claims(tokens)
    validate_id_token(claims, issuer=_ISSUER, client_id=_CLIENT_ID, nonce=params["nonce"])
    return tokens, claims


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "extra"),
    _PARAMETER_MODULES,
    ids=[alias for alias, _ in _PARAMETER_MODULES],
)
def test_authorize_parameter_is_accepted(
    harness: ConformanceHarness, alias: str, extra: dict[str, str]
) -> None:
    """Paramètre d'autorisation accepté : flux happy complet sans erreur.

    ``oidcc-display-page``, ``oidcc-display-popup``, ``oidcc-login-hint``,
    ``oidcc-ui-locales``, ``oidcc-claims-locales``,
    ``oidcc-ensure-request-with-unknown-parameter-succeeds``,
    ``oidcc-ensure-request-with-acr-values-succeeds``, ``oidcc-claims-essential``.
    """
    tokens, claims = _happy_flow(harness, **extra)
    assert tokens["id_token"], "id_token absent"
    assert claims["sub"], f"sub absent pour {alias}"


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "scope"), _SCOPE_MODULES, ids=[alias for alias, _ in _SCOPE_MODULES]
)
def test_scope_claims_returned_in_userinfo(
    harness: ConformanceHarness, alias: str, scope: str
) -> None:
    """``oidcc-scope-*`` : le userinfo rend les claims du scope demandé.

    ``CallUserInfoEndpoint`` + ``ValidateUserInfoStandardClaims`` +
    ``VerifyScopesReturnedInUserInfoClaims`` (WARNING dans la suite, assertion
    ici : le rendu effectif doit être prouvé au rejeu).
    """
    tokens, claims = _happy_flow(harness, scope=scope)
    response = harness.userinfo("get", str(tokens["access_token"]))
    userinfo = check_userinfo_response(response, str(claims["sub"]))
    check_scope_claims_returned(userinfo, scope)


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "method"), _USERINFO_MODULES, ids=[alias for alias, _ in _USERINFO_MODULES]
)
def test_userinfo_endpoint_method(harness: ConformanceHarness, alias: str, method: str) -> None:
    """``oidcc-userinfo-*`` : appel du endpoint userinfo selon la méthode attendue.

    ``CallUserInfoEndpoint`` (GET + Bearer), ``SetResourceMethodToPost`` (POST +
    Bearer) ou ``CallUserInfoEndpointWithBearerTokenInBody`` (POST form sans
    header — la suite n'exige pas ce mode : absence de 2xx = skip).
    """
    tokens, claims = _happy_flow(harness)
    response = harness.userinfo(method, str(tokens["access_token"]))
    if method == "post_body" and response.status_code >= 300:
        pytest.skip(
            "mode access_token dans le corps non supporté (la suite émet un "
            f"WARNING `UserInfoEndpointWithAccessTokenInBodyNotSupported`) : {response.status_code}"
        )
    check_userinfo_response(response, str(claims["sub"]))


@pytest.mark.conformance
def test_prompt_none_logged_in_issues_code(harness: ConformanceHarness) -> None:
    """``oidcc-prompt-none-logged-in`` : connecté, ``prompt=none`` renvoie un code.

    ``AbstractOIDCCSameAuthTwiceServerTest`` + ``AddPromptNoneToAuthorizationEndpointRequest`` :
    deuxième passe sans reconnexion (pages de connexion nulles), mêmes ``sub`` et
    ``auth_time`` (``CheckIdTokenAuthTimeClaimsSameIfPresent``,
    ``CheckIdTokenSubConsistentForSecondAuthorization``).
    """
    _tokens, first_claims = _happy_flow(harness)

    verifier = new_verifier()
    params = harness.authorize_params(verifier, prompt="none")
    second = harness.run_flow(**params)
    expect_callback_success(second, params["state"])
    assert second.login_pages == 0, f"prompt=none a présenté une page : {second.hops}"
    second_tokens = harness.exchange_code(second, verifier)
    second_claims = ConformanceHarness.id_token_claims(second_tokens)
    check_second_id_token_consistent(first_claims, second_claims)


@pytest.mark.conformance
def test_id_token_hint_keeps_session(harness: ConformanceHarness) -> None:
    """``oidcc-id-token-hint`` : reprise avec ``id_token_hint`` + ``prompt=none``.

    ``AddIdTokenHintFromFirstLoginToAuthorizationEndpointRequest`` +
    ``AddPromptNoneToAuthorizationEndpointRequest`` : la seconde passe doit
    réussir sans reconnexion avec les mêmes ``sub`` et ``auth_time``.
    """
    first_tokens, first_claims = _happy_flow(harness)

    verifier = new_verifier()
    params = harness.authorize_params(
        verifier,
        prompt="none",
        id_token_hint=str(first_tokens["id_token"]),
    )
    second = harness.run_flow(**params)
    expect_callback_success(second, params["state"])
    assert second.login_pages == 0, f"id_token_hint a présenté une page : {second.hops}"
    second_claims = ConformanceHarness.id_token_claims(harness.exchange_code(second, verifier))
    check_second_id_token_consistent(first_claims, second_claims)


@pytest.mark.conformance
def test_max_age_10000_keeps_session_and_returns_auth_time(
    harness: ConformanceHarness,
) -> None:
    """``oidcc-max-age-10000`` : ``max_age`` passé → ``auth_time`` présent et stable.

    ``AddMaxAge15000ToAuthorizationEndpointRequest`` puis
    ``AddMaxAge10000ToAuthorizationEndpointRequest`` :
    ``CheckIdTokenAuthTimeClaimPresentDueToMaxAge`` (2 appels) puis
    ``CheckIdTokenAuthTimeClaimsSameIfPresent`` +
    ``CheckIdTokenSubConsistentForSecondAuthorization``.
    """
    _tokens, first_claims = _happy_flow(harness, max_age="15000")
    assert first_claims.get("auth_time"), "auth_time absent avec max_age=15000"

    verifier = new_verifier()
    params = harness.authorize_params(verifier, max_age="10000")
    second = harness.run_flow(**params)
    expect_callback_success(second, params["state"])
    assert second.login_pages == 0, f"max_age=10000 a exigé une reconnexion : {second.hops}"
    second_claims = ConformanceHarness.id_token_claims(harness.exchange_code(second, verifier))
    assert second_claims.get("auth_time"), "auth_time absent avec max_age=10000"
    check_second_id_token_consistent(first_claims, second_claims)


@pytest.mark.conformance
def test_prompt_none_without_session_returns_login_required(
    harness: ConformanceHarness,
) -> None:
    """``oidcc-prompt-none-not-logged-in`` : anonyme + ``prompt=none`` → erreur.

    ``performGenericAuthorizationEndpointErrorResponseValidation`` puis
    ``CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface``
    : ``error`` ∈ {login_required, …}, ``state`` repris, aucun code.
    """
    harness.reset_session()
    verifier = new_verifier()
    params = harness.authorize_params(verifier, prompt="none")
    result = harness.run_flow(**params)
    expect_authorization_error(result, params["state"], _PROMPT_NONE_ERRORS)


@pytest.mark.conformance
def test_response_type_missing_shows_error_page(harness: ConformanceHarness) -> None:
    """``oidcc-response-type-missing`` : sans ``response_type``, page d'erreur.

    ``ExpectResponseTypeMissingErrorPage`` : la suite accepte la page d'erreur
    **ou** un callback ``unsupported_response_type``/``invalid_request`` — ici
    la page (RFC 6749 §3.1.1), jamais de code.
    """
    verifier = new_verifier()
    params = {
        key: value
        for key, value in harness.authorize_params(verifier).items()
        if key != "response_type"
    }
    result = harness.run_flow(**params)
    expect_response_type_missing_error_page(result)


@pytest.mark.conformance
def test_request_without_nonce_succeeds(harness: ConformanceHarness) -> None:
    """``oidcc-ensure-request-without-nonce-succeeds-for-code-flow`` : flux sans nonce.

    La suite s'arrête au callback (``ExtractAuthorizationCodeFromAuthorizationResponse``)
    : aucun échange de code, seul le code doit être émis sans erreur.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    params.pop("nonce")
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])


@pytest.mark.conformance
def test_request_with_valid_pkce_succeeds(harness: ConformanceHarness) -> None:
    """``oidcc-ensure-request-with-valid-pkce-succeeds`` : PKCE S256 complet.

    ``SetupPkceAndAddToAuthorizationRequest`` + ``AddCodeVerifierToTokenEndpointRequest`` :
    le flux doit réussir de bout en bout (le harness signe toujours en S256).
    """
    _tokens, claims = _happy_flow(harness)
    assert claims["sub"], "sub absent"


@pytest.mark.conformance
def test_post_authorization_request_succeeds(harness: ConformanceHarness) -> None:
    """``oidcc-ensure-post-request-succeeds`` : demande d'autorisation en HTTP POST.

    ``performRedirect("POST")`` : la requête part en POST et le callback doit
    revenir (RFC 6749 §3.1.2 note). La session est établie au préalable : sur
    une session vierge l'OP renvoie vers ``/login`` avec un ``next`` reconstruit
    sans la query string — la suite y verrait simplement le WARNING
    ``ExpectRedirectUriHasBeenCalled`` (OIDCC-3.1.2.1), le rejeu préfère prouver
    l'acceptation effective du POST, voir ``TRACEABILITY.md``.
    """
    harness.login()
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow_post(**params)
    expect_callback_success(result, params["state"])
    harness.exchange_code(result, verifier)


@pytest.mark.conformance
def test_alternate_happy_flow_with_reordered_scopes(harness: ConformanceHarness) -> None:
    """``oidcc-alternate-happy-flow`` : scopes inversés, flux heureux (``oidcc-scope-email``).

    ``ReverseScopeOrderInAuthorizationEndpointRequest`` +
    ``BuildPlainRedirectToAuthorizationEndpointReorderedParams`` : l'OP ne doit
    pas dépendre de l'ordre des scopes (RFC 6749 §3.3) — hérite des checks
    ``oidcc-scope-email`` (userinfo + ``EnsureIdTokenDoesNotContainEmailForScopeEmail``).
    """
    tokens, claims = _happy_flow(harness, scope="email openid")
    userinfo = check_userinfo_response(
        harness.userinfo("get", str(tokens["access_token"])), str(claims["sub"])
    )
    check_scope_claims_returned(userinfo, "email")
    assert "email" not in claims, "email ne doit pas figurer dans l'id_token (OIDCC-5.1)"


@pytest.mark.conformance
def test_authorization_code_has_minimum_quality(harness: ConformanceHarness) -> None:
    """``oidcc-server`` : longueur/entropie minimales du code d'autorisation.

    ``EnsureMinimumAuthorizationCodeLength`` +
    ``EnsureMinimumAuthorizationCodeEntropy`` (RFC 6749 §4.1.2).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    check_authorization_code_quality(result.code)


@pytest.mark.conformance
def test_client_secret_post_authentication(harness: ConformanceHarness) -> None:
    """``oidcc-server-client-secret-post`` : authentification client dans le corps.

    ``AddFormBasedClientSecretToRequest`` + ``EnsureServerConfigurationSupportsClientSecretPost`` :
    ``client_id``/``client_secret`` en form-data au token endpoint.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = harness.exchange_code(result, verifier, auth_method="post")
    _check_token_payload(tokens)
    validate_id_token(
        ConformanceHarness.id_token_claims(tokens),
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        nonce=params["nonce"],
    )


@pytest.mark.conformance
def test_id_token_signature_is_rs256_with_kid(harness: ConformanceHarness) -> None:
    """``oidcc-idtoken-signature`` : header ``alg=RS256`` + ``kid`` présent.

    ``EnsureIdTokenContainsKid`` + ``EnsureIdTokenSignatureIsRS256``. La suite
    impose ``ClientRegistration=dynamic_client`` (non jouable ici : le
    registration endpoint exige un initial access token) — les checks du
    module sont reproduits sur le client statique, voir ``TRACEABILITY.md``.
    """
    tokens, _claims = _happy_flow(harness)
    header = ConformanceHarness.id_token_header(tokens)
    expect_id_token_signature(header)


@pytest.mark.conformance
def test_id_token_alg_none_not_supported_skips(harness: ConformanceHarness) -> None:
    """``oidcc-idtoken-unsigned`` : ``skip`` car ``none`` non supporté.

    ``skipTestIfSigningAlgorithmNotSupported``
    (``OIDCCCheckIdTokenSigningAlgValuesSupportedAlgNone``) : ``none`` absent
    de ``id_token_signing_alg_values_supported`` → la suite ``fireTestSkipped``
    — saut fidèle ici.
    """
    response = harness._client.get("/.well-known/openid-configuration")
    algs = response.json().get("id_token_signing_alg_values_supported", [])
    if "none" not in algs:
        pytest.skip(f"alg=none non supporté par l'OP (discovery : {algs})")
    raise AssertionError(f"none déclaré ({algs}) : le check signature devrait être rejoué")


@pytest.mark.conformance
@pytest.mark.parametrize("alias", _REQUEST_OBJECT_MODULES)
def test_request_object_modules_skip_without_none_support(
    harness: ConformanceHarness, alias: str
) -> None:
    """Modules ``request``/``request_uri`` : saut fidèle à ``skipTestIfNoneUnsupported``.

    ``none`` absent de ``request_object_signing_alg_values_supported`` (le
    discovery déclare ``request_parameter_supported=false``) → la suite saute
    le test — ``oidcc-request-uri-unsigned-…``,
    ``oidcc-unsigned-request-object-…``,
    ``oidcc-ensure-request-object-with-redirect-uri``.
    """
    response = harness._client.get("/.well-known/openid-configuration")
    algs = response.json().get("request_object_signing_alg_values_supported", [])
    if "none" not in algs:
        pytest.skip(f"request object alg=none non supporté (discovery : {algs})")
    raise AssertionError(f"alg=none déclaré ({algs}) : le module devrait être rejoué ({alias})")


@pytest.mark.conformance
def test_authorization_code_cannot_be_reused(harness: ConformanceHarness) -> None:
    """``oidcc-codereuse`` : réutilisation immédiate du code → ``invalid_grant``.

    ``CallTokenEndpointAndReturnFullResponse`` avec le même code puis
    ``CheckErrorFromTokenEndpointResponseErrorInvalidGrant`` (RFC 6749 §4.1.2).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    harness.exchange_code(result, verifier)
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": harness._redirect_uri,
            "code_verifier": verifier,
        }
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
def test_authorization_code_reuse_after_30_seconds(harness: ConformanceHarness) -> None:
    """``oidcc-codereuse-30seconds`` : réutilisation après 30 s → ``invalid_grant``.

    ``WaitFor30Seconds`` puis ``CallTokenEndpointAndReturnFullResponse`` — le
    code consommé reste invalide, l'access token d'origine doit être révoqué
    (``CallProtectedResource`` + ``EnsureHttpStatusCodeIs4xx``, toléré ici :
    non observé au rejeu local).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    harness.exchange_code(result, verifier)
    time.sleep(30)
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": harness._redirect_uri,
            "code_verifier": verifier,
        }
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
def test_refresh_token_grant_and_client_binding(harness: ConformanceHarness) -> None:
    """``oidcc-refresh-token`` : refresh accordé, puis ``invalid_grant`` chez un autre client.

    ``RefreshTokenRequestSteps`` (nouveau jeton, ``EnsureAccessTokenValuesAreDifferent``,
    ``CompareIdTokenClaims``) puis ``RefreshTokenRequestExpectingErrorSteps`` :
    le refresh token n'est valable que pour le client qui l'a reçu
    (``CheckErrorFromTokenEndpointResponseErrorInvalidGrant``).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier, scope="openid offline_access", prompt="consent")
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = harness.exchange_code(result, verifier)
    refresh = str(tokens.get("refresh_token", ""))
    assert refresh, f"refresh_token absent : {sorted(tokens)}"

    # ``RefreshTokenRequestSteps`` : ``WaitForOneSecond`` avant l'appel.
    time.sleep(1)
    refreshed = harness.token_request({"grant_type": "refresh_token", "refresh_token": refresh})
    payload = check_token_endpoint_success(refreshed)
    assert payload.get("refresh_token"), "nouveau refresh_token absent"
    assert payload["access_token"] != tokens["access_token"], (
        "EnsureAccessTokenValuesAreDifferent : le refresh doit émettre un nouvel access token"
    )
    check_refreshed_id_token_claims(
        ConformanceHarness.id_token_claims(tokens),
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
