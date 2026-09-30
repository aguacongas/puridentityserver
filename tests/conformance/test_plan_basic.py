"""Rejeu local des 35 modules restants du plan Basic (issue #70).

``oidcc-basic-certification-test-plan`` (release-v5.2.4) compte 38 modules :
3 sont déjà rejoués par ``test_redirect_reauth.py`` (PR 1 : redirect-uri,
prompt=login, max_age=1), les 35 autres sont rejoués ici — chaque test s'appuie
sur les checks extraits des fichiers Java de la suite (``checks.py``, fiches
dans ``TRACEABILITY.md``), jamais sur une relecture de la spécification seule.

Les modules ``request``/``request_uri`` et ``oidcc-idtoken-unsigned`` sont
rejoués pour de vrai (issue #76) : l'OP annonce désormais ``none`` dans
``request_object_signing_alg_values_supported`` et
``id_token_signing_alg_values_supported``, ce qui lève les sauts
``skipTestIfNoneUnsupported`` / ``skipTestIfSigningAlgorithmNotSupported`` de
la suite — plus aucun ``pytest.skip`` dans ce fichier.
"""

from __future__ import annotations

import base64
import json
import secrets
import time

import pytest
from checks import (
    check_acr_claim,
    check_authorization_code_quality,
    check_refreshed_id_token_claims,
    check_scope_claims_absent_from_id_token,
    check_scope_claims_returned,
    check_second_id_token_consistent,
    check_token_endpoint_success,
    check_userinfo_response,
    expect_access_token_refused,
    expect_authorization_error,
    expect_callback_success,
    expect_hybrid_callback,
    expect_id_token_signature,
    expect_implicit_callback,
    expect_invalid_grant,
    expect_response_type_missing_error_page,
    validate_id_token,
)
from conftest import _CLIENT_UNSIGNED, RequestDocumentServer, build_app
from harness import ConformanceHarness, FlowResult, decode_id_token_claims, new_verifier

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
# La suite n'annonce aucun ``acr_values_supported`` ni ``claims`` supplémentaire
# : ``acr_values=1 2`` et ``scope=openid`` seul sont repris des logs de
# certification (OIDCC-3.1.2.1 / OIDCC-5.5).
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

# Modules ``request``/``request_uri`` (RFC 9101) et mode de transport employé :
# la suite les applique à **toutes** les variantes ``ResponseType`` des plans
# Basic, Implicit et Hybrid (``OIDCCBasicTestPlan``,
# ``OIDCCImplicitTestPlan``, ``OIDCCHybridTestPlan``) — leur saut commun
# ``skipTestIfNoneUnsupported`` est levé depuis que ``none`` est annoncé.
_REQUEST_OBJECT_MODULES: tuple[tuple[str, str], ...] = (
    (
        "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
        "request",
    ),
    (
        "oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported",
        "request_uri",
    ),
    ("oidcc-ensure-request-object-with-redirect-uri", "redirect_uri"),
)
# Variantes ``ResponseType`` : ``code`` (Basic), les 2 implicites et les 3 hybrides.
_REQUEST_OBJECT_TYPES = (
    "code",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
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
    ``oidcc-ensure-request-with-acr-values-succeeds``,
    ``oidcc-claims-essential``.

    ``acr_values`` → ``ValidateIdTokenACRClaimAgainstAcrValuesRequest`` :
    l'id_token du token endpoint porte un ``acr`` ∈ valeurs demandées.
    ``claims`` → ``EnsureUserInfoContainsName`` (WARNING de la suite) :
    le member ``userinfo`` de ``claims`` élargit le filtrage de ``/userinfo`` ;
    ``EnsureIdTokenDoesNotContainName`` interdit ``name`` dans l'id_token.
    """
    tokens, claims = _happy_flow(harness, **extra)
    assert tokens["id_token"], "id_token absent"
    assert claims["sub"], f"sub absent pour {alias}"
    if "acr_values" in extra:
        check_acr_claim(claims, extra["acr_values"])
    if alias == "oidcc-claims-essential":
        userinfo = check_userinfo_response(
            harness.userinfo("get", str(tokens["access_token"])), str(claims["sub"])
        )
        assert "name" in userinfo, "EnsureUserInfoContainsName : name absent du userinfo"
        assert "name" not in claims, (
            "EnsureIdTokenDoesNotContainName : name ne doit pas figurer dans l'id_token"
        )


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
    ici : le rendu effectif doit être prouvé au rejeu). Pour ``oidcc-scope-email``,
    ``OIDCCScopeEmail`` ajoute ``EnsureIdTokenDoesNotContainEmailForScopeEmail`` :
    avec un code, l'email va au userinfo, jamais dans l'id_token (OIDCC-5.4).
    """
    tokens, claims = _happy_flow(harness, scope=scope)
    response = harness.userinfo("get", str(tokens["access_token"]))
    userinfo = check_userinfo_response(response, str(claims["sub"]))
    check_scope_claims_returned(userinfo, scope)
    if alias == "oidcc-scope-email":
        check_scope_claims_absent_from_id_token(claims, "email")


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "method"), _USERINFO_MODULES, ids=[alias for alias, _ in _USERINFO_MODULES]
)
def test_userinfo_endpoint_method(harness: ConformanceHarness, alias: str, method: str) -> None:
    """``oidcc-userinfo-*`` : appel du endpoint userinfo selon la méthode attendue.

    ``CallUserInfoEndpoint`` (GET + Bearer), ``SetResourceMethodToPost`` (POST +
    Bearer) ou ``CallUserInfoEndpointWithBearerTokenInBody`` (POST form sans
    header, token en corps — RFC 6750 §2.1.2 ; la suite y voyait un WARNING
    `UserInfoEndpointWithAccessTokenInBodyNotSupported`, assertion ici).
    """
    tokens, claims = _happy_flow(harness)
    response = harness.userinfo(method, str(tokens["access_token"]))
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

    ``performRedirect("POST")`` : la requête part en POST **sur session
    vierge** et le callback doit revenir (RFC 6749 §3.1.2 note). L'OP
    mémorise le corps form pour reconstruire ``next`` après ``/login`` — sans
    cela le retour arrive sur ``/authorize`` sans paramètres et la suite
    conclut en WARNING ``ExpectRedirectUriHasBeenCalled`` (OIDCC-3.1.2.1).
    """
    harness.reset_session()
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
def test_id_token_alg_none_is_issued(unsigned_harness: ConformanceHarness) -> None:
    """``oidcc-idtoken-unsigned`` : ``id_token`` émis sans signature (``alg=none``).

    ``AddIdTokenSigningAlgNoneToDynamicRegistrationRequest`` inscrit le client
    avec ``id_token_signed_response_alg=none`` ;
    ``CheckIdTokenSignatureAlgorithm`` (OIDCC-3.1.3.7) exige
    ``header.alg == "none"``. Le saut
    ``skipTestIfSigningAlgorithmNotSupported`` n'a plus lieu d'être puisque
    ``none`` figure dans ``id_token_signing_alg_values_supported``.
    """
    verifier = new_verifier()
    params = unsigned_harness.authorize_params(verifier)
    result = unsigned_harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = unsigned_harness.exchange_code(result, verifier)

    header = ConformanceHarness.id_token_header(tokens)
    assert header["alg"] == "none", f"en-tête non signé attendu : {header!r}"
    id_token = str(tokens["id_token"])
    assert id_token.endswith("."), f"segment de signature vide attendu : {id_token[-24:]!r}"
    validate_id_token(
        ConformanceHarness.id_token_claims(tokens),
        issuer=_ISSUER,
        client_id=str(_CLIENT_UNSIGNED["client_id"]),
        nonce=str(params["nonce"]),
    )


def _unsigned_request_object(claims: dict[str, str]) -> str:
    """JWT compact non signé (``PlainJWT.serialize()`` de nimbus).

    En-tête ``{"alg":"none"}``, payload JSON, segment de signature vide :
    ``header.payload.`` — c'est le document que sert la suite en
    ``Content-Type: application/jwt``.
    """
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode("ascii")
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"{header}.{payload}."


def _request_object_claims(harness: ConformanceHarness, response_type: str) -> dict[str, str]:
    """Demande complète portée par le request object (OIDC Core 1.0 §6.1).

    ``state`` et ``nonce`` n'existent que dans le jeton : un OP qui
    ignorerait le request object échouerait sur le ``state`` attendu.
    """
    return {
        "response_type": response_type,
        "client_id": harness._client_id,
        "redirect_uri": harness._redirect_uri,
        "scope": "openid profile",
        "state": secrets.token_urlsafe(8),
        "nonce": secrets.token_urlsafe(8),
    }


def _request_object_query(
    claims: dict[str, str],
    kind: str,
    document_server: RequestDocumentServer,
) -> dict[str, str]:
    """Reconstruit la query de ``AbstractAuthorizationCodeTest.buildRedirect``.

    Seuls les doublons obligatoires (``response_type``, ``client_id``,
    ``scope``, ``redirect_uri``) y figurent à côté de ``request`` /
    ``request_uri`` ; ``redirect_uri`` choisit la variante
    ``AddInvalidRedirectUriToAuthorizationRequest`` (URI non enregistrée en
    query, URI valide conservée dans le jeton).
    """
    query = {
        "response_type": claims["response_type"],
        "client_id": claims["client_id"],
        "redirect_uri": claims["redirect_uri"],
        "scope": claims["scope"],
    }
    if kind == "request_uri":
        query["request_uri"] = f"{document_server.url}{_document_path(claims)}"
        document_server.document = _unsigned_request_object(claims)
    else:
        if kind == "redirect_uri":
            query["redirect_uri"] = f"{claims['redirect_uri']}_invalid"
        query["request"] = _unsigned_request_object(claims)
    return query


def _document_path(claims: dict[str, str]) -> str:
    """Chemin ``request_uri`` dédié au test (le ``state`` le rend unique)."""
    return f"/requesturi/{claims['state']}"


def _expect_request_object_callback(
    harness: ConformanceHarness,
    claims: dict[str, str],
    result: FlowResult,
) -> str:
    """Contrôle le callback selon le ``response_type`` puis rend l'id_token.

    Code : échange au token endpoint (sans PKCE, la demande n'en porte pas) ;
    flux implicites/hybrides : l'id_token arrive en fragment. ``nonce`` et
    ``state`` ne provenant que du request object, leur présence atteste que
    l'OP l'a réellement traité.
    """
    parts = claims["response_type"].split()
    has_code = "code" in parts
    has_id_token = "id_token" in parts
    with_token = "token" in parts
    if not has_code:
        expect_implicit_callback(result, claims["state"], with_token=with_token)
        return result.id_token
    if has_id_token:
        expect_hybrid_callback(result, claims["state"], with_id_token=True, with_token=with_token)
    else:
        expect_callback_success(result, claims["state"])
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": harness._redirect_uri,
        },
        "basic",
    )
    return str(check_token_endpoint_success(response)["id_token"])


@pytest.mark.conformance
@pytest.mark.parametrize(
    ("alias", "kind"),
    _REQUEST_OBJECT_MODULES,
    ids=[kind for _alias, kind in _REQUEST_OBJECT_MODULES],
)
@pytest.mark.parametrize("response_type", _REQUEST_OBJECT_TYPES, ids=lambda value: f"rt-{value}")
def test_request_object_module_completes(
    harness: ConformanceHarness,
    request_document_server: RequestDocumentServer,
    alias: str,
    kind: str,
    response_type: str,
) -> None:
    """Module ``request``/``request_uri`` : le request object est traité, jamais ignoré.

    ``skipTestIfNoneUnsupported`` est levé (``none`` annoncé dans
    ``request_object_signing_alg_values_supported``) ; les trois modules
    (``alias``) rejouent les 6 ``ResponseType`` des plans Basic, Implicit et
    Hybrid : la demande portée par le JWT doit produire le callback attendu,
    y compris ``state``/``nonce`` qui n'existent que dans le jeton.
    """
    claims = _request_object_claims(harness, response_type)
    query = _request_object_query(claims, kind, request_document_server)

    result = harness.run_flow(**query)
    try:
        id_token = _expect_request_object_callback(harness, claims, result)
    except AssertionError as error:
        raise AssertionError(f"{alias} [{response_type}] : {error}") from error

    if kind == "redirect_uri":
        assert result.callback_url.startswith(harness._redirect_uri), (
            f"{alias} (OIDCC-6.1) : la redirect_uri du request object doit "
            f"primer sur celle de la query : {result.callback_url!r}"
        )
    if kind == "request_uri":
        # La demande repart depuis ``/authorize`` après login/consent : chaque
        # passage re-lit le document — seule l'URL exigée ne doit pas varier.
        assert request_document_server.paths, f"{alias} : aucun document lu"
        assert set(request_document_server.paths) == {_document_path(claims)}, (
            f"{alias} : chemins lus inattendus : {request_document_server.paths!r}"
        )
    validate_id_token(
        decode_id_token_claims(id_token),
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        nonce=claims["nonce"],
    )


@pytest.mark.conformance
def test_authorization_code_cannot_be_reused(harness: ConformanceHarness) -> None:
    """``oidcc-codereuse`` : réutilisation immédiate du code → ``invalid_grant``.

    ``CallTokenEndpointAndReturnFullResponse`` avec le même code puis
    ``CheckErrorFromTokenEndpointResponseErrorInvalidGrant`` (RFC 6749 §4.1.2) ;
    l'access token du premier échange est révoqué au passage
    (``CallProtectedResource`` + ``EnsureHttpStatusCodeIs4xx``).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = harness.exchange_code(result, verifier)
    response = harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": harness._redirect_uri,
            "code_verifier": verifier,
        }
    )
    expect_invalid_grant(response)
    expect_access_token_refused(harness.userinfo("get", str(tokens["access_token"])))


@pytest.mark.conformance
def test_authorization_code_reuse_after_30_seconds(harness: ConformanceHarness) -> None:
    """``oidcc-codereuse-30seconds`` : réutilisation après 30 s → ``invalid_grant``.

    ``WaitFor30Seconds`` puis ``CallTokenEndpointAndReturnFullResponse`` — le
    code consommé reste invalide. Les jetons du premier échange sont révoqués
    (RFC 6749 §4.1.2) : ``CallProtectedResource`` + ``EnsureHttpStatusCodeIs4xx``
    sur l'access token, ``invalid_grant`` sur le refresh token. ``offline_access``
    est demandé pour que ce dernier soit émis (le plan de certification ne le
    fait pas, l'observable lui reste identique hors refresh).
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier, scope="openid profile offline_access")
    result = harness.run_flow(**params)
    expect_callback_success(result, params["state"])
    tokens = harness.exchange_code(result, verifier)
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
    expect_access_token_refused(harness.userinfo("get", str(tokens["access_token"])))
    expect_invalid_grant(
        harness.token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": str(tokens["refresh_token"]),
            }
        )
    )


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
