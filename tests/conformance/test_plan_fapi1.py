"""Rejeu local du plan FAPI 1.0 Advanced Final (issue #110).

``fapi1-advanced-final-test-plan`` (release-v5.2.4) rejoue ses modules contre
l'application locale via ``FapiHarness`` : JAR ``PS256``, ``private_key_jwt``
(et ``pushed`` avec PKCE), en deux variantes ``fapi_auth_request_method``
``by_value`` / ``pushed`` quand le module les rejoue toutes les deux.

Chaque test s'appuie sur les checks extraits des fichiers Java de la suite
(``checks.py``, fiches dans ``TRACEABILITY.md``), jamais sur une relecture de
la spécification seule — voir le clone lecture seule ``release-v5.2.4``.
"""

from __future__ import annotations

import base64
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from checks import (
    check_front_channel_artefact_hashes,
    expect_authorization_error,
    expect_hybrid_callback,
)
from fapi_harness import FAPI_CLIENT_1, FAPI_CLIENT_2, FapiHarness
from harness import (
    FlowResult,
    decode_id_token_claims,
    decode_id_token_header,
    new_verifier,
)

#: Erreurs de callback admises par les modules ``ensure-request-object-without-*``
#: et ``state-only-outside``
#: (``EnsureInvalidRequestInvalidRequestObjectInvalidRequestUriOrAccessDeniedError``).
_CALLBACK_ERRORS_4 = (
    "invalid_request",
    "invalid_request_object",
    "invalid_request_uri",
    "access_denied",
)


def _check_callback(result: FlowResult, *, state: str, nonce: str) -> dict[str, Any]:
    """Callback hybride : structure, header ``PS256``, ``nonce`` et hashes."""
    expect_hybrid_callback(result, state, with_id_token=True, with_token=False)
    header = decode_id_token_header(result.id_token)
    assert header["alg"] == "PS256", f"alg du fragment attendu PS256 : {header}"
    assert header.get("kid"), f"kid absent du header (OIDC 10.1) : {header}"
    claims = decode_id_token_claims(result.id_token)
    assert claims.get("nonce") == nonce, claims.get("nonce")
    check_front_channel_artefact_hashes(claims, code=result.code, state=state)
    return claims


def _complete_flow(
    fapi_harness: FapiHarness,
    result: FlowResult,
    *,
    state: str,
    nonce: str,
    verifier: str = "",
    audience: str | list[str] | None = None,
) -> dict[str, Any]:
    """Flux complet de la base : callback + échange ``/token`` + ressource."""
    _check_callback(result, state=state, nonce=nonce)
    tokens = fapi_harness.exchange_code(result, verifier, audience=audience)
    assert tokens.get("refresh_token"), (
        f"refresh_token absent (scope offline_access) : {sorted(tokens)}"
    )
    token_claims = decode_id_token_claims(str(tokens["id_token"]))
    assert token_claims.get("nonce") == nonce, token_claims.get("nonce")
    resource = fapi_harness.resource(str(tokens["access_token"]))
    assert resource.status_code in (200, 201), (
        f"ressource refusée ({resource.status_code}) : {resource.text[:300]}"
    )
    return tokens


def _accept_outcome(result: FlowResult, state: str, allowed: tuple[str, ...]) -> str:
    """Valide l'une des issues admises ; retourne ``success``/``error``/``page``.

    Reproduit le branch « issues multiples » des modules ``…Expecting…`` :
    callback heureux, erreur de callback dans *allowed* (``state`` repris,
    aucun ``code``) ou page d'erreur non redirigeante (placeholder).
    """
    if result.callback_url and not result.error:
        expect_hybrid_callback(result, state, with_id_token=True, with_token=False)
        return "success"
    if result.error:
        expect_authorization_error(result, state, allowed)
        return "error"
    assert result.status_code and result.body, (
        f"ni callback ni page d'erreur (hops : {result.hops})"
    )
    return "page"


def _run_rejected_jar(
    fapi_harness: FapiHarness,
    method: str,
    jar: str,
    state: str,
    par_errors: tuple[str, ...],
    callback_errors: tuple[str, ...],
    **extra: str,
) -> str:
    """Issue d'un JAR invalide : rejet ``/par``, callback en erreur ou page.

    Reproduit la trifurcation des modules ``ensure-request-object-*-fails``
    (parent ``…PARExpectingAuthorizationEndpointPlaceholderOrCallback``) :
    ``400`` + ``error`` ∈ *par_errors* au ``/par``
    (``EnsurePAR…Error``), callback avec ``error`` ∈ *callback_errors* et
    ``state`` repris (``Ensure…ErrorFromAuthorizationEndpointResponse``) ou
    page d'erreur (placeholder ``Expect…ErrorPage``) — jamais de code,
    jamais de succès. Retourne ``par_error``/``error``/``page``.
    """
    if method == "pushed":
        response = fapi_harness.push(jar)
        if response.status_code != 201:
            payload = dict(response.json())
            assert response.status_code == 400, f"POST /par : {response.text[:300]}"
            assert payload.get("error") in par_errors, payload
            return "par_error"
        result = fapi_harness.run_flow(
            request_uri=str(response.json()["request_uri"]),
            client_id=fapi_harness.client.client_id,
            **extra,
        )
    else:
        result = fapi_harness.start_authorization("by_value", jar, **extra)
    assert not result.query.get("code") and not result.fragment.get("code"), (
        f"code retourné (module négatif) : {result.callback_url!r}"
    )
    outcome = _accept_outcome(result, state, callback_errors)
    assert outcome != "success", "JAR invalide accepté"
    return outcome


def _check_client_assertion_rejection(response: httpx.Response) -> None:
    """Rejet d'une ``client_assertion`` invalide (RFC 6749 §5.2, RFC 7523 §3).

    Commun aux modules ``par-ensure-client-assertion-*-fails`` (2 checks :
    ``CheckParEndpointHttpStatusIs400Allowing401ForInvalidClientError`` +
    ``EnsurePARInvalidClientOrInvalidRequestError``) et aux modules
    ``ensure-client-assertion-*-fails`` côté ``/token`` : 400 attendu,
    401 admis uniquement pour ``invalid_client``,
    ``error ∈ {invalid_client, invalid_request}``. Le test s'arrête à la
    réponse d'endpoint (``fireTestFinished()`` : aucun redirect, aucune
    ressource).
    """
    payload = dict(response.json())
    error = payload.get("error")
    assert error in ("invalid_client", "invalid_request"), payload
    if response.status_code == 401:
        assert error == "invalid_client", payload
    else:
        assert response.status_code == 400, (
            f"HTTP {response.status_code} attendu : {response.text[:300]}"
        )


def _check_token_error(response: httpx.Response, errors: tuple[str, ...]) -> None:
    """Refus ``/token`` : les checks communs des modules d'endpoint de jeton.

    ``CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError``
    (400 attendu, 401 admis uniquement pour ``invalid_client``),
    ``CheckTokenEndpointReturnedJsonContentType`` (JSON, OIDCC-3.1.3.4),
    ``error`` ∈ *errors* et ``error_description`` non vide sans CR/LF/TAB
    (``ValidateErrorDescriptionFromTokenEndpointResponseError``,
    RFC 6749 §5.2) — le test s'arrête au token endpoint, aucune ressource.
    """
    payload = dict(response.json())
    error = payload.get("error")
    assert error in errors, payload
    if response.status_code == 401:
        assert error == "invalid_client", payload
    else:
        assert response.status_code == 400, (
            f"HTTP {response.status_code} attendu : {response.text[:300]}"
        )
    assert "application/json" in response.headers.get("content-type", ""), dict(response.headers)
    description = str(payload.get("error_description", ""))
    assert description and not any(char in description for char in "\r\n\t"), payload


def _check_token_assertion_rejection(response: httpx.Response) -> None:
    """Rejet ``/token`` d'une ``client_assertion`` invalide (7 checks communs).

    ``error ∈ {invalid_client, invalid_request}``
    (``CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest``),
    au-delà des checks de forme portés par :func:`_check_token_error`.
    """
    _check_token_error(response, ("invalid_client", "invalid_request"))


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_discovery_declares_jar_par_and_pkce(fapi_harness: FapiHarness, method: str) -> None:
    """``GetDynamicServerConfiguration`` + checks de variantes du discovery.

    Variante ``pushed`` : ``CheckDiscEndpointPARSupported`` (PAR-5) +
    ``EnsureServerConfigurationSupportsCodeChallengeMethodS256``
    (FAPI1-ADV-5.2.2-18). Variante ``by_value`` :
    ``CheckDiscEndpointRequestParameterSupported`` (FAPI1-ADV-5.2.2-1,
    OIDCD-3) puis ``CheckDiscRequirePushedAuthorizationRequestsNotSet``
    (PAR-5, ``require_pushed_authorization_requests`` jamais publié).
    Commun : ``FAPICheckDiscEndpointRequestObjectSigningAlgValuesSupported``,
    ``FAPIRWCheckDiscEndpointResponseTypesSupported`` (``code id_token``,
    FAPI1-ADV-5.2.2-2), ``SupportsCodeChallengeMethodS256`` et
    ``token_endpoint_auth_signing_alg_values_supported`` (PS256/ES256).
    """
    discovery = fapi_harness.discovery()
    jar_algs = discovery.get("request_object_signing_alg_values_supported", [])
    assert "PS256" in jar_algs and "ES256" in jar_algs, jar_algs
    assert "S256" in discovery.get("code_challenge_methods_supported", []), discovery.get(
        "code_challenge_methods_supported"
    )
    auth_signing = discovery.get("token_endpoint_auth_signing_alg_values_supported", [])
    assert "PS256" in auth_signing, auth_signing
    assert "code id_token" in discovery.get("response_types_supported", []), discovery.get(
        "response_types_supported"
    )
    assert discovery.get("request_parameter_supported") is True
    assert "require_pushed_authorization_requests" not in discovery
    if method == "pushed":
        assert discovery.get("pushed_authorization_request_endpoint"), sorted(discovery)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_advanced_final_happy_flow(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final`` : flux hybride signé complet (les 2 variantes).

    ``AbstractFAPI1AdvancedFinalServerTestModule.performAuthorizationFlow`` :
    JAR ``code id_token`` (PKCE ``S256`` en variante ``pushed``) → callback en
    fragment (``code``, ``id_token``, ``c_hash``, ``s_hash``,
    ``ExtractSHash``) → échange ``/token`` en ``private_key_jwt`` → ressource
    protégée Bearer (``CallProtectedResource``). La classe étend
    ``AbstractFAPI1AdvancedFinalMultipleClient`` : le second client rejoue le
    flux avec ``requested_state_length = 128`` et un nonce de 43 caractères
    (``FAPI1AdvancedFinal.java:76-90``). Étape finale
    ``switchToClient1AndTryClient2AccessToken`` (Bearer non PoP) exclue du
    rejeu — voir ``TRACEABILITY.md`` ; l'ordre renversé des paramètres du
    second client (``…ReorderedParams``) n'est pas rejoué (Starlette est
    insensible à l'ordre de la query).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)

    fapi_harness.switch(FAPI_CLIENT_2)
    verifier2 = new_verifier() if method == "pushed" else ""
    state2 = secrets.token_urlsafe(96)
    nonce2 = secrets.token_urlsafe(32)
    assert len(state2) == 128, f"state du 2ᵉ client sur 128 caractères : {len(state2)}"
    assert len(nonce2) == 43, f"nonce du 2ᵉ client sur 43 caractères : {len(nonce2)}"
    jar2 = fapi_harness.jar(verifier2, state=state2, nonce=nonce2)
    result2 = fapi_harness.start_authorization(method, jar2)
    _complete_flow(fapi_harness, result2, state=state2, nonce=nonce2, verifier=verifier2)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_user_rejects_authentication(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-user-rejects-authentication`` (2 clients).

    ``Command { requested_state_length = 128 }`` avant
    ``CreateRandomStateValue`` (state ``token_urlsafe(96)`` = 128
    caractères), refus du consentement (``action=deny``, aucune page
    d'erreur attendue par le module) → ``error=access_denied`` + ``state``
    repris à l'identique, jamais de ``code`` :
    ``ExpectAccessDeniedErrorDueToUserRejectingRequest`` (OIDC Core 1.0
    §3.1.2.6, RFC 6749 §4.1.2.1). ``prompt=consent`` force l'écran même
    quand un consentement mémorisé couvre la demande (OIDC §3.1.2.1) :
    le smoke sert tous les tests contre un **serveur partagé** dont les
    consentements persistent — sans force, l'écran serait sauté après les
    tests nominaux. Rejoué pour le second client
    (``AbstractFAPI1AdvancedFinalMultipleClient`` avec
    ``AddRedirectUriQuerySuffix``). ``CheckForUnexpectedParameters``
    (WARNING OIDC Core 1.0 §3.1.2.6) n'admet que ``error``,
    ``error_description``, ``error_uri``, ``state``, ``session_state``,
    ``iss`` dans la réponse d'erreur.
    """
    allowed = {"error", "error_description", "error_uri", "state", "session_state", "iss"}
    for client in (FAPI_CLIENT_1, FAPI_CLIENT_2):
        fapi_harness.switch(client)
        state = secrets.token_urlsafe(96)
        assert len(state) == 128, f"state de 128 caractères attendu : {state!r}"
        verifier = new_verifier() if method == "pushed" else ""
        jar = fapi_harness.jar(verifier, state=state, prompt="consent")
        result = fapi_harness.start_authorization(method, jar, deny_consent=True)
        expect_authorization_error(result, state, ("access_denied",))
        assert set(result.fragment) <= allowed, (
            f"paramètres inattendus dans le fragment d'erreur : {sorted(result.fragment)}"
        )


@pytest.mark.conformance
def test_fapi1_valid_pkce_succeeds(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-ensure-valid-pkce-succeeds`` (by_value).

    ``@VariantNotApplicable(FAPIAuthRequestMethod, {"pushed"})`` : seul test
    « PKCE valide » du plan — ``SetupPkceAndAddToAuthorizationRequest``
    (RFC 7636 §4.1/4.2/4.3) ajoute ``code_challenge``/``S256`` au JAR en
    variante ``by_value``, ``AddCodeVerifierToTokenEndpointRequest``
    (RFC 7636 §4.5) joint le ``code_verifier`` à l'échange. Succès intégral
    obligatoire (RFC 6749 §3.1 : paramètre non reconnu ⇒ ignoré).
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization("by_value", jar)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_multiple_aud_succeeds(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-multiple-aud-succeeds``.

    ``AddMultipleAudToRequestObject`` (RFC 7519 §4.1.3) : ``aud`` =
    ``[issuer, "https://other1.example.com", "invalid"]`` — l'OP doit
    accepter un tableau contenant son issuer. En variante ``pushed``, la
    redirection ``…WithoutDuplicates`` (PAR-4) n'envoie que ``request_uri`` +
    ``client_id`` (paramétrage ``pushed`` du harness). Succès intégral.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(
        verifier,
        state=state,
        nonce=nonce,
        aud=[fapi_harness.issuer, "https://other1.example.com", "invalid"],
    )
    result = fapi_harness.start_authorization(method, jar)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_without_state_success(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-authorization-request-without-state-success``.

    ``skip(AddStateToAuthorizationEndpointRequest)`` (« NOT adding state to
    request object ») : ni ``state`` dans l'URL ni dans le JAR —
    ``VerifyNoStateInAuthorizationResponse`` et ``VerifyNoSHash``
    (FAPI1-ADV-5.2.2-10) exigent un callback **sans** ``state`` ni
    ``s_hash`` ; ``c_hash`` reste exigé. Aucune erreur admise (succès seul).
    """
    verifier = new_verifier() if method == "pushed" else ""
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, nonce=nonce, remove=("state",))
    result = fapi_harness.start_authorization(method, jar)
    _complete_flow(fapi_harness, result, state="", nonce=nonce, verifier=verifier)
    assert result.returned_state == "", (
        f"state ne doit pas être émis sans state dans le JAR : {result.returned_state!r}"
    )
    fragment_claims = decode_id_token_claims(result.id_token)
    assert "s_hash" not in fragment_claims, (
        f"s_hash ne doit pas être émis sans state : {sorted(fragment_claims)}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_other_scope_order_succeeds(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-other-scope-order-succeeds``.

    ``ReverseScopeOrderInAuthorizationEndpointRequest`` (RFC 6749 §3.3) :
    ordre du ``scope`` inversé avant conversion en JAR — l'ordre des scopes
    n'a aucune importance ; succès intégral obligatoire.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(
        verifier, state=state, nonce=nonce, scope="offline_access profile openid"
    )
    result = fapi_harness.start_authorization(method, jar)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_access_token_type_header_case_sensitivity(
    fapi_harness: FapiHarness, method: str
) -> None:
    """Module ``fapi1-advanced-final-access-token-type-header-case-sensitivity``.

    ``SetAccessTokenTypeToInvertedCase`` (STOP RFC 9110 §11.1) : le
    ``token_type`` renvoyé a sa casse inversée lettre à lettre (ex.
    ``Bearer`` → ``bEArer``) puis la ressource est appelée avec ce schéma —
    le RS doit l'accepter (comparaison insensible à la casse).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    tokens = fapi_harness.exchange_code(result, verifier)
    token_type = str(tokens.get("token_type", ""))
    assert token_type, f"token_type absent : {sorted(tokens)}"
    inverted = "".join(c.lower() if c.isupper() else c.upper() for c in token_type)
    assert inverted != token_type, f"token_type déjà tout en casse : {token_type!r}"
    resource = fapi_harness.resource(str(tokens["access_token"]), scheme=inverted)
    assert resource.status_code in (200, 201), (
        f"schéma de casse inversée refusé ({resource.status_code}) : {resource.text[:300]}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_response_mode_query(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-response-mode-query``.

    ``SetAuthorizationEndpointRequestResponseModeToQuery`` force
    ``response_mode=query`` dans le JAR (interdit FAPI). Issues admises :
    page ``ExpectResponseModeQueryErrorPage`` (OAuth2 RT-5), callback
    ``error=invalid_request`` (``EnsureInvalidRequestError`` FAILURE) ou
    succès (l'OP ignore ``response_mode=query``, réponse en **fragment**) —
    jamais de ``code`` en query (``RejectAuthCodeInUrlQuery`` OIDC 3.3.2.5).
    En succès aucun appel token/ressource (``fireTestFinished()`` direct).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, response_mode="query")
    if method == "pushed":
        response = fapi_harness.push(jar)
        if response.status_code != 201:
            payload = dict(response.json())
            assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload
            return
        result = fapi_harness.run_flow(
            request_uri=str(response.json()["request_uri"]),
            client_id=fapi_harness.client.client_id,
        )
    else:
        result = fapi_harness.start_authorization("by_value", jar)
    assert not result.query.get("code"), f"code en query (OIDC 3.3.2.5) : {result.callback_url!r}"
    outcome = _accept_outcome(result, state, ("invalid_request",))
    if outcome == "success":
        assert result.fragment.get("id_token"), (
            f"id_token attendu en fragment : {result.callback_url!r}"
        )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_different_nonce_inside_and_outside(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-different-nonce-inside-and-outside…``.

    ``AddIncorrectNonceToAuthorizationEndpointRequest`` insert, **après** la
    copie dans le JAR, un second nonce de 10 caractères dans
    ``authorization_endpoint_request`` → valeurs différentes dedans/dehors
    (``buildRedirect`` le rejoue en query). Issues admises : page
    ``ExpectRequestDifferentNonceInsideAndOutsideErrorPage``, callback
    ``error=invalid_request`` (OIDC 6.1) ou succès avec le nonce **du JAR**
    retourné dans l'``id_token``.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar, nonce="abcdefghij")
    outcome = _accept_outcome(result, state, ("invalid_request",))
    if outcome == "success":
        _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_registered_redirect_uri_rejected(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-registered-redirect-uri``.

    ``CreateBadRedirectUriByAppending`` : ``redirect_uri`` = base +
    ``/`` + 10 caractères alphanumériques, non enregistrée. Issues admises :
    page d'erreur ``ExpectRedirectUriErrorPage`` (FAPI1-BASE-5.2.2-8) ou
    rejet PAR ``invalid_request``/``invalid_request_object`` (PAR-2.3) —
    toute redirection vers l'URI non enregistrée est un échec
    (``processCallback`` lève ``TestFailureException``).
    """
    bad_uri = f"{fapi_harness.client.redirect_uri}/abcdefghij"
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(state=state, nonce=nonce, redirect_uri=bad_uri)
    if method == "by_value":
        result = fapi_harness.start_authorization("by_value", jar, redirect_uri=bad_uri)
        assert not result.callback_url, (
            f"redirection vers l'URI non enregistrée : {result.callback_url!r}"
        )
        assert result.status_code and result.body, f"page d'erreur attendue (hops : {result.hops})"
        return
    response = fapi_harness.push(jar)
    if response.status_code != 201:
        payload = dict(response.json())
        assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload
        return
    request_uri = str(response.json()["request_uri"])
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=fapi_harness.client.client_id)
    assert not result.callback_url, (
        f"redirection vers l'URI non enregistrée : {result.callback_url!r}"
    )
    assert result.status_code and result.body, f"page d'erreur attendue (hops : {result.hops})"


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_long_nonce_accepted(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-long-nonce``.

    ``requested_nonce_length = 384`` (issue gitlab FAPI #359) : nonce de 384
    caractères (``nextAlphanumeric(380) + "-._~"``) dans le JAR. Issues
    admises : succès avec le nonce retourné intact, ``invalid_request`` en
    callback (WARNING), ``invalid_request`` à PAR (pushed, PAR-2.3) ou page
    ``ExpectRequestObjectWithLongNonceErrorPage`` — jamais de nonce tronqué.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = "a" * 380 + "-._~"
    assert len(nonce) == 384, len(nonce)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    outcome = _accept_outcome(result, state, ("invalid_request",))
    if outcome == "success":
        _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_64_char_nonce_success(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-64-char-nonce-success``.

    ``requested_nonce_length = 64`` : le serveur doit renvoyer le nonce
    exact ou rejeter (``invalid_request`` WARNING, PAR-2.3) — jamais un
    nonce tronqué ou corrompu. Succès attendu ici avec ``nonce`` identique.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(48)
    assert len(nonce) == 64, len(nonce)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    outcome = _accept_outcome(result, state, ("invalid_request",))
    if outcome == "success":
        _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_long_state_accepted(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-long-state``.

    ``requested_state_length = 1000`` (PR FAPI #483) : state de 1000
    caractères dans le JAR. Issues admises : succès avec le state retourné à
    l'identique, ``invalid_request`` (WARNING + ``WarningAboutRejectingLongState``),
    ``invalid_request`` à PAR (pushed, PAR-2.3) ou page
    ``ExpectRequestObjectWithLongStateErrorPage``.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = "s" * 996 + "-._~"
    assert len(state) == 1000, len(state)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    outcome = _accept_outcome(result, state, ("invalid_request",))
    if outcome == "success":
        _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_matching_key_rejected(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-matching-key-in-authorization-request``.

    JAR signé avec la clé du **client 2** alors que ``iss``/``client_id``
    restent ceux du client 1 (``mapKey("client_jwks", "client_jwks2")``) et
    ``expose_state_in_authorization_endpoint_request`` → ``state`` aussi en
    clair dans la query pour être renvoyable. Issues admises : callback
    ``error=invalid_request_object`` (FAILURE exact, FAPI1-ADV-5.2.2-1,
    OIDC 6.3.2) avec le ``state`` correct, page
    ``ExpectRequestObjectUnverifiableErrorPage`` ou rejet PAR
    ``invalid_request``/``invalid_request_object`` (JAR-6.2). Succès = échec.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(
        state=state,
        nonce=nonce,
        key=FAPI_CLIENT_2.private_key,
        kid=FAPI_CLIENT_2.kid,
    )
    if method == "by_value":
        result = fapi_harness.run_flow(
            request=jar,
            client_id=fapi_harness.client.client_id,
            redirect_uri=fapi_harness.client.redirect_uri,
            response_type="code id_token",
            scope=fapi_harness.client.scope,
            state=state,
        )
    else:
        response = fapi_harness.push(jar)
        if response.status_code != 201:
            payload = dict(response.json())
            assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload
            return
        request_uri = str(response.json()["request_uri"])
        result = fapi_harness.run_flow(
            request_uri=request_uri,
            client_id=fapi_harness.client.client_id,
            state=state,
        )
    outcome = _accept_outcome(result, state, ("invalid_request_object",))
    assert outcome != "success", "un JAR signé par une autre clé doit être rejeté"


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_without_request_object_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-authorization-request-without-request-object-fails``.

    Aucun JAR : paramètres plats (``BuildPlainRedirectToAuthorizationEndpoint``
    STOP FAPI1-ADV-5.2.2-1) ; ``isPar = Troolean.ISNT`` interdit tout appel
    PAR **même en variante ``pushed``**. Issues admises : callback
    ``error=invalid_request`` (FAILURE) ou page
    ``ExpectAuthorizationRequestWithoutRequestObjectErrorPage`` ; succès =
    échec.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    params = {
        "response_type": "code id_token",
        "client_id": fapi_harness.client.client_id,
        "redirect_uri": fapi_harness.client.redirect_uri,
        "scope": fapi_harness.client.scope,
        "state": state,
        "nonce": nonce,
    }
    result = fapi_harness.run_flow(**params)
    outcome = _accept_outcome(result, state, ("invalid_request",))
    assert outcome != "success", "un flux FAPI sans JAR doit être rejeté"


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_redirect_uri_missing(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-redirect-uri-in-authorization-request``.

    ``redirect_uri`` retirée de ``authorization_endpoint_request`` avant la
    copie dans le JAR (absente des deux côtés). Issues admises : rejet PAR
    ``invalid_request``/``invalid_request_object`` (PAR-2.3), page
    ``ExpectRedirectUriMissingErrorPage`` (FAPI1-BASE-5.2.2-9) ou succès
    (URI enregistrée par défaut, RFC 6749 §3.1.2.3) — le client seedé
    possède deux ``redirect_uris`` : pas de défaut possible ici.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(state=state, nonce=nonce, remove=("redirect_uri",))
    if method == "by_value":
        result = fapi_harness.start_authorization("by_value", jar, redirect_uri="")
        outcome = _accept_outcome(result, state, ("invalid_request",))
        assert outcome != "success", "le succès exigerait un redirect_uri par défaut unique"
        return
    response = fapi_harness.push(jar)
    if response.status_code != 201:
        payload = dict(response.json())
        assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload
        return
    request_uri = str(response.json()["request_uri"])
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=fapi_harness.client.client_id)
    outcome = _accept_outcome(result, state, ("invalid_request",))
    assert outcome != "success", "le succès exigerait un redirect_uri par défaut unique"


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_attempt_reuse_code_after_one_second(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-attempt-reuse-authorisation-code-after-one-second``.

    Flux complet (le code est échangé une première fois), ``WaitForOneSecond``,
    puis ré-échange du **même code** avec une assertion fraîche
    (``CreateJWTClientAuthenticationAssertion…``) : ``CallTokenEndpoint…``
    STOP FAPI1-BASE-5.2.2-13 — HTTP 400 + ``error=invalid_grant`` exigé
    (200 ⇒ ``ServerAllowedReusingAuthorizationCode`` FAILURE). Pas de 2ᵉ
    client ; la révocation éventuelle de l'access_token n'est qu'une WARNING
    (``EnsureHttpStatusCodeIs4xx`` RFC 6749 §4.1.2) — non bloquante.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    tokens = fapi_harness.exchange_code(result, verifier)
    assert tokens.get("access_token"), sorted(tokens)
    time.sleep(1)
    payload: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": result.code,
        "redirect_uri": fapi_harness.client.redirect_uri,
    }
    if verifier:
        payload["code_verifier"] = verifier
    response = fapi_harness.token_request(payload)
    assert response.status_code == 400, (
        f"réutilisation du code acceptée ({response.status_code}) : {response.text[:300]}"
    )
    error_payload = dict(response.json())
    assert error_payload.get("error") == "invalid_grant", error_payload


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_iss_aud_succeeds(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-with-iss-aud-succeeds``.

    ``UpdateClientAuthenticationAssertionClaimsWithISSAud`` : l'``aud`` de la
    client assertion vaut l'``issuer`` au lieu du ``token_endpoint``
    (RFC 9126 §2 : issuer, token endpoint ou PAR endpoint acceptés). Issues
    admises : succès (200) ou ``invalid_client`` en HTTP 400/401 (WARNING
    certification). Appel token unique : ``fireTestFinished()`` après
    ``processTokenEndpointResponse`` — aucune ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    payload: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": result.code,
        "redirect_uri": fapi_harness.client.redirect_uri,
    }
    if verifier:
        payload["code_verifier"] = verifier
    response = fapi_harness.token_request(payload, audience=fapi_harness.issuer)
    if response.status_code == 200:
        data = dict(response.json())
        assert data.get("access_token"), sorted(data)
        return
    assert response.status_code in (400, 401), (
        f"HTTP {response.status_code} inattendu : {response.text[:300]}"
    )
    assert dict(response.json()).get("error") == "invalid_client", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_refresh_token(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-refresh-token`` (2 clients).

    ``AddPromptConsentToAuthorizationEndpointRequestIfScopeContainsOfflineAccess``
    (STOP OIDC 11) ajoute ``prompt=consent`` quand ``offline_access`` est
    demandé → ``refresh_token`` obligatoire (``fireTestSkipped`` sinon),
    caractères RFC 6749 §A.17, puis ``RefreshTokenRequestSteps`` : refresh en
    200 avec ``access_token`` + ``id_token``. Le second client rejoue le flux
    (state 128), puis un refresh **cross-client** (refresh_token du client 2
    avec l'assertion du client 1) doit échouer. Exclus du rejeu : refresh
    avec cert mTLS falsifié (``CallTokenEndpointAllowingTLSFailure``,
    FAPI1-ADV-5.2.2-6) et ``switchToClient1AndTryClient2AccessToken`` —
    voir ``TRACEABILITY.md``.
    """

    def _allowed_chars(value: str) -> bool:
        return all(c == "!" or ("#" <= c <= "[") or ("]" <= c <= "~") for c in value)

    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, prompt="consent")
    result = fapi_harness.start_authorization(method, jar)
    tokens = _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)
    refresh_token = str(tokens.get("refresh_token", ""))
    assert refresh_token, f"refresh_token absent avec offline_access : {sorted(tokens)}"
    assert _allowed_chars(refresh_token), "refresh_token hors RFC 6749 §A.17"

    first = fapi_harness.refresh(refresh_token)
    assert first.status_code == 200, f"refresh refusé ({first.status_code}) : {first.text[:300]}"
    first_tokens = dict(first.json())
    assert first_tokens.get("access_token"), sorted(first_tokens)
    assert first_tokens.get("id_token"), sorted(first_tokens)
    rotated = str(first_tokens.get("refresh_token", refresh_token))
    assert _allowed_chars(rotated), "refresh_token rotaté hors RFC 6749 §A.17"

    fapi_harness.switch(FAPI_CLIENT_2)
    verifier2 = new_verifier() if method == "pushed" else ""
    state2 = secrets.token_urlsafe(96)
    assert len(state2) == 128, len(state2)
    nonce2 = secrets.token_urlsafe(16)
    jar2 = fapi_harness.jar(verifier2, state=state2, nonce=nonce2, prompt="consent")
    result2 = fapi_harness.start_authorization(method, jar2)
    tokens2 = _complete_flow(fapi_harness, result2, state=state2, nonce=nonce2, verifier=verifier2)
    refresh_token2 = str(tokens2.get("refresh_token", ""))
    assert refresh_token2, f"refresh_token absent côté client 2 : {sorted(tokens2)}"
    second = fapi_harness.refresh(refresh_token2)
    assert second.status_code == 200, (
        f"refresh client 2 refusé ({second.status_code}) : {second.text[:300]}"
    )

    fapi_harness.switch(FAPI_CLIENT_1)
    cross = fapi_harness.refresh(refresh_token2)
    assert cross.status_code == 400, (
        f"refresh cross-client accepté ({cross.status_code}) : {cross.text[:300]}"
    )
    cross_payload = dict(cross.json())
    assert cross_payload.get("error") in ("invalid_grant", "invalid_client", "invalid_request"), (
        cross_payload
    )


@pytest.mark.conformance
def test_fapi1_par_reused_request_uri_succeeds(fapi_harness: FapiHarness) -> None:
    """Module ``…-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`` (pushed).

    ``request_uri`` réutilisée **avant** la fin de l'authentification : la
    première visite présente la page de login sans action (``ExpectLoginPage``
    STOP ; ``frequency(visited, redirect_url) >= 2`` exigé au callback), la
    seconde visite complète le flux → succès. ``invalid_request_uri`` en
    callback n'est qu'un WARNING (``WarningAboutRequestUriError``). Module
    mono-client (classe étend la base, pas ``MultipleClient``).
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    request_uri = fapi_harness.push_ok(jar)
    path = "/authorize?" + urlencode(
        {"request_uri": request_uri, "client_id": fapi_harness.client.client_id}
    )
    first = fapi_harness.raw_get(path)
    assert first.status_code in (302, 303, 307, 308), (
        f"1ʳᵉ visite sans redirection ({first.status_code}) : {first.text[:200]}"
    )
    first_location = first.headers.get("location", "")
    assert "/login" in first_location, (
        f"login attendue à la 1ʳᵉ visite (authentification différée) : {first_location}"
    )
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=fapi_harness.client.client_id)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
def test_fapi1_par_endpoint_as_assertion_audience(fapi_harness: FapiHarness) -> None:
    """Module ``…-par-test-pushed-authorization-url-as-audience-for-client-JWT-assertion``.

    ``AddPAREndpointAsAudToClientAuthenticationAssertionClaims`` (PAR-2) :
    ``aud`` de l'assertion ``/par`` = ``pushed_authorization_request_endpoint``
    — RFC 9126 §2 impose à l'AS d'accepter ce troisième ``aud``. Pushed
    uniquement, mono-client, succès intégral.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    request_uri = fapi_harness.push_ok(jar, audience=fapi_harness.par_endpoint)
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=fapi_harness.client.client_id)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
def test_fapi1_par_token_endpoint_as_assertion_audience(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-token-endpoint-url-as-audience-for-client-JWT-assertion``.

    ``AddTokenEndpointAsAudToClientAuthenticationAssertionClaims`` (PAR-2) :
    ``aud`` de l'assertion ``/par`` = ``token_endpoint`` ; l'assertion
    ``/token`` reste standard (``aud`` = ``token_endpoint``). Pushed
    uniquement, mono-client, succès intégral.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    request_uri = fapi_harness.push_ok(jar, audience=fapi_harness.token_endpoint)
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=fapi_harness.client.client_id)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_array_as_assertion_audience(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-test-array-as-audience-for-client-JWT-assertion``.

    ``AddArrayContainingIssuerAndAnotherValueAsAud…`` (RFC 7519 §4.1.3,
    PAR-2) : ``aud = [issuer, token_endpoint]`` sur l'assertion ``/par``
    (variante ``pushed``) **et** l'assertion ``/token`` (les deux variantes) —
    RFC 7523 §3 : le tableau doit contenir une valeur identifiant l'AS.
    Succès intégral.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    audience = [fapi_harness.issuer, fapi_harness.token_endpoint]
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    if method == "pushed":
        request_uri = fapi_harness.push_ok(jar, audience=audience)
        result = fapi_harness.run_flow(
            request_uri=request_uri, client_id=fapi_harness.client.client_id
        )
    else:
        result = fapi_harness.start_authorization("by_value", jar)
    _complete_flow(
        fapi_harness, result, state=state, nonce=nonce, verifier=verifier, audience=audience
    )


@pytest.mark.conformance
def test_fapi1_par_without_duplicate_parameters(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-without-duplicate-parameters`` (pushed).

    ``BuildRequestObjectByReference…WithoutDuplicates`` (STOP PAR-4,
    RFC 9101 §5) : la query d'autorisation ne contient que ``request_uri`` +
    ``client_id`` — le paramétrage ``pushed`` du harness respecte déjà cette
    forme. Pushed uniquement, mono-client, succès intégral.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization("pushed", jar)
    _complete_flow(fapi_harness, result, state=state, nonce=nonce, verifier=verifier)


@pytest.mark.conformance
def test_fapi1_par_client_assertion_wrong_aud_fails(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-ensure-client-assertion-with-wrong-aud-fails``.

    ``AddWrongAudToClientAssertionClaims`` (RFC 7523 §3, PAR-2) : ``aud`` de
    la ``client_assertion`` = ``https://fapidev-rs.authlete.net/api/userinfo``
    (valeur codée en dur de la suite) → rejet au ``/par``, pas de redirect
    navigateur. Pushed uniquement, ``mtls`` non applicable (pas d'assertion).
    """
    jar = fapi_harness.jar(new_verifier())
    response = fapi_harness.push(jar, audience="https://fapidev-rs.authlete.net/api/userinfo")
    _check_client_assertion_rejection(response)


@pytest.mark.conformance
def test_fapi1_par_client_assertion_wrong_iss_fails(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-ensure-client-assertion-with-wrong-iss-fails``.

    ``AddWrongIssToClientAssertionClaims`` (RFC 7523 §3, OIDCC-9) :
    ``iss = "wrong-issuer-value"`` (``sub``/``aud`` corrects) → rejet au
    ``/par`` — distingue la validation ``iss`` de celle de ``aud``.
    Pushed uniquement, test terminé au ``/par``.
    """
    jar = fapi_harness.jar(new_verifier())
    response = fapi_harness.push(
        jar, extra={"client_assertion": fapi_harness.assertion(iss="wrong-issuer-value")}
    )
    _check_client_assertion_rejection(response)


@pytest.mark.conformance
def test_fapi1_par_client_assertion_wrong_sub_fails(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-ensure-client-assertion-with-wrong-sub-fails``.

    ``SetSubToWrongValueInClientAssertionClaims`` (RFC 7523 §3, OIDCC-9) :
    ``sub = "wrong-sub-value"`` (``iss``/``aud`` corrects) → rejet au
    ``/par``. Pushed uniquement, test terminé au ``/par``.
    """
    jar = fapi_harness.jar(new_verifier())
    response = fapi_harness.push(
        jar, extra={"client_assertion": fapi_harness.assertion(sub="wrong-sub-value")}
    )
    _check_client_assertion_rejection(response)


@pytest.mark.conformance
def test_fapi1_par_pkce_required(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-ensure-pkce-required`` (pushed).

    ``SetupPkceAndAddToAuthorizationRequest`` sauté : ni ``code_challenge``
    ni ``code_challenge_method`` dans le JAR (FAPI1-ADV-5.2.2-18,
    RFC 7636 §4.4.1). Issues admises : 400 ``invalid_request`` au ``/par``
    (``EnsurePARInvalidRequestError``), ``invalid_request`` sur la réponse
    d'autorisation (``EnsureInvalidRequestError``) ou page d'erreur
    (``ExpectPkceMissingErrorPage``) — jamais un callback heureux.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(state=state, nonce=nonce)
    response = fapi_harness.push(jar)
    if response.status_code != 201:
        payload = dict(response.json())
        assert response.status_code == 400, f"POST /par : {response.text[:300]}"
        assert payload.get("error") == "invalid_request", payload
        return
    result = fapi_harness.run_flow(
        request_uri=str(response.json()["request_uri"]),
        client_id=fapi_harness.client.client_id,
    )
    outcome = _accept_outcome(result, state, ("invalid_request",))
    assert outcome != "success", "PKCE absent accepté en variante pushed (RFC 7636 §4.4.1)"


@pytest.mark.conformance
def test_fapi1_par_plain_pkce_rejected(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-plain-pkce-rejected`` (pushed).

    ``CreatePlainCodeChallenge`` : ``code_challenge = code_verifier`` et
    ``code_challenge_method = "plain"`` (RFC 7636 §4.4.1) — c'est la
    **méthode** qui doit être rejetée, pas le verifier. Mêmes issues admises
    que ``par-ensure-pkce-required`` : ``invalid_request`` au ``/par`` ou sur
    la réponse d'autorisation, ou page d'erreur
    (``ExpectPlainPkceErrorPage``).
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier = new_verifier()
    jar = fapi_harness.jar(
        state=state, nonce=nonce, code_challenge=verifier, code_challenge_method="plain"
    )
    response = fapi_harness.push(jar)
    if response.status_code != 201:
        payload = dict(response.json())
        assert response.status_code == 400, f"POST /par : {response.text[:300]}"
        assert payload.get("error") == "invalid_request", payload
        return
    result = fapi_harness.run_flow(
        request_uri=str(response.json()["request_uri"]),
        client_id=fapi_harness.client.client_id,
    )
    outcome = _accept_outcome(result, state, ("invalid_request",))
    assert outcome != "success", "PKCE plain accepté (RFC 7636 §4.4.1)"


@pytest.mark.conformance
def test_fapi1_par_attempt_invalid_redirect_uri(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-attempt-invalid-redirect-uri`` (pushed).

    ``AddBadRedirectUriToRequestParameters`` : ``redirect_uri`` fictif
    (``https://junk.io/junk/callback``) dans le JAR signé → ``400`` au
    ``/par`` avec ``error ∈ {invalid_request, invalid_request_object}``
    (``EnsurePARInvalidRequestOrInvalidRequestObjectError``, PAR-2.3).
    ``ExpectRedirectUriErrorPage`` est du code mort dans la suite : le module
    ne fait aucune navigation.
    """
    jar = fapi_harness.jar(new_verifier(), redirect_uri="https://junk.io/junk/callback")
    response = fapi_harness.push(jar)
    payload = dict(response.json())
    assert response.status_code == 400, f"POST /par : {response.text[:300]}"
    assert payload.get("error") in ("invalid_request", "invalid_request_object"), payload


@pytest.mark.conformance
def test_fapi1_par_url_as_audience_in_request_object(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-pushed-authorization-url-as-audience…`` (pushed).

    ``AddPAREndpointAsAudToRequestObject`` (JAR-6.2, PAR-2.3) : ``aud`` du
    JAR = ``pushed_authorization_request_endpoint`` au lieu de l'issuer →
    rejet ``invalid_request_object`` au ``/par``, ou
    ``error = invalid_request_uri`` sur la réponse d'autorisation
    (``EnsureInvalidRequestUriError``), ou page d'erreur
    (``ExpectInvalidAudienceErrorPage``) — jamais de succès.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(new_verifier(), state=state, nonce=nonce, aud=fapi_harness.par_endpoint)
    response = fapi_harness.push(jar)
    if response.status_code != 201:
        payload = dict(response.json())
        assert response.status_code == 400, f"POST /par : {response.text[:300]}"
        assert payload.get("error") == "invalid_request_object", payload
        return
    result = fapi_harness.run_flow(
        request_uri=str(response.json()["request_uri"]),
        client_id=fapi_harness.client.client_id,
    )
    outcome = _accept_outcome(result, state, ("invalid_request_uri",))
    assert outcome != "success", "aud = endpoint PAR accepté (JAR-6.2)"


@pytest.mark.conformance
def test_fapi1_par_attempt_invalid_http_method(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-attempt-invalid-http-method`` (pushed).

    ``CallPAREndpoint`` rejoué en ``PUT`` (PAR-2.3.3 impose POST) : la
    condition ``EnsureParHTTPError`` attend tout status 4xx/5xx et ne
    contrôle pas le ``error`` — ``FAILURE`` seulement sur 2xx/3xx.
    """
    jar = fapi_harness.jar(new_verifier())
    response = fapi_harness.push(jar, method="PUT")
    assert 400 <= response.status_code < 600, (
        f"PUT /par : HTTP {response.status_code} attendu (PAR-2.3.3) : {response.text[:200]}"
    )


@pytest.mark.conformance
def test_fapi1_incorrect_pkce_code_verifier_rejected(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-incorrect-pkce-code-verifier-rejected`` (pushed).

    Flux PAR complet puis échange du code avec un ``code_verifier`` **neuf**
    (jamais lié au ``code_challenge`` poussé) : ``400`` +
    ``error = invalid_grant`` au token endpoint
    (``CheckErrorFromTokenEndpointResponseErrorInvalidGrant``,
    RFC 7636 §4.6), contenu JSON (``OIDCC-3.1.3.4``) — pas d'appel ressource.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization("pushed", jar)
    _check_callback(result, state=state, nonce=nonce)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi_harness.client.redirect_uri,
            "code_verifier": new_verifier(),
        }
    )
    assert response.status_code == 400, (
        f"faux code_verifier accepté ({response.status_code}) : {response.text[:300]}"
    )
    assert "application/json" in response.headers.get("content-type", ""), dict(response.headers)
    assert dict(response.json()).get("error") == "invalid_grant", response.text[:300]


@pytest.mark.conformance
def test_fapi1_ensure_pkce_code_verifier_required(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-ensure-pkce-code-verifier-required`` (pushed).

    ``addPkceCodeVerifier()`` surchargé à vide : le token endpoint reçoit une
    form **sans** ``code_verifier`` (le ``code_challenge`` S256 était présent
    au ``/par``) → ``400`` + ``error = invalid_grant``
    (``CheckErrorFromTokenEndpointResponseErrorInvalidGrant``,
    RFC 7636 §4.6) — rien n'est falsifié, le paramètre est absent.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization("pushed", jar)
    _check_callback(result, state=state, nonce=nonce)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi_harness.client.redirect_uri,
        }
    )
    assert response.status_code == 400, (
        f"code_verifier absent accepté ({response.status_code}) : {response.text[:300]}"
    )
    assert "application/json" in response.headers.get("content-type", ""), dict(response.headers)
    assert dict(response.json()).get("error") == "invalid_grant", response.text[:300]


@pytest.mark.conformance
def test_fapi1_par_request_uri_form_param_rejected(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-authorization-request-containing-request_uri-form-param``.

    ``AddBadRequestUriToRequestParameters`` (PAR-2.1) : un ``request_uri``
    en paramètre de form du POST ``/par`` en plus de ``{request}`` →
    ``400`` avec
    ``error ∈ {invalid_request, invalid_request_object, request_uri_not_supported}``
    (``EnsurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError``).
    Pushed uniquement, test terminé au ``/par``.
    """
    jar = fapi_harness.jar(new_verifier())
    response = fapi_harness.push(
        jar,
        extra={"request_uri": "urn:fdc:authlete.com:E2ooXxELkEFSKR90ymYV-BbwAvCC2TozHfSb_mMCw2s"},
    )
    payload = dict(response.json())
    assert response.status_code == 400, f"POST /par : {response.text[:300]}"
    assert payload.get("error") in (
        "invalid_request",
        "invalid_request_object",
        "request_uri_not_supported",
    ), payload


@pytest.mark.conformance
def test_fapi1_par_request_uri_claim_in_request_object(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-authorization-request-containing-request-uri``.

    ``AddBadRequestUriToAuthorizationRequest`` (PAR-2, JAR-6.2) : claim
    ``request_uri`` **dans le JAR signé** (constante de la suite, déjà
    percent-encodée) → ``400`` + ``error = invalid_request_object`` exactement
    (``EnsurePARInvalidRequestObjectError`` : un seul attendu — un OP qui
    répond ``invalid_request`` fait échouer le module, cf. commentaire du
    fichier Java).
    """
    jar = fapi_harness.jar(
        new_verifier(), request_uri="urn%3Aexample%3Abwc4JK-ESC0w8acc191e-Y1LTC2"
    )
    response = fapi_harness.push(jar)
    payload = dict(response.json())
    assert response.status_code == 400, f"POST /par : {response.text[:300]}"
    assert payload.get("error") == "invalid_request_object", payload


@pytest.mark.conformance
def test_fapi1_par_attempt_expired_request_uri(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-attempt-to-use-expired-request-uri`` (pushed).

    ``waitForExpiresIn`` : ``Thread.sleep(expires_in)`` puis réutilisation du
    ``request_uri`` expiré (skip si ``expires_in > 1800`` s, règle de la
    suite). ``invalid_request_uri`` attendu sur la réponse d'autorisation
    (``EnsureInvalidRequestUriError``, PAR-2.2) ou page d'erreur
    (``ExpectInvalidRequestUriErrorPage``) — jamais de succès. Le harness
    seed ``par_ttl_seconds=30`` borne le sommeil.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    response = fapi_harness.push(jar)
    assert response.status_code == 201, f"POST /par refusé : {response.text[:300]}"
    payload = dict(response.json())
    expires_in = int(payload["expires_in"])
    if expires_in > 1800:
        pytest.skip(f"expires_in={expires_in} > 1800 s : la suite n'attend pas l'expiration")
    time.sleep(expires_in + 1)
    result = fapi_harness.run_flow(
        request_uri=str(payload["request_uri"]),
        client_id=fapi_harness.client.client_id,
    )
    outcome = _accept_outcome(result, state, ("invalid_request_uri",))
    assert outcome != "success", "request_uri expirée acceptée (PAR-2.2)"


@pytest.mark.conformance
def test_fapi1_par_attempt_reuse_request_uri(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-attempt-reuse-request_uri`` (pushed).

    Deux visites dans le même test : visite 1 flux complet réussi (token +
    ressource), visite 2 réutilise le **même** ``request_uri`` après
    consommation. Rejet attendu : ``invalid_request_uri`` en callback
    (``EnsureInvalidRequestUriError``, PAR-2.2/JAR-7) ou page d'erreur ;
    un reuse **accepté** n'est qu'un WARNING dans la suite
    (``EnsureErrorFromAuthorizationEndpointResponse`` niveau WARNING,
    PAR-7.3) donc le succès du second callback reste admis.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    request_uri = fapi_harness.push_ok(jar)
    client_id = fapi_harness.client.client_id
    first = fapi_harness.run_flow(request_uri=request_uri, client_id=client_id)
    _complete_flow(fapi_harness, first, state=state, nonce=nonce, verifier=verifier)
    second = fapi_harness.run_flow(request_uri=request_uri, client_id=client_id)
    _accept_outcome(second, state, ("invalid_request_uri",))


def _exchange_with_mutated_assertion(
    fapi_harness: FapiHarness,
    result: FlowResult,
    verifier: str,
    **assertion_kwargs: object,
) -> httpx.Response:
    """``POST /token`` du callback avec une ``client_assertion`` mutée.

    ``assertion_kwargs`` alimentent ``FapiHarness.assertion`` (claims
    remplacés ou retirés) — les modules ``ensure-client-assertion-*-fails``
    falsifient uniquement l'assertion, la requête de jeton reste nominale.
    """
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": result.code,
        "redirect_uri": fapi_harness.client.redirect_uri,
    }
    if verifier:
        data["code_verifier"] = verifier
    return fapi_harness.token_request(data, assertion=fapi_harness.assertion(**assertion_kwargs))


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_wrong_iss_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-with-wrong-iss-fails``.

    ``AddWrongIssToClientAssertionClaims`` (RFC 7523 §3, OIDCC-9) : flux
    complet jusqu'au ``/token`` puis ``iss = "wrong-issuer-value"``
    (``sub``/``aud`` corrects) → rejet de l'assertion, aucun appel ressource.
    ``mtls`` non applicable (pas d'assertion JWT).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = _exchange_with_mutated_assertion(
        fapi_harness, result, verifier, iss="wrong-issuer-value"
    )
    _check_token_assertion_rejection(response)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_wrong_sub_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-with-wrong-sub-fails``.

    ``SetSubToWrongValueInClientAssertionClaims`` (RFC 7523 §3, OIDCC-9) :
    ``sub = "wrong-sub-value"`` (``iss``/``aud`` corrects) au ``/token`` →
    rejet, aucun appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = _exchange_with_mutated_assertion(
        fapi_harness, result, verifier, sub="wrong-sub-value"
    )
    _check_token_assertion_rejection(response)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_wrong_aud_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-with-wrong-aud-fails``.

    ``AddWrongAudToClientAssertionClaims`` (RFC 7523 §3) : ``aud`` d'un
    autre serveur (``https://fapidev-rs.authlete.net/api/userinfo``, valeur
    codée en dur de la suite) sur l'assertion ``/token`` → rejet, aucun
    appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = _exchange_with_mutated_assertion(
        fapi_harness,
        result,
        verifier,
        audience="https://fapidev-rs.authlete.net/api/userinfo",
    )
    _check_token_assertion_rejection(response)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_no_sub_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-with-no-sub-fails``.

    ``RemoveSubFromClientAssertionClaims`` : assertion **sans** ``sub`` —
    RFC 7523 §2.2 l'exige (raison d'être du test : un request object ne
    peut pas servir d'assertion) → rejet au ``/token``, aucun appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = _exchange_with_mutated_assertion(fapi_harness, result, verifier, remove=("sub",))
    _check_token_assertion_rejection(response)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_exp_in_past_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``…-ensure-client-assertion-with-exp-is-5-minutes-in-past-fails``.

    ``AddExpIs5MinutesInPastToClientAssertionClaims`` : ``exp = now - 300 s``
    sur l'assertion ``/token`` → rejet (RFC 7523 §2.1 : ``exp`` périmé),
    aucun appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = _exchange_with_mutated_assertion(
        fapi_harness, result, verifier, exp=int(time.time()) - 300
    )
    _check_token_assertion_rejection(response)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_response_type_code_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-response-type-code-fails``.

    ``butFirst`` pose ``response_type=code`` (sans ``response_mode``) dans la
    requête d'autorisation : FAPI1-ADV-5.2.2-2 n'admet que ``code id_token``
    (hybride) ou ``code`` + JARM. Issues admises : rejet ``400`` au ``/par``
    avec ``error ∈ {unsupported_response_type, invalid_request, unauthorized_client}``
    (variante ``pushed``), callback en erreur avec
    ``error ∈ {unsupported_response_type, invalid_request}`` (``state`` repris,
    ``EnsureUnsupportedResponseTypeOrInvalidRequestError``) ou page d'erreur
    (``ExpectResponseTypeErrorPage``) — jamais de ``code``
    (``RejectAuthCodeInUrlQuery`` / ``…InUrlFragment``, FAPI1-ADV-5.2.2-2).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, response_type="code")
    if method == "pushed":
        response = fapi_harness.push(jar)
        if response.status_code != 201:
            payload = dict(response.json())
            assert response.status_code == 400, f"POST /par : {response.text[:300]}"
            assert payload.get("error") in (
                "unsupported_response_type",
                "invalid_request",
                "unauthorized_client",
            ), payload
            return
        result = fapi_harness.run_flow(
            request_uri=str(response.json()["request_uri"]),
            client_id=fapi_harness.client.client_id,
        )
    else:
        result = fapi_harness.start_authorization("by_value", jar, response_type="code")
    assert not result.query.get("code") and not result.fragment.get("code"), (
        f"code retourné pour response_type=code (FAPI1-ADV-5.2.2-2) : {result.callback_url!r}"
    )
    outcome = _accept_outcome(result, state, ("unsupported_response_type", "invalid_request"))
    assert outcome != "success", "response_type=code accepté (FAPI1-ADV-5.2.2-2)"


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_without_exp_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-without-exp-fails``.

    ``AddExpToRequestObject`` sauté : le JAR n'a pas de claim ``exp``
    (FAPI1-ADV-5.2.2-13). Issues admises : ``400`` + ``invalid_request_object``
    au ``/par``, callback en erreur (sans ``invalid_request_object`` sous
    ``pushed`` — ``EnsureInvalidRequestInvalidRequestUriOrAccessDeniedError``)
    ou page d'erreur (``ExpectRequestObjectMissingExpClaimErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, remove=("exp",))
    callback = (
        ("invalid_request", "invalid_request_uri", "access_denied")
        if method == "pushed"
        else _CALLBACK_ERRORS_4
    )
    _run_rejected_jar(fapi_harness, method, jar, state, ("invalid_request_object",), callback)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_without_nbf_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-without-nbf-fails``.

    ``AddNbfToRequestObject`` sauté : le JAR n'a pas de claim ``nbf``
    (FAPI1-ADV-5.2.2-17, JAR-6.3). Mêmes issues admises que le module
    « sans ``exp`` » : ``400`` + ``invalid_request_object`` au ``/par``,
    callback en erreur (bifurcation ``pushed``/``by_value``) ou page
    d'erreur (``ExpectRequestObjectMissingNbfClaimErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, remove=("nbf",))
    callback = (
        ("invalid_request", "invalid_request_uri", "access_denied")
        if method == "pushed"
        else _CALLBACK_ERRORS_4
    )
    _run_rejected_jar(fapi_harness, method, jar, state, ("invalid_request_object",), callback)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_without_scope_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-without-scope-fails``.

    ``RemoveScopeFromRequestObject`` retire ``scope`` des claims du JAR alors
    qu'il reste dupliqué hors JAR en ``by_value`` (FAPI1-ADV-5.2.3-8).
    Issues admises : ``400`` + ``error ∈ {invalid_request, invalid_request_object}``
    au ``/par``, callback avec les 4 erreurs admises (sans bifurcation,
    ``invalid_request_object`` y compris sous ``pushed``) ou page d'erreur
    (``ExpectRequestObjectMissingScopeErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, remove=("scope",))
    _run_rejected_jar(
        fapi_harness,
        method,
        jar,
        state,
        ("invalid_request", "invalid_request_object"),
        _CALLBACK_ERRORS_4,
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_state_only_outside_request_object(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-state-only-outside-request-object-not-used``.

    ``AddStateToAuthorizationEndpointRequest`` sauté avant la conversion puis
    ré-inséré **après** signature : le JAR n'a pas de claim ``state`` mais la
    query porte ``state=…``. Variante **succès** du module : le callback ne
    doit contenir ni ``state`` ni ``s_hash``
    (``VerifyNoStateInAuthorizationResponse``, ``VerifyNoSHash``,
    FAPI1-ADV-5.2.2-10 — l'AS doit ignorer le ``state`` hors JAR), puis
    token + ressource. Issues admises aussi : page d'erreur
    (``ExpectRequestObjectMissingStateErrorPage``) ou callback en ``error`` ∈
    les 4 erreurs admises (``state`` y optionnel). Sous ``pushed`` le PAR
    doit accepter : le parent de ce module n'est pas PAR-tolérant.
    """
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier = new_verifier() if method == "pushed" else ""
    jar = fapi_harness.jar(verifier, remove=("state",), nonce=nonce)
    if method == "pushed":
        request_uri = fapi_harness.push_ok(jar)
        result = fapi_harness.run_flow(
            request_uri=request_uri, client_id=fapi_harness.client.client_id, state=state
        )
    else:
        result = fapi_harness.start_authorization("by_value", jar, state=state)
    if result.error:
        assert result.error in _CALLBACK_ERRORS_4, result.error
        assert not result.code, f"code avec erreur : {result.callback_url!r}"
        return
    if not result.callback_url:
        assert result.status_code and result.body, f"ni callback ni page (hops : {result.hops})"
        return
    claims = _check_callback(result, state="", nonce=nonce)
    assert "s_hash" not in claims, "s_hash émis alors que le state hors JAR doit être ignoré"
    _complete_flow(fapi_harness, result, state="", nonce=nonce, verifier=verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_without_nonce_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-without-nonce-fails``.

    Le ``nonce`` n'entre **pas** dans le JAR mais est ajouté après signature,
    donc seulement hors JAR (FAPI1-ADV-5.2.3-8) : l'AS qui lit ``nonce`` hors
    ``request`` doit rejeter. Issues admises : ``400`` + ``error ∈ {invalid_request,
    invalid_request_object}`` au ``/par``, callback en ``error`` ∈
    ``{invalid_request, invalid_request_object, invalid_request_uri}``
    (**pas** d'``access_denied``) ou page d'erreur
    (``ExpectRequestObjectMissingNonceErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, remove=("nonce",))
    _run_rejected_jar(
        fapi_harness,
        method,
        jar,
        state,
        ("invalid_request", "invalid_request_object"),
        ("invalid_request", "invalid_request_object", "invalid_request_uri"),
        nonce=nonce,
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_without_redirect_uri_fails(
    fapi_harness: FapiHarness, method: str
) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-without-redirect-uri-fails``.

    ``RemoveRedirectUriFromRequestObject`` : ``redirect_uri`` reste hors JAR
    (doublon obligatoire en ``by_value``) mais absent du JAR signé
    (FAPI1-ADV-5.2.3-8, JAR-6.2). Issues admises — liste la plus étroite du
    batch : ``400`` + ``error ∈ {invalid_request, invalid_request_object}``
    au ``/par``, callback **uniquement** ``invalid_request_object`` ou
    ``invalid_request``, ou page d'erreur
    (``ExpectRequestObjectMissingRedirectUriErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, remove=("redirect_uri",))
    _run_rejected_jar(
        fapi_harness,
        method,
        jar,
        state,
        ("invalid_request", "invalid_request_object"),
        ("invalid_request_object", "invalid_request"),
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_expired_request_object_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-expired-request-object-fails``.

    ``AddExpiredExpToRequestObject`` : ``exp = now - 3600`` (RFC 7519 §4.1.4).
    Issues admises : ``400`` + ``invalid_request_object`` au ``/par``,
    callback avec ``error = invalid_request_object`` **strictement** (aucune
    bifurcation, y compris sous ``pushed``) ou page d'erreur
    (``ExpectExpiredRequestObjectClaimErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, exp=int(time.time()) - 3600)
    _run_rejected_jar(
        fapi_harness, method, jar, state, ("invalid_request_object",), ("invalid_request_object",)
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_bad_aud_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-bad-aud-fails``.

    ``AddBadAudToRequestObject`` : ``aud = "https://www.other1.example.com/"``
    (OIDC Core 1.0 §6.1, RFC 7519 §4.1.3). Issues admises : ``400`` +
    ``invalid_request_object`` au ``/par``, callback ``invalid_request_uri``
    **strict** sous ``pushed`` (JAR-4) mais ``invalid_request_object`` strict
    en ``by_value``, ou page d'erreur
    (``ExpectRequestObjectWithBadAudClaimErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(
        verifier, state=state, nonce=nonce, aud="https://www.other1.example.com/"
    )
    callback = ("invalid_request_uri",) if method == "pushed" else ("invalid_request_object",)
    _run_rejected_jar(fapi_harness, method, jar, state, ("invalid_request_object",), callback)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_exp_over_60_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-exp-over-60-fails``.

    ``exp = now + 70 min`` avec ``nbf = now`` : écart ``exp - nbf`` supérieur
    aux 60 min tolérées (FAPI1-ADV-5.2.2-13). Issues admises : ``400`` +
    ``invalid_request_object`` au ``/par``, callback ``invalid_request_uri``
    strict sous ``pushed`` / ``invalid_request_object`` strict en ``by_value``,
    ou page d'erreur (``Expect…ExpOver60ClaimErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, exp=int(time.time()) + 70 * 60)
    callback = ("invalid_request_uri",) if method == "pushed" else ("invalid_request_object",)
    _run_rejected_jar(fapi_harness, method, jar, state, ("invalid_request_object",), callback)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_nbf_over_60_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-nbf-over-60-fails``.

    ``nbf = now - 70 min`` alors que ``exp = now + 300`` : ``nbf`` remonte de
    plus de 60 min (OIDC Core 1.0 §6.1, RFC 7519 §4.1.5). Issues admises
    identiques au module ``exp-over-60`` : ``400`` + ``invalid_request_object``
    au ``/par``, bifurcation ``invalid_request_uri`` (``pushed``) /
    ``invalid_request_object`` (``by_value``) au callback, ou page d'erreur.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, nbf=int(time.time()) - 70 * 60)
    callback = ("invalid_request_uri",) if method == "pushed" else ("invalid_request_object",)
    _run_rejected_jar(fapi_harness, method, jar, state, ("invalid_request_object",), callback)


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_alg_none_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-signature-algorithm-is-not-none``.

    JAR ``alg=none`` (FAPI1-ADV-8.6 n'admet que PS256/ES256, FAPI1-ADV-5.2.3.1-3)
    : le header doit être rejeté même si les claims sont corrects. Issues
    admises : ``400`` + ``invalid_request_object`` au ``/par``, callback
    ``invalid_request_object`` **strict** (aucune bifurcation) ou page
    d'erreur (``ExpectRequestObjectUnverifiableErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, algorithm="none")
    _run_rejected_jar(
        fapi_harness, method, jar, state, ("invalid_request_object",), ("invalid_request_object",)
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_rs256_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-signed-request-object-with-RS256-fails``.

    JAR signé **RS256** alors que la clé enregistrée est ``PS256``
    (FAPI1-ADV-8.6) : l'AS doit comparer l'``alg`` signé à l'``alg``
    enregistré. Issues admises : ``400`` + ``invalid_request_object`` au
    ``/par``, callback ``invalid_request_object`` strict ou page d'erreur
    (``ExpectSignedRS256RequestObjectErrorPage``). Pas de skip : les clients
    FAPI du harness sont en PS256 (la suite saute avec des clés ES256).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce, algorithm="RS256")
    _run_rejected_jar(
        fapi_harness, method, jar, state, ("invalid_request_object",), ("invalid_request_object",)
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_request_object_invalid_signature_fails(
    fapi_harness: FapiHarness, method: str
) -> None:
    """Module ``fapi1-advanced-final-ensure-request-object-with-invalid-signature-fails``.

    ``InvalidateRequestObjectSignature`` : tous les octets de la signature
    JWS sont inversés (``bytes[i] ^= 0x5A``) — header et claims intacts, le
    JWT reste parsable mais la vérification échoue. Issues admises : ``400`` +
    ``invalid_request_object`` au ``/par``, callback ``invalid_request_object``
    strict ou page d'erreur
    (``ExpectRequestObjectInvalidSignatureErrorPage``).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    header, payload, signature = jar.split(".")
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    broken = base64.urlsafe_b64encode(bytes(byte ^ 0x5A for byte in raw))
    tampered = f"{header}.{payload}.{broken.rstrip(b'=').decode('ascii')}"
    _run_rejected_jar(
        fapi_harness,
        method,
        tampered,
        state,
        ("invalid_request_object",),
        ("invalid_request_object",),
    )


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_id_in_token_endpoint(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-client-id-in-token-endpoint``.

    ``AddClientIdToRequest`` (FAPI1-BASE-5.2.2-19) : le code émis pour le
    client 1 est présenté avec l'assertion du **client 2** — la suite poste
    en plus ``client_id=client2`` avec une assertion signée clé client 1
    (déséquilibre volontaire ``client``/``client_jwks``). Issues admises :
    ``400`` (``401`` pour ``invalid_client``) + ``error ∈ {invalid_client,
    invalid_grant}`` — les specs ne définissent pas l'ordre entre
    l'authentification client et la liaison du code. Pas d'appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    fapi_harness.switch(FAPI_CLIENT_2)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": FAPI_CLIENT_1.redirect_uri,
            **({"code_verifier": verifier} if verifier else {}),
        },
        assertion=fapi_harness.assertion(kid=FAPI_CLIENT_1.kid, key=FAPI_CLIENT_1.private_key),
    )
    fapi_harness.switch(FAPI_CLIENT_1)
    _check_token_error(response, ("invalid_client", "invalid_grant"))


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_authorization_code_bound_to_client(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-authorization-code-is-bound-to-client``.

    L'identité du client 1 est authentifiée sans faute côté callback, puis le
    **même** code est échangé avec les credentials valides du client 2
    (assertion ``iss``/``sub`` = client 2, clé client 2) : la liaison du code
    (FAPI1-ADV-5.2.2-6) impose ``400`` + ``error = invalid_grant``
    **strictement** — contrairement au module ``client-id-in-token-endpoint``,
    l'authentification ici réussit, seul le code lie. Pas d'appel ressource.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    fapi_harness.switch(FAPI_CLIENT_2)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": FAPI_CLIENT_1.redirect_uri,
            **({"code_verifier": verifier} if verifier else {}),
        }
    )
    fapi_harness.switch(FAPI_CLIENT_1)
    _check_token_error(response, ("invalid_grant",))


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_missing_in_token_endpoint(
    fapi_harness: FapiHarness, method: str
) -> None:
    """Module ``fapi1-advanced-final-ensure-client-assertion-in-token-endpoint``.

    ``addClientAuthenticationToTokenEndpointRequest()`` réduit à
    ``AddClientIdToRequest`` : la form du ``/token`` porte ``client_id`` mais
    **aucune** ``client_assertion``, alors que le client FAPI s'authentifie en
    ``private_key_jwt`` (FAPI1-BASE-5.2.2-19). Issues admises : ``400``
    (``401`` pour ``invalid_client``) + ``error ∈ {invalid_client,
    invalid_request}``. ``mtls`` non applicable (module ``private_key_jwt``
    uniquement).
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi_harness.client.redirect_uri,
            "code_verifier": verifier,
            "client_id": fapi_harness.client.client_id,
        },
        auth_method="none",
    )
    _check_token_error(response, ("invalid_client", "invalid_request"))


@pytest.mark.conformance
@pytest.mark.parametrize("method", ["by_value", "pushed"])
def test_fapi1_client_assertion_rs256_fails(fapi_harness: FapiHarness, method: str) -> None:
    """Module ``fapi1-advanced-final-ensure-signed-client-assertion-with-RS256-fails``.

    ``ChangeClientJwksAlgToRS256`` puis ``SignClientAuthenticationAssertion`` :
    la ``client_assertion`` est présente et bien signée mais en **RS256**,
    algorithme interdit par FAPI1-ADV-8.6 (PS256/ES256 exigés) — rejet attendu
    ``invalid_client`` **strict** (``invalid_grant`` non admis ici), ``400``
    ou ``401``. Pas de skip : les clients du harness sont en PS256.
    """
    verifier = new_verifier() if method == "pushed" else ""
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    result = fapi_harness.start_authorization(method, jar)
    _check_callback(result, state=state, nonce=nonce)
    response = fapi_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi_harness.client.redirect_uri,
            "code_verifier": verifier,
        },
        assertion=fapi_harness.assertion(algorithm="RS256"),
    )
    _check_token_error(response, ("invalid_client",))


@pytest.mark.conformance
def test_fapi1_par_request_uri_bound_to_client(fapi_harness: FapiHarness) -> None:
    """Module ``fapi1-advanced-final-par-attempt-to-use-request_uri-for-different-client``.

    ``request_uri`` poussée par le client 1 puis présentée par le **client 2**
    (``AddClientIdToAuthorizationEndpointRequest``, PAR-2.2.1 : le
    ``request_uri`` doit être lié au client qui l'a poussé). Issues admises :
    ``error ∈ {invalid_request, invalid_request_object, invalid_request_uri}``
    au callback (PAR-3-3) ou page d'erreur (``ExpectInvalidRequestUriErrorPage``)
    — **jamais** de code (le serveur ne doit pas autoriser l'échange).
    Pushed uniquement.
    """
    verifier = new_verifier()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    jar = fapi_harness.jar(verifier, state=state, nonce=nonce)
    request_uri = fapi_harness.push_ok(jar)
    fapi_harness.switch(FAPI_CLIENT_2)
    result = fapi_harness.run_flow(request_uri=request_uri, client_id=FAPI_CLIENT_2.client_id)
    fapi_harness.switch(FAPI_CLIENT_1)
    assert not result.query.get("code") and not result.fragment.get("code"), (
        f"code retourné pour un request_uri d'un autre client : {result.callback_url!r}"
    )
    outcome = _accept_outcome(
        result,
        state,
        ("invalid_request", "invalid_request_object", "invalid_request_uri"),
    )
    assert outcome != "success", "request_uri d'un autre client acceptée (PAR-2.2.1)"
