"""Rejeu local des modules FAPI-CIBA-ID1 (issue #109).

``fapi-ciba-id1-test-plan`` (release-v5.2.4) publie 66 modules ; la variante
locale ``private_key_jwt`` + ``poll`` + ``plain_fapi`` en rend 34 applicables
(21 ConnectID, 5 ping, 2 modules Brésil, 4 modules mTLS / hors-variante sont
exclus par ``@VariantNotApplicable`` / ``@VariantSetup``). Chaque test rejoue
les checks lus dans les fichiers Java du clone lecture seule (matrice dans
``TRACEABILITY.md``), jamais la spécification seule.

Écarts assumés (issues #110/#111, détaillés TRACEABILITY) :

- ``CheckTLSClientCertificateBoundAccessTokensTrue`` et le cross-check
  « jeton du client 2 avec les clés du client 1 » supposent des jetons
  contraints par certificat (RFC 8705) : non assertés ;
- ``acr_values_supported`` absent du discovery : la suite saute ses étapes
  ACR (``skipIfElementMissing``), ``requested_acr`` reste vide ;
- les sleeps d'intervalle de la suite sont supprimés (les erreurs sont
  assertées, pas leur instant) ; seules les attentes temporelles utiles
  subsistent (expiration de l'``auth_req_id``, distanciation des ``iat``).
"""

from __future__ import annotations

import secrets
import time
from typing import Any, cast

import pytest
from checks import (
    check_backchannel_ack,
    check_backchannel_error,
    check_ciba_id_token,
    check_ciba_id_token_header,
    check_ciba_token_success,
    check_fapi_ciba_discovery,
    check_pending_or_slowdown,
    check_protected_resource,
    check_refreshed_id_token_claims,
    check_token_error,
)
from ciba_harness import (
    BINDING_MESSAGE,
    CIBA_GRANT,
    CLIENT_SCOPE,
    HINT_VALUE,
    CibaClient,
    CibaHarness,
)
from harness import decode_id_token_claims

# Constante ``AddPotentiallyBadBindingMessageToAuthorizationEndpointRequest.
# POTENTIALLY_BAD_BINDING_MESSAGE`` (émojis = paires de surrogates Java).
_POTENTIALLY_BAD_BINDING_MESSAGE = (
    "1234 \U0001f44d\U0001f3ff ?? Lorem ipsum dolor sit amet, consectetur "
    "adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore "
    "magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco "
    "laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
    "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa "
    "qui officia deserunt mollit anim id est laborum."
)

# Erreurs admises par ``CheckErrorFromBackchannelAuthenticationEndpointError``
# (modules « sans assertion » / assertion RS256 côté ``/bc-authorize``) et
# statuts de ``CheckBackchannelAuthenticationEndpointErrorHttpStatus``
# (``invalid_request`` → 400, ``access_denied`` → 403, ``invalid_client`` →
# 400/401).
_BC_GENERIC_ERRORS = ("access_denied", "invalid_request", "invalid_client")
_BC_GENERIC_STATUSES = (400, 401, 403)

# Modules ``fapi-ciba-id1-ensure-request-object-*-fails`` : 16 mutations,
# une par ligne du plan (``@VariantNotApplicable`` exclus).
_NEGATIVE_CASES: tuple[str, ...] = (
    "missing-aud",
    "bad-aud",
    "missing-iss",
    "bad-iss",
    "missing-exp",
    "expired-exp",
    "exp-70-minutes",
    "missing-iat",
    "missing-nbf",
    "nbf-10-minutes",
    "nbf-70-minutes",
    "missing-jti",
    "alg-none",
    "alg-bad",
    "alg-rs256",
    "signed-by-other-client",
)

# Claims retirés (``Remove*FromRequestObject``) et valeurs étrangères
# (``AddBadAud`` / ``AddBadIss`` : « une URL valide, mais pas celle du
# serveur »).
_REMOVALS: dict[str, str] = {
    "missing-aud": "aud",
    "missing-iss": "iss",
    "missing-exp": "exp",
    "missing-iat": "iat",
    "missing-nbf": "nbf",
    "missing-jti": "jti",
}
_FOREIGN_AUD = "https://rp.example.invalid"
_FOREIGN_ISS = "https://issuer.example.invalid"

# Claims à valeur étrangère (``AddBadAud``/``AddBadIss``), bornes temporelles
# (``AddExpiredExp``, ``AddExpValueIs70Minutes``, ``AddNbf*``) et algénérations
# du JAR (``SerializeRequestObjectWith{NullAlgorithm,RS256}``) : tables
# pures, une entrée par module.
_FOREIGN_CLAIMS: dict[str, tuple[str, str]] = {
    "bad-aud": ("aud", _FOREIGN_AUD),
    "bad-iss": ("iss", _FOREIGN_ISS),
}
_TIME_CLAIMS: dict[str, tuple[str, int]] = {
    "expired-exp": ("exp", -60),
    "exp-70-minutes": ("exp", 70 * 60),
    "nbf-10-minutes": ("nbf", 10 * 60),
    "nbf-70-minutes": ("nbf", -70 * 60),
}
_ALGORITHMS: dict[str, str] = {"alg-none": "none", "alg-rs256": "RS256"}


def _start_authentication(
    harness: CibaHarness,
    client: CibaClient,
    *,
    jar: str = "",
    ack_expires_in: int | None = None,
    **jar_overrides: object,
) -> str:
    """Acquittement puis deux polls en attente.

    ``performValidateAuthorizationResponse`` +
    ``performPostAuthorizationResponse`` (``pending`` puis ``slow_down`` sans
    sleep d'intervalle : les deux erreurs sont admises).
    """
    request = jar or harness.jar(client, **cast(dict[str, Any], jar_overrides))
    ack = check_backchannel_ack(harness.bc_authorize(harness.bc_form(client, request)))
    auth_req_id = str(ack["auth_req_id"])
    if ack_expires_in is not None:
        assert ack["expires_in"] == ack_expires_in, (
            f"expires_in={ack['expires_in']} != requested_expiry {ack_expires_in}"
        )
    check_pending_or_slowdown(harness.poll(client, auth_req_id))
    check_pending_or_slowdown(harness.poll(client, auth_req_id))
    return auth_req_id


def _finish_authentication(
    harness: CibaHarness,
    client: CibaClient,
    auth_req_id: str,
    *,
    requested_acr: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Approbation puis poll jusqu'aux jetons.

    ``callAutomatedEndpoint`` + ``waitForPollingAuthenticationToComplete`` +
    ``handleSuccessfulTokenEndpointResponse`` + contrôles d'id_token
    (``PerformStandardIdTokenChecks``).
    """
    decision = harness.approve(auth_req_id, "allow")
    assert decision.status_code < 300, (
        f"approbation refusée : HTTP {decision.status_code} {decision.text[:200]}"
    )
    tokens = check_ciba_token_success(harness.poll(client, auth_req_id), expect_refresh=True)
    id_token = str(tokens["id_token"])
    check_ciba_id_token_header(id_token)
    claims = decode_id_token_claims(id_token)
    check_ciba_id_token(
        claims,
        issuer=harness.issuer,
        client_id=client.client_id,
        requested_acr=requested_acr,
        auth_req_id=auth_req_id,
    )
    return tokens, claims


def _check_resource(harness: CibaHarness, tokens: dict[str, Any]) -> dict[str, Any]:
    """``requestProtectedResource`` : Bearer + ``x-fapi-interaction-id`` échoyé."""
    claims = decode_id_token_claims(str(tokens["id_token"]))
    interaction_id = secrets.token_urlsafe(16)
    response = harness.resource(str(tokens["access_token"]), interaction_id=interaction_id)
    return check_protected_resource(
        response,
        interaction_id=interaction_id,
        subject=str(claims["sub"]),
        expect_date=harness.remote,
    )


def _negative_jar_kwargs(case: str, harness: CibaHarness) -> dict[str, Any]:
    """Mutations des 16 modules ``...RequestObject...Fails`` pour ``jar()``."""
    if case in _REMOVALS:
        return {"remove": (_REMOVALS[case],)}
    if case in _FOREIGN_CLAIMS:
        claim, value = _FOREIGN_CLAIMS[case]
        return {claim: value}
    if case in _TIME_CLAIMS:
        claim, offset = _TIME_CLAIMS[case]
        return {claim: int(time.time()) + offset}
    if case in _ALGORITHMS:
        return {"algorithm": _ALGORITHMS[case]}
    if case == "alg-bad":
        return {}
    other = harness.register(name=f"jar-other-{secrets.token_hex(3)}")
    return {"key": other.private_key, "kid": other.kid}


def _corrupt_signature(token: str) -> str:
    """Corrompt la signature d'un JAR — ``InvalidateRequestObjectSignature``."""
    header, payload, signature = token.split(".")
    replacement = "A" if signature[-1] != "A" else "B"
    return f"{header}.{payload}.{signature[:-1]}{replacement}"


@pytest.mark.conformance
def test_ciba_discovery_endpoint_verification(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-discovery-end-point-verification``."""
    check_fapi_ciba_discovery(ciba_harness.discovery())


@pytest.mark.conformance
def test_ciba_happy_flow_two_clients(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1`` (« Two client test »).

    Deux clients authentifiés successivement ; le second envoie
    ``requested_expiry=300`` (``AddRequestedExp300SToAuthorizationEndpointRequest``)
    et signe avec l'en-tête ``typ`` « OautH-auThZ-REQ+jWt »
    (``SignRequestObjectIncludeMediaType``). La réutilisation de
    l'``auth_req_id`` du second client échoue en ``invalid_grant`` (CIBA-11).
    Les étapes TLS / jeton contraint par certificat sont écartées (issue #110).
    """
    client1 = ciba_harness.register(name="ciba-happy-1")
    auth1 = _start_authentication(ciba_harness, client1)
    tokens1, _claims1 = _finish_authentication(ciba_harness, client1, auth1)
    _check_resource(ciba_harness, tokens1)

    client2 = ciba_harness.register(name="ciba-happy-2")
    jar2 = ciba_harness.jar(
        client2,
        headers={"typ": "OautH-auThZ-REQ+jWt"},
        requested_expiry=300,
    )
    auth2 = _start_authentication(ciba_harness, client2, jar=jar2, ack_expires_in=300)
    tokens2, _claims2 = _finish_authentication(ciba_harness, client2, auth2)
    _check_resource(ciba_harness, tokens2)

    check_token_error(
        ciba_harness.poll(client2, auth2),
        ("invalid_grant",),
        status_code=400,
    )


@pytest.mark.conformance
def test_ciba_user_rejects_authentication(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-user-rejects-authentication`` (``request_action=deny``)."""
    client = ciba_harness.register(name="ciba-reject")
    auth_req_id = _start_authentication(ciba_harness, client)
    denial = ciba_harness.approve(auth_req_id, "deny")
    assert denial.status_code < 300, (
        f"refus non accepté : HTTP {denial.status_code} {denial.text[:200]}"
    )
    check_token_error(
        ciba_harness.poll(client, auth_req_id),
        ("access_denied",),
        status_code=400,
    )


@pytest.mark.conformance
def test_ciba_multiple_calls_to_token_endpoint(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-multiple-call-to-token-endpoint`` (20 polls).

    Chaque appel doit rester non-200 avec ``authorization_pending`` ou
    ``slow_down`` (``multipleCallToTokenEndpointAndVerifyResponse``).
    """
    client = ciba_harness.register(name="ciba-multicall")
    auth_req_id = _start_authentication(ciba_harness, client)
    errors = {check_pending_or_slowdown(ciba_harness.poll(client, auth_req_id))}
    for _ in range(18):
        errors.add(check_pending_or_slowdown(ciba_harness.poll(client, auth_req_id)))
    assert errors <= {"authorization_pending", "slow_down"}, sorted(errors)


@pytest.mark.conformance
def test_ciba_auth_req_id_expired(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-auth-req-id-expired`` (``requested_expiry`` 10 s).

    ``SleepUntilAuthReqExpires`` : la suite dort jusqu'à l'expiration de
    l'``auth_req_id`` puis attend ``expired_token`` (CIBA-11). Les deux polls
    en attente précèdent le sommeil (les sleeps d'intervalle sont supprimés).
    """
    client = ciba_harness.register(name="ciba-expired")
    auth_req_id = _start_authentication(
        ciba_harness, client, requested_expiry=10, ack_expires_in=10
    )
    time.sleep(11)
    check_token_error(
        ciba_harness.poll(client, auth_req_id),
        ("expired_token",),
        status_code=400,
    )


@pytest.mark.conformance
def test_ciba_binding_message_succeeds(ciba_harness: CibaHarness) -> None:
    """Module ``...with-binding-message-succeeds`` (« 1234 », FAPI-CIBA-5.2.2-2)."""
    assert BINDING_MESSAGE == "1234", BINDING_MESSAGE
    client = ciba_harness.register(name="ciba-binding")
    auth_req_id = _start_authentication(ciba_harness, client)
    tokens, _claims = _finish_authentication(ciba_harness, client, auth_req_id)
    _check_resource(ciba_harness, tokens)


@pytest.mark.conformance
def test_ciba_other_scope_order_succeeds(ciba_harness: CibaHarness) -> None:
    """Module ``...other-scope-order-succeeds`` (RFC6749-3.3 : l'ordre n'a pas d'effet)."""
    client = ciba_harness.register(name="ciba-scope-order")
    reversed_scope = " ".join(reversed(CLIENT_SCOPE.split()))
    auth_req_id = _start_authentication(ciba_harness, client, scope=reversed_scope)
    tokens, _claims = _finish_authentication(ciba_harness, client, auth_req_id)
    _check_resource(ciba_harness, tokens)


@pytest.mark.conformance
def test_ciba_requested_expiry_as_string_succeeds(
    ciba_harness: CibaHarness,
) -> None:
    """Module ``...requested-expiry-as-string-succeeds`` (CIBA-7.1.1).

    ``requested_expiry`` est accepté en chaîne ou en nombre :
    ``expires_in`` vaut 30.
    """
    client = ciba_harness.register(name="ciba-expiry-string")
    auth_req_id = _start_authentication(
        ciba_harness, client, requested_expiry="30", ack_expires_in=30
    )
    tokens, _claims = _finish_authentication(ciba_harness, client, auth_req_id)
    _check_resource(ciba_harness, tokens)


@pytest.mark.conformance
def test_ciba_potentially_bad_binding_message(ciba_harness: CibaHarness) -> None:
    """Module ``...potentially-bad-binding-message`` (CIBA-13 / CIBA-7.1).

    L'OP doit soit rejeter ``invalid_binding_message``, soit accepter le
    message long et authentifier l'utilisateur (la suite attend alors une
    capture de l'affichage — ``ExpectBindingMessageCorrectDisplay``).
    """
    client = ciba_harness.register(name="ciba-bad-binding")
    jar = ciba_harness.jar(client, binding_message=_POTENTIALLY_BAD_BINDING_MESSAGE)
    response = ciba_harness.bc_authorize(ciba_harness.bc_form(client, jar))
    if response.status_code >= 400:
        check_backchannel_error(response, ("invalid_binding_message",))
        return
    auth_req_id = str(check_backchannel_ack(response)["auth_req_id"])
    check_pending_or_slowdown(ciba_harness.poll(client, auth_req_id))
    tokens, _claims = _finish_authentication(ciba_harness, client, auth_req_id)
    _check_resource(ciba_harness, tokens)


@pytest.mark.conformance
@pytest.mark.parametrize("case", _NEGATIVE_CASES)
def test_ciba_request_object_negative(ciba_harness: CibaHarness, case: str) -> None:
    """Modules ``fapi-ciba-id1-ensure-request-object-*-fails`` (16 cas).

    ``AbstractFAPICIBAID1EnsureSendingInvalidBackchannelAuthorizationRequest`` :
    ``invalid_request`` en 400 sur ``/bc-authorize`` (CIBA-13).
    """
    client = ciba_harness.register(name=f"neg-{case}")
    jar = ciba_harness.jar(client, **_negative_jar_kwargs(case, ciba_harness))
    if case == "alg-bad":
        jar = _corrupt_signature(jar)
    response = ciba_harness.bc_authorize(ciba_harness.bc_form(client, jar))
    check_backchannel_error(response, ("invalid_request",))


@pytest.mark.conformance
def test_ciba_multiple_hints_fails(ciba_harness: CibaHarness) -> None:
    """Module ``...with-multiple-hints-fails`` (CIBA-7.2-3 : deux hints)."""
    client = ciba_harness.register(name="ciba-multi-hints")
    jar = ciba_harness.jar(
        client,
        login_hint="join@example.com",
        login_hint_token="xxxxxxxxxxxxxxxxxxxx",
    )
    response = ciba_harness.bc_authorize(ciba_harness.bc_form(client, jar))
    check_backchannel_error(response, ("invalid_request",))


@pytest.mark.conformance
def test_ciba_wrong_auth_req_id_fails(ciba_harness: CibaHarness) -> None:
    """Module ``...wrong-auth-req-id-in-token-endpoint-request`` (RFC6749-5.2).

    L'``auth_req_id`` du client 1 présenté par le client 2 → ``invalid_grant``.
    """
    client1 = ciba_harness.register(name="ciba-wrong-1")
    client2 = ciba_harness.register(name="ciba-wrong-2")
    auth_req_id = _start_authentication(ciba_harness, client1)
    check_token_error(
        ciba_harness.poll(client2, auth_req_id),
        ("invalid_grant",),
        status_code=400,
    )


@pytest.mark.conformance
@pytest.mark.parametrize("endpoint", ("backchannel", "token"))
def test_ciba_without_client_assertion_fails(ciba_harness: CibaHarness, endpoint: str) -> None:
    """Modules ``...without-client-assertion-in-{backchannel,token}-endpoint-request``.

    ``client_id`` à la place de l'assertion : ``access_denied`` /
    ``invalid_request`` / ``invalid_client`` sur ``/bc-authorize`` et
    ``invalid_client`` / ``invalid_request`` sur ``/token`` (400/401).
    """
    client = ciba_harness.register(name=f"no-assertion-{endpoint}")
    if endpoint == "backchannel":
        form = ciba_harness.bc_form(client, ciba_harness.jar(client), with_assertion=False)
        form["client_id"] = client.client_id
        check_backchannel_error(
            ciba_harness.bc_authorize(form),
            _BC_GENERIC_ERRORS,
            allow_statuses=_BC_GENERIC_STATUSES,
        )
        return
    auth_req_id = _start_authentication(ciba_harness, client)
    check_token_error(
        ciba_harness.poll(client, auth_req_id, with_assertion=False),
        ("invalid_client", "invalid_request"),
        status_code=None,
        allow_statuses=(400, 401),
    )


@pytest.mark.conformance
@pytest.mark.parametrize("endpoint", ("backchannel", "token"))
def test_ciba_client_assertion_rs256_fails(ciba_harness: CibaHarness, endpoint: str) -> None:
    """Modules « assertion RS256 » côté ``/bc-authorize`` et ``/token`` (7.10).

    ``...client-assertion-signature-algorithm-in-{backchannel,token}
    -authorization-request-is-RS256-fails``. La suite signe l'assertion en
    RS256 (``ChangeClientJwksAlgToRS256``) alors que le JWKS enregistré porte
    ``alg=PS256`` : l'OP doit refuser (``invalid_client`` sur ``/token``,
    erreur générique CIBA-13 sur ``/bc-authorize``).
    """
    client = ciba_harness.register(name=f"rs256-{endpoint}")
    if endpoint == "backchannel":
        form = ciba_harness.bc_form(client, ciba_harness.jar(client), assertion_algorithm="RS256")
        check_backchannel_error(
            ciba_harness.bc_authorize(form),
            _BC_GENERIC_ERRORS,
            allow_statuses=_BC_GENERIC_STATUSES,
        )
        return
    auth_req_id = _start_authentication(ciba_harness, client)
    check_token_error(
        ciba_harness.poll(client, auth_req_id, assertion_algorithm="RS256"),
        ("invalid_client",),
        status_code=None,
        allow_statuses=(400, 401),
    )


@pytest.mark.conformance
def test_ciba_client_assertion_iss_aud_accepted(ciba_harness: CibaHarness) -> None:
    """Module ``...client-assertion-with-iss-aud-to-token-endpoint-succeeds`` (RFC7523-3).

    ``aud`` vaut l'``issuer`` seul : l'OP peut accepter (``pending``/
    ``slow_down``) ou rejeter en ``invalid_client`` (400/401) — les deux issues
    sont admises par la suite.
    """
    client = ciba_harness.register(name="ciba-iss-aud")
    auth_req_id = _start_authentication(ciba_harness, client)
    check_token_error(
        ciba_harness.poll(client, auth_req_id, assertion_audience=ciba_harness.issuer),
        ("authorization_pending", "slow_down", "invalid_client"),
        status_code=None,
        allow_statuses=(400, 401),
    )


@pytest.mark.conformance
def test_ciba_without_request_object_fails(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-ensure-unsigned-backchannel-authorization-request-fails``.

    Requête sans ``request`` signé : FAPI-CIBA impose le JAR (CIBA-7.1) →
    ``invalid_request`` sur ``/bc-authorize`` (CIBA-13).
    """
    client = ciba_harness.register(name="ciba-unsigned")
    form = ciba_harness.bc_form(client, "", with_request=False)
    form["scope"] = CLIENT_SCOPE
    form["login_hint"] = HINT_VALUE
    form["binding_message"] = BINDING_MESSAGE
    response = ciba_harness.bc_authorize(form)
    check_backchannel_error(response, ("invalid_request",))


@pytest.mark.conformance
def test_ciba_refresh_token_flow(ciba_harness: CibaHarness) -> None:
    """Module ``fapi-ciba-id1-refresh-token`` (liison du refresh token, OIDCD-3).

    Flux complet du client 1, refresh + ressource, flux du client 2 puis
    présentation du ``refresh_token`` du client 2 par le client 1 →
    ``invalid_grant`` (``RefreshTokenRequestExpectingErrorSteps``).
    """
    grants = (CIBA_GRANT, "refresh_token")
    client1 = ciba_harness.register(name="ciba-refresh-1", grant_types=grants)
    auth1 = _start_authentication(ciba_harness, client1)
    tokens1, claims1 = _finish_authentication(ciba_harness, client1, auth1)
    _check_resource(ciba_harness, tokens1)

    # La suite sépare les deux émissions par ses sleeps de poll : un iat
    # strictement postérieur est exigé (``CompareIdTokenClaims``, OIDCC-12.2).
    time.sleep(1.1)
    refreshed = check_ciba_token_success(
        ciba_harness.refresh(client1, str(tokens1["refresh_token"])),
        expect_refresh=True,
    )
    refreshed_id_token = str(refreshed["id_token"])
    check_ciba_id_token_header(refreshed_id_token)
    refreshed_claims = decode_id_token_claims(refreshed_id_token)
    check_ciba_id_token(
        refreshed_claims,
        issuer=ciba_harness.issuer,
        client_id=client1.client_id,
    )
    check_refreshed_id_token_claims(claims1, refreshed_claims)
    _check_resource(ciba_harness, refreshed)

    client2 = ciba_harness.register(name="ciba-refresh-2", grant_types=grants)
    auth2 = _start_authentication(ciba_harness, client2)
    tokens2, _claims2 = _finish_authentication(ciba_harness, client2, auth2)

    check_token_error(
        ciba_harness.refresh(client1, str(tokens2["refresh_token"])),
        ("invalid_grant",),
        status_code=400,
    )
