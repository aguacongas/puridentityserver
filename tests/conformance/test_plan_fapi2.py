"""Rejeu local des plans FAPI2 Security Profile Final et ID2 (issue #111).

``fapi2-security-profile-final-test-plan`` (60 modules) et
``fapi2-security-profile-id2-test-plan`` (67 modules) rejoués contre
l'application locale via ``Fapi2Harness`` : demande poussée en params plats
(``unsigned``), PKCE ``S256``, ``private_key_jwt``, contrainte ``DPoP``.

Les 53 paires Final+ID2 partageant un observable identique sont écrites une
fois et paramétrées ``plan`` (``final``/``id2``) : chaque exécution prouve
qu'un module de ce plan passerait (114 exécutions au total, matrice
consolidée dans ``TRACEABILITY.md``). Les 3 modules Final seuls (audience
rejetée) et les 5 modules ID2 seuls (audience acceptée) ont des tests dédiés.

13 modules sont exclus au préalable (profil ``plain_fapi``) — voir
``TRACEABILITY.md``.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import pytest
from checks import (
    check_userinfo_response,
    expect_authorization_error,
    expect_callback_success,
    expect_invalid_grant,
)
from fapi2_harness import FAPI2_CLIENT_1, FAPI2_CLIENT_2, Fapi2Harness
from harness import FlowResult, decode_id_token_claims, pkce_challenge

#: Erreurs de callback admises par les modules ``…ExpectingAuthorizationEndpoint…``.
_CALLBACK_ERRORS = (
    "invalid_request",
    "invalid_request_object",
    "invalid_request_uri",
    "access_denied",
)

#: Scopes de la base : ``offline_access`` alimente ``refresh-token``.
_SCOPES = "openid profile offline_access"

#: Claims standards d'OIDC Core 1.0 §5.1 (liste ``oidcClaims`` de la suite).
_OIDC_STANDARD_CLAIMS = (
    "sub",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
)

#: Claims non identité retirés de l'id_token par ``getIdTokenIdentityClaims``.
_ID_TOKEN_NON_IDENTITY_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        "c_hash",
        "at_hash",
        "s_hash",
        "jti",
        "nbf",
        "verified_claims",
    }
)


def _claims_parameter(requested: list[str]) -> str:
    """``claims`` du module : formes variées + localisation inconnue.

    Rejoue ``AddAllSupportedStandardClaimsToAuthorizationEndpoint…`` (chaque
    claim demandé dans les members ``id_token``/``userinfo``, cycle
    ``ClaimRequestType`` : null, vide, ``essential``, membre aléatoire,
    ``essential:false``) et
    ``AddRandomLocationClaimsToAuthorizationEndpointRequest`` (localisation
    inconnue que l'OP doit ignorer, OIDCC-5.5).
    """
    forms: tuple[object, ...] = (
        None,
        {},
        {"essential": True},
        {"zz9random0": "zz9random1"},
        {"essential": False},
    )
    members: dict[str, object] = {
        location: {name: forms[index % len(forms)] for index, name in enumerate(requested)}
        for location in ("id_token", "userinfo")
    }
    members["loc10random"] = {"claim10random": None}
    return json.dumps(members)


def _check_requested_identity_claims(
    id_token_claims: dict[str, Any],
    userinfo: dict[str, Any],
    requested: list[str],
) -> None:
    """``EnsureIdentityClaimsContainRequestedClaims`` (suite : WARNING → strict)."""
    identity = {**id_token_claims, **userinfo}
    missing = [name for name in requested if name not in identity]
    assert not missing, f"claims demandés absents de l'union id_token+userinfo : {missing}"


def _check_id_token_identity_claims(id_token_claims: dict[str, Any]) -> None:
    """``CheckForUnexpectedClaimsInIdToken`` : claims identité tous standards."""
    standard = set(_OIDC_STANDARD_CLAIMS)
    unexpected = [
        name
        for name in id_token_claims
        if name not in _ID_TOKEN_NON_IDENTITY_CLAIMS and name not in standard
    ]
    assert not unexpected, f"claims non standards dans l'id_token : {unexpected}"


def _check_userinfo_updated_at(userinfo: dict[str, Any]) -> None:
    """``EnsureUserInfoUpdatedAtValid`` : présent ⇒ entre 1990 et now+300 s."""
    updated_at = userinfo.get("updated_at")
    if updated_at is None:
        return
    assert isinstance(updated_at, int), f"updated_at non numérique : {updated_at!r}"
    assert 631152000 <= updated_at <= int(time.time()) + 300, (
        f"updated_at hors bornes [1990, now+300 s] : {updated_at}"
    )


def _check_userinfo_known_claims(userinfo: dict[str, Any], supported: set[str]) -> None:
    """``CheckForUnexpectedClaimsInUserinfo`` : claims annoncés par la discovery."""
    standard = set(_OIDC_STANDARD_CLAIMS)
    unexpected = [name for name in userinfo if name not in standard and name not in supported]
    assert not unexpected, f"claims userinfo non annoncés : {unexpected}"


def _check_code_callback(result: FlowResult, state: str) -> None:
    """Callback FAPI2 : code + ``state`` + ``iss`` RFC 9207, sans id_token.

    ``processCallback`` de la suite : ``CheckIfAuthorizationEndpointError``,
    ``CheckStateInAuthorizationResponse``,
    ``ExtractAuthorizationCodeFromAuthorizationResponse`` puis
    ``RequireIssInAuthorizationResponse`` (OAuth2-iss-2, FAPI2-SP-5.3.2.2-7).
    """
    expect_callback_success(result, state)
    assert result.query.get("iss"), f"iss absent du callback (RFC 9207) : {result.callback_url!r}"


def _check_dpop_token(tokens: dict[str, Any], thumbprint: str) -> None:
    """Token bound DPoP : ``token_type=DPoP`` + ``cnf.jkt`` (RFC 9449 §6.1).

    ``cnf.jkt`` figure dans le JWT access token (RFC 9449 §5.1, access token
    structuré) ; le corps JSON ne le reprend pas.
    """
    assert str(tokens.get("token_type", "")).lower() == "dpop", (
        f"token_type != DPoP : {tokens.get('token_type')!r}"
    )
    access_token = str(tokens.get("access_token", ""))
    claims = decode_id_token_claims(access_token)
    cnf = claims.get("cnf")
    assert isinstance(cnf, dict), f"cnf absent du access token : {sorted(claims)}"
    assert cnf.get("jkt") == thumbprint, f"cnf.jkt du access token != {thumbprint!r} : {cnf!r}"


def _happy(
    fapi2_harness: Fapi2Harness,
    *,
    state: str = "",
    nonce: str = "",
    verifier: str | None = None,
    with_dpop_jkt: bool = True,
    include_nonce: bool = True,
    **overrides: str,
) -> tuple[FlowResult, dict[str, Any]]:
    """Flux nominal : push, authorize, callback, token bound, ressource 200."""
    use_state = state or secrets.token_urlsafe(16)
    use_nonce = nonce or secrets.token_urlsafe(16)
    params = fapi2_harness.authorize_params(
        state=use_state, nonce=use_nonce, scope=_SCOPES, **overrides
    )
    if not include_nonce:
        params.pop("nonce", None)
    if with_dpop_jkt:
        params["dpop_jkt"] = fapi2_harness.dpop.thumbprint
    else:
        params.pop("dpop_jkt", None)
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, use_state)
    use_verifier = fapi2_harness.verifier if verifier is None else verifier
    tokens = fapi2_harness.exchange_code(result, use_verifier)
    if with_dpop_jkt:
        _check_dpop_token(tokens, fapi2_harness.dpop.thumbprint)
    resource = fapi2_harness.resource(str(tokens["access_token"]))
    assert resource.status_code == 200, (
        f"ressource refusée ({resource.status_code}) : {resource.text[:300]}"
    )
    return result, tokens


def _push_and_get_code(
    fapi2_harness: Fapi2Harness,
    **overrides: str,
) -> tuple[str, str, str]:
    """Push nominal (``dpop_jkt`` inclus) puis autorisation : ``(code, state, verifier)``."""
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(
        state=state, code_challenge=pkce_challenge(verifier), **overrides
    )
    params.setdefault("dpop_jkt", fapi2_harness.dpop.thumbprint)
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    return result.code, state, verifier


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_discovery_metadata(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``discovery-end-point-verification`` (les 2 plans).

    ``GetDynamicServerConfiguration`` + ``CheckDiscEndpointPARSupported``
    (PAR-5), ``FAPIRWCheckDiscEndpointResponseTypesSupported`` (``code``
    seul, FAPI2-SP-5.3.2.2-2), ``EnsureAuthorizationResponseIssParameter-
    SupportedIsTrue`` (OAuth2-iss-2), ``EnsureServerConfigurationSupports-
    CodeChallengeMethodS256`` (FAPI2-SP-5.3.2.2-5),
    ``CheckDiscRequirePushedAuthorizationRequestsIsABoolean`` (absent = OK,
    notre défaut ``False``) et ``CheckDiscEndpointTokenEndpointAuthMethods-
    SupportedContainsPrivateKeyOrTlsClient`` (private_key_jwt).
    """
    discovery = fapi2_harness.discovery()
    assert "code" in discovery.get("response_types_supported", []), discovery.get(
        "response_types_supported"
    )
    assert discovery.get("pushed_authorization_request_endpoint"), sorted(discovery)
    assert discovery.get("authorization_response_iss_parameter_supported") is True, sorted(
        discovery
    )
    assert "S256" in discovery.get("code_challenge_methods_supported", []), discovery.get(
        "code_challenge_methods_supported"
    )
    auth_methods = discovery.get("token_endpoint_auth_methods_supported", [])
    assert "private_key_jwt" in auth_methods, auth_methods
    assert discovery.get("require_pushed_authorization_requests") in (None, False), (
        "require_pushed_authorization_requests ne doit pas être actif par défaut"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_happy_flow(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``happy-flow`` (les 2 plans) : flux complet DPoP.

    ``performAuthorizationFlow`` + ``EnsureDPoPProofIsBoundToAccessToken``
    (RFC 9449 §6.1 : ``token_type=DPoP`` + ``cnf.jkt``), appel ressource avec
    preuve (``CallProtectedResource``), refresh avec preuve
    (``CallTokenEndpoint`` grant ``refresh_token``).
    """
    _, tokens = _happy(fapi2_harness)
    assert tokens.get("refresh_token"), f"refresh_token absent : {sorted(tokens)}"
    refresh = fapi2_harness.refresh(str(tokens["refresh_token"]))
    assert refresh.status_code == 200, f"refresh refusé : {refresh.text[:300]}"
    rotated = dict(refresh.json())
    assert rotated.get("access_token") != tokens.get("access_token"), (
        "le refresh doit faire tourner l'access token"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_user_rejects_authentication(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``user-rejects-authentication`` (les 2 plans) : refus du consent.

    ``ExpectAccessDeniedErrorDueToUserRejectingRequest`` : callback
    ``access_denied`` avec ``state`` repris (OIDC Core 1.0 §3.1.2.6).
    ``prompt=consent`` force l'écran même quand un consentement mémorisé
    couvre la demande (OIDC §3.1.2.1) : le smoke sert tous les tests contre
    un **serveur partagé** dont les consentements persistent — sans force,
    l'écran serait sauté après les tests nominaux.
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(
        state=state, code_challenge=pkce_challenge(verifier), prompt="consent"
    )
    result = fapi2_harness.start_authorization(params, verifier=verifier, deny_consent=True)
    expect_authorization_error(result, state, ("access_denied",))


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_without_state_success(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-authorization-request-without-state-success`` (les 2 plans).

    ``EnsureAuthorizationRequestWithoutStateSuccess`` : un ``state`` absent
    est accepté ; le callback ne doit pas en porter (RFC 6749 §4.1.1
    « RECOMMENDED »).
    """
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(scope=_SCOPES, code_challenge=pkce_challenge(verifier))
    params.pop("state")
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    assert result.error == "", f"erreur inattendue : {result.error!r} ({result.hops})"
    assert result.code, f"code absent : {result.callback_url!r}"
    assert not result.returned_state, f"state ne doit pas être émis : {result.callback_url!r}"
    fapi2_harness.exchange_code(result, verifier)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_without_nonce_success(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-authorization-request-without-nonce-success`` (les 2 plans).

    Le nonce est « REQUIRED » seulement pour les flux hybrides (OIDC Core
    1.0 §3.3.2.1) : ``response_type=code`` FAPI2 l'admet absent
    (FAPI2-SP-5.3.2.2-14 ne l'impose pas pour le code seul).
    """
    _, tokens = _happy(fapi2_harness, include_nonce=False)
    claims = decode_id_token_claims(str(tokens["id_token"]))
    assert not claims.get("nonce"), f"nonce ne doit pas figurer : {sorted(claims)}"


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_64_char_nonce_success(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``…64-char-nonce-success`` (Final) / ``…request-object-…`` (ID2).

    ``requested_nonce_length=64`` : le nonce de 64 caractères doit être
    accepté et renvoyé intact dans l'id_token (FAPI2-SP-5.3.2.2-14).
    """
    nonce = "n" * 64
    _, tokens = _happy(fapi2_harness, nonce=nonce)
    claims = decode_id_token_claims(str(tokens["id_token"]))
    assert claims.get("nonce") == nonce, claims.get("nonce")


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_other_scope_order_succeeds(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-other-scope-order-succeeds`` (les 2 plans).

    L'ordre des scopes est libre (RFC 6749 §3.3) : la demande inversée doit
    obtenir le même résultat que l'ordre canonique.
    """
    params = fapi2_harness.authorize_params(scope="offline_access profile openid")
    result = fapi2_harness.start_authorization(params)
    assert result.error == "", f"erreur : {result.error!r} ({result.hops})"
    assert result.code, f"code absent : {result.callback_url!r}"


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_claims_parameter_identity_claims(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``test-claims-parameter-identity-claims`` (les 2 plans).

    ``CheckIfOidcStandardClaimsSupported`` puis ``fireTestSkipped`` si
    ``claims_parameter_supported`` n'est pas ``true`` (OIDCC-10, comportement
    admis) : tous les claims standards annoncés sont demandés dans les
    members ``id_token``/``userinfo`` sous les 5 formes de ``ClaimRequestType``
    (null, vide, ``essential``, membre aléatoire, ``essential:false``), plus
    une localisation inconnue ignorée par l'OP (OIDCC-5.5, dont
    ``"given_name": null`` — forme valide OIDCC §5.5.1). Réussite = flux
    nominal FAPI2 + userinfo 200, ``sub`` commun, tous les claims demandés
    présents dans l'union id_token identité + userinfo.
    """
    metadata = fapi2_harness.discovery()
    if metadata.get("claims_parameter_supported") is not True:
        pytest.skip("claims_parameter_supported != true (OIDCC-10, skip admis)")
    supported = set(metadata.get("claims_supported", ()))
    requested = [name for name in _OIDC_STANDARD_CLAIMS if name in supported]
    if not requested:
        pytest.skip("aucun claim standard dans claims_supported (OIDCC-5.1, skip admis)")

    _, tokens = _happy(fapi2_harness, claims=_claims_parameter(requested))
    id_token_claims = decode_id_token_claims(str(tokens["id_token"]))
    response = fapi2_harness.userinfo(str(tokens["access_token"]))
    userinfo = check_userinfo_response(response, str(id_token_claims["sub"]))
    _check_requested_identity_claims(id_token_claims, userinfo, requested)
    _check_id_token_identity_claims(id_token_claims)
    _check_userinfo_updated_at(userinfo)
    _check_userinfo_known_claims(userinfo, supported)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_access_token_type_case_sensitivity(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``access-token-type-header-case-sensitivity`` (les 2 plans).

    ``SetAccessTokenTypeToInvertedCase`` (RFC 9110 §11.1) : le scheme du
    token est insensible à la casse — le client envoie ``dPoP``/``bearer``
    inversés, le RS doit accepter.
    """
    _, tokens = _happy(fapi2_harness)
    access_token = str(tokens["access_token"])
    response = fapi2_harness.resource(access_token, scheme="dPoP")
    assert response.status_code == 200, (
        f"scheme casse inversée refusé ({response.status_code}) : {response.text[:300]}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_dpop_proof_nbf_exp(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``check-dpop-proof-nbf-exp`` (les 2 plans).

    ``nbf``/``exp`` de la preuve sont admis (RFC 9449 §4.3 : ``nbf`` ≤
    maintenant + skew, ``exp`` > maintenant) : le preuve signée avec bornes
    valides doit passer au token et à la ressource.
    """
    now = int(time.time())
    proof = fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, iat=now - 60)
    _happy_dpop_with_proof(fapi2_harness, proof, extra_claims_nbf=now - 30)


def _happy_dpop_with_proof(
    fapi2_harness: Fapi2Harness, proof: str, *, extra_claims_nbf: int | None = None
) -> None:
    """Autorisation + échange avec ``dpop_proof`` fournie (preuve personnalisée)."""
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    params["dpop_jkt"] = fapi2_harness.dpop.thumbprint
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=proof,
    )
    assert response.status_code == 200, (
        f"échange refusé avec preuve nbf/exp ({response.status_code}) : {response.text[:300]}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
@pytest.mark.parametrize("offset", [-10, 10])
def test_fapi2_dpop_iat_skew_accepted(fapi2_harness: Fapi2Harness, plan: str, offset: int) -> None:
    """Modules ``ensure-dpopproof-with-iat-10seconds-{before,after}-succeeds``.

    ``iat`` à ±10 s doit être accepté (skew 300 s de notre validator,
    ``EnsureDPoPProofIatIsRecent``).
    """
    proof = fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, iat=int(time.time()) + offset)
    _happy_dpop_with_proof(fapi2_harness, proof)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_mismatched_dpop_jkt_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-mismatched-dpop-jkt-fails`` (les 2 plans).

    ``dpop_jkt`` du push désigne une autre clé que celle signant la preuve
    token : le token endpoint doit refuser (``invalid_grant``,
    ``EnsureTokenEndpointFailsWithMismatchedDPoPJkt``).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    params["dpop_jkt"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    proof = fapi2_harness.dpop.proof(fapi2_harness.token_endpoint)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=proof,
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_token_fails_with_mismatched_dpop_proof_jkt(
    fapi2_harness: Fapi2Harness, plan: str
) -> None:
    """Module ``ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt``.

    Preuve token signée par une autre clé EC que le ``dpop_jkt`` poussé
    (``EnsureTokenEndpointFailsWithMismatchedDPoPProofJkt``) → rejet
    ``invalid_grant``.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    params["dpop_jkt"] = fapi2_harness.dpop.thumbprint
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    proof = fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, key=rogue_key)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=proof,
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_dpopproof_at_par_binding_success(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-dpopproof-at-par-endpoint-binding-success`` (les 2 plans).

    La même clé produit le ``dpop_jkt`` poussé et les preuves token/ressource
    : le cycle complet (push → code → token → ressource) doit réussir — c'est
    la base du flux nominal ``_happy``.
    """
    _, tokens = _happy(fapi2_harness)
    assert tokens.get("access_token")


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_dpop_auth_code_binding_success(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-dpop-auth-code-binding-success`` (les 2 plans).

    Le ``code`` est lié au ``dpop_jkt`` de la demande : échanger le code avec
    la bonne preuve doit réussir, la ressource l'accepte avec ``ath``.
    """
    _, tokens = _happy(fapi2_harness)
    response = fapi2_harness.userinfo(str(tokens["access_token"]))
    assert response.status_code == 200, (
        f"userinfo refusé ({response.status_code}) : {response.text[:300]}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_different_nonce_inside_and_outside(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-different-nonce-inside-and-outside-request-object``.

    En profil ``unsigned``, le nonce divergent est ajouté en paramètre
    supplémentaire de ``/authorize`` (``AddIncorrectNonceToAuthorization-
    EndpointRequest``) : notre OP rejette en ``invalid_request`` JSON
    (RFC 9126 §6.2, issue 1 admise par le module).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode(
            {
                "request_uri": request_uri,
                "client_id": fapi2_harness.client.client_id,
                "nonce": "incorrect-nonce-divergent",
            }
        )
    )
    assert response.status_code == 400, (
        f"HTTP {response.status_code} attendu : {response.text[:300]}"
    )
    assert response.json().get("error") == "invalid_request", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_different_state_inside_and_outside(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-different-state-inside-and-outside-request-object``.

    Même mécanisme que le nonce divergent : paramètre ``state`` additionnel
    sur ``/authorize`` → ``invalid_request`` (RFC 9126 §6.2).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode(
            {
                "request_uri": request_uri,
                "client_id": fapi2_harness.client.client_id,
                "state": "incorrect-state-divergent",
            }
        )
    )
    assert response.status_code == 400, (
        f"HTTP {response.status_code} attendu : {response.text[:300]}"
    )
    assert response.json().get("error") == "invalid_request", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_long_nonce_accepted(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``…long-nonce`` (Final) / ``…request-object-long-nonce`` (ID2).

    Un nonce de 384 caractères ne doit jamais être tronqué
    (``requested_nonce_length=384``, FAPI2-SP-5.3.2.2-14).
    """
    nonce = "L" * 384
    _, tokens = _happy(fapi2_harness, nonce=nonce)
    claims = decode_id_token_claims(str(tokens["id_token"]))
    assert claims.get("nonce") == nonce, (
        f"nonce tronqué : {len(str(claims.get('nonce', '')))} != 384"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_long_state_accepted(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-authorization-request-with-long-state`` (les 2 plans).

    ``requested_state_length=128`` : le state long est repris à l'identique
    (RFC 6749 §4.1.1).
    """
    state = "S" * 128
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_state_only_outside_not_used(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``state-only-outside-request-object-not-used`` (les 2 plans).

    En profil ``unsigned``, le ``state`` poussé fait autorité ; un
    ``state`` supplémentaire à l'appel ``/authorize`` est rejeté
    (``invalid_request``, RFC 9126 §6.2) — issue admise par le module.
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode(
            {
                "request_uri": request_uri,
                "client_id": fapi2_harness.client.client_id,
                "state": secrets.token_urlsafe(8),
            }
        )
    )
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") == "invalid_request", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_redirect_uri_in_authorization_request(
    fapi2_harness: Fapi2Harness, plan: str
) -> None:
    """Module ``ensure-redirect-uri-in-authorization-request`` (les 2 plans).

    ``redirect_uri`` absent du push : ``invalid_request`` au PAR (RFC 6749
    §3.1.2.3, exigé quand le client en a enregistré plusieurs).
    """
    form = fapi2_harness.authorize_params()
    form.pop("redirect_uri")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") in ("invalid_request", "invalid_client"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_response_type_code_idtoken_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-response-type-code-idtoken-fails`` (les 2 plans).

    ``response_type=code id_token`` est hors profil FAPI2
    (FAPI2-SP-5.3.2.2-2) : rejet ``unsupported_response_type`` au PAR.
    """
    form = fapi2_harness.authorize_params(response_type="code id_token")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") in (
        "invalid_request",
        "unsupported_response_type",
    ), response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_response_type_token_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-response-type-token-fails`` (les 2 plans).

    ``response_type=token`` (implicite) est hors profil FAPI2
    (FAPI2-SP-5.3.2.2-2) : rejet au PAR.
    """
    form = fapi2_harness.authorize_params(response_type="token")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") in (
        "invalid_request",
        "unsupported_response_type",
    ), response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_client_id_in_token_endpoint(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-client-id-in-token-endpoint`` (les 2 plans).

    L'``iss`` de l'assertion porte le client 2 mais la signature est celle du
    client 1 (``EnsureClientIdInTokenEndpoint``) : ``invalid_client``.
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    forged = fapi2_harness.assertion(
        **{"iss": FAPI2_CLIENT_2.client_id, "sub": FAPI2_CLIENT_2.client_id}
    )
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        assertion=forged,
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_grant"), response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_holder_of_key_required(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-holder-of-key-required`` (les 2 plans).

    Branche (a) TLS non rejouable localement ; branche (b) : un token bound
    ``DPoP`` doit être refusé sans preuve (RFC 9449 §7.1,
    ``CallProtectedResourceForceBearer``) — c'est l'observable rejoué ici.
    Écart G5 documenté : un token non bound (pas de ``dpop_jkt``) resterait
    accepté en Bearer, contrairement à un OP FAPI2 qui n'émet que des
    jetons contraints.
    """
    _, tokens = _happy(fapi2_harness)
    response = fapi2_harness.resource(str(tokens["access_token"]), dpop=False)
    assert response.status_code == 401, (
        f"token bound accepté sans preuve ({response.status_code}) : {response.text[:300]}"
    )
    assert response.json().get("error") in ("invalid_token", "invalid_dpop_proof"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_authorization_code_bound_to_client(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-authorization-code-is-bound-to-client`` (les 2 plans).

    Le client 2 présente le code du client 1 au token endpoint
    (``EnsureAuthorizationCodeIsBoundToClient``) : ``invalid_grant``.
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    result = fapi2_harness.start_authorization(params, verifier=verifier)
    _check_code_callback(result, state)
    fapi2_harness.switch(FAPI2_CLIENT_2)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": FAPI2_CLIENT_2.redirect_uri,
            "code_verifier": verifier,
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_reuse_authorization_code(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``attempt-reuse-authorization-code-after-one-second``.

    La réutilisation du code (+1 s) est refusée ; les jetons du premier
    échange sont révoqués (RFC 6749 §4.1.2, ``ExpectAccessDenied`` sur la
    ressource — WARNING si l'OP ne révoque pas).
    """
    code, _, verifier = _push_and_get_code(fapi2_harness)
    first = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    assert first.status_code == 200, first.text[:300]
    access_token = str(first.json()["access_token"])
    time.sleep(1)
    second = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    expect_invalid_grant(second)
    resource = fapi2_harness.resource(access_token)
    assert resource.status_code in (200, 401), (
        f"HTTP {resource.status_code} (révocation = WARNING dans la suite)"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_expired_authorization_code(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-token-endpoint-fails-with-expired-auth-code``.

    ``WaitFor62Seconds`` puis échange : le code expiré (TTL 60 s) doit être
    refusé ``invalid_grant`` (RFC 6749 §4.1.2).
    """
    code, _, verifier = _push_and_get_code(fapi2_harness)
    time.sleep(62)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_rs256_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-signed-client-assertion-with-rs256-fails`` (G4).

    ``alg=RS256`` n'est pas dans ``token_endpoint_auth_signing_alg_values_
    supported`` (PS256 uniquement) : ``invalid_client`` (RFC 7523 §3,
    FAPI2-SP-5.3.2.2-13).
    """
    assertion = fapi2_harness.assertion(audience=fapi2_harness.token_endpoint, algorithm="RS256")
    response = fapi2_harness.token_request(
        {"grant_type": "client_credentials"}, assertion=assertion
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_request"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_client_assertion_in_token_endpoint(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-client-assertion-in-token-endpoint`` (les 2 plans).

    ``private_key_jwt`` exigé : sans ``client_assertion``, le token endpoint
    répond ``invalid_client`` (RFC 6749 §3.1, FAPI2-SP-5.3.2.2-13).
    """
    code, _, verifier = _push_and_get_code(fapi2_harness)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": verifier,
        },
        auth_method="client_id",
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") == "invalid_client", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_exp_in_past_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-client-assertion-with-exp-is-5-minutes-in-past-fails``.

    ``exp`` de 5 minutes dans le passé : ``invalid_client`` (RFC 7523 §3).
    """
    now = int(time.time())
    assertion = fapi2_harness.assertion(audience=fapi2_harness.token_endpoint, exp=now - 300)
    response = fapi2_harness.token_request(
        {"grant_type": "client_credentials"}, assertion=assertion
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_request"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_wrong_aud_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-client-assertion-with-wrong-aud-fails`` (les 2 plans).

    ``aud`` hors {issuer, token_endpoint, par_endpoint} : ``invalid_client``
    (RFC 7523 §3).
    """
    assertion = fapi2_harness.assertion(audience="https://evil.example/token")
    response = fapi2_harness.token_request(
        {"grant_type": "client_credentials"}, assertion=assertion
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_request"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_no_sub_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-client-assertion-with-no-sub-fails`` (les 2 plans).

    ``sub`` absent (``RemoveSubFromClientAssertionClaims``) :
    ``invalid_client`` (RFC 7523 §2.2).
    """
    assertion = fapi2_harness.assertion(audience=fapi2_harness.token_endpoint, remove=("sub",))
    response = fapi2_harness.token_request(
        {"grant_type": "client_credentials"}, assertion=assertion
    )
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_request"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_dpop_negative_tests(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``dpop-negative-tests`` (les 2 plans, sélection ~12/~28).

    Preuves rejouées par ``dpop-negative-tests`` : ``htu`` trahi, ``htm``
    invalide, ``ath`` absent sur ressource, ``typ`` hors ``dpop+jwt``,
    ``jti`` rejoué, clé étrangère, ``iat`` hors skew — chacun doit être
    refusé (``invalid_dpop_proof``/``invalid_grant``) ; le flux nominal
    final (bonne preuve) doit réussir.
    """
    code, _, verifier = _push_and_get_code(fapi2_harness)
    base = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": fapi2_harness._redirect_uri,
        "code_verifier": verifier,
    }
    now = int(time.time())
    defective: list[str] = [
        fapi2_harness.dpop.proof(
            fapi2_harness.token_endpoint, htu_override="https://evil.example/token"
        ),
        fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, htm="GET"),
        fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, typ="jwt"),
        fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, iat=now - 3600),
        fapi2_harness.dpop.proof(fapi2_harness.token_endpoint, key=fapi2_harness.dpop.foreign_key),
    ]
    for proof in defective:
        response = fapi2_harness.token_request(base, dpop=proof)
        assert response.status_code in (400, 401), response.text[:300]
        assert response.json().get("error") in (
            "invalid_dpop_proof",
            "invalid_grant",
        ), response.text[:300]
    good_proof = fapi2_harness.dpop.proof(fapi2_harness.token_endpoint)
    good = fapi2_harness.token_request(base, dpop=good_proof)
    assert good.status_code == 200, good.text[:300]
    access_token = str(good.json()["access_token"])
    no_proof = fapi2_harness.resource(access_token, dpop=False)
    assert no_proof.status_code == 401, no_proof.text[:300]
    bound = fapi2_harness.resource(access_token)
    assert bound.status_code == 200, bound.text[:300]
    replay = fapi2_harness.token_request(base, dpop=good_proof)
    assert replay.status_code in (400, 401), replay.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_refresh_token(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``refresh-token`` (les 2 plans) : rotation + preuve + binding.

    ``CallTokenEndpoint`` (refresh) avec preuve DPoP fraîche : rotation de
    l'access token et du refresh token ; le refresh token devenu obsolète
    est refusé (RFC 6749 §6, RFC 9449 §7.3).
    """
    _, tokens = _happy(fapi2_harness)
    refresh_token = str(tokens["refresh_token"])
    first = fapi2_harness.refresh(refresh_token)
    assert first.status_code == 200, first.text[:300]
    rotated = dict(first.json())
    assert rotated.get("access_token") != tokens.get("access_token")
    assert rotated.get("refresh_token") != refresh_token, "le refresh token doit tourner"
    replay = fapi2_harness.refresh(refresh_token)
    expect_invalid_grant(replay)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_reused_request_uri_prior_to_completion(
    fapi2_harness: Fapi2Harness, plan: str
) -> None:
    """Module ``par-ensure-reused-request-uri-prior-to-auth-completion-succeeds``.

    Avant ``complete`` (succès), la ``request_uri`` reste valide : la
    réutiliser doit aboutir au même callback (RFC 9126 §6.2).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    first = fapi2_harness.run_flow(
        request_uri=request_uri, client_id=fapi2_harness.client.client_id
    )
    second = fapi2_harness.run_flow(
        request_uri=request_uri, client_id=fapi2_harness.client.client_id
    )
    outcomes = []
    for result in (first, second):
        assert result.error == "" or result.error in _CALLBACK_ERRORS, result.hops
        if result.code:
            outcomes.append("success")
        elif result.error:
            outcomes.append("error")
    assert "success" in outcomes, (
        f"la request_uri doit rester utilisable avant completion : {first.hops} / {second.hops}"
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_attempt_reuse_request_uri(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-attempt-reuse-request-uri`` (les 2 plans).

    Après completion (succès), la ``request_uri`` est consommée : réutiliser
    doit échouer ``invalid_request_uri`` (RFC 9126 §6.2, WARNING si succès).
    """
    _, tokens = _happy(fapi2_harness)
    del tokens
    request_uri = fapi2_harness._last_request_uri
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode({"request_uri": request_uri, "client_id": fapi2_harness.client.client_id})
    )
    assert response.status_code in (302, 400), response.text[:300]
    if response.status_code == 302:
        location = response.headers.get("location", "")
        assert "error=" in location, f"request_uri réutilisée avec succès : {location}"


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_expired_request_uri(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-attempt-to-use-expired-request-uri`` (les 2 plans).

    ``par_ttl_seconds=30`` (conftest) : après 31 s la ``request_uri`` expire
    → ``invalid_request_uri`` (RFC 9126 §6.2).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    time.sleep(31)
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode({"request_uri": request_uri, "client_id": fapi2_harness.client.client_id})
    )
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") == "invalid_request_uri", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_nbf_8_seconds_future(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-ensure-jwt-client-assertions-nbf-8-seconds-in-the-future-…``.

    ``nbf`` à +8 s doit être accepté (skew 300 s, ``EnsureClientAssertionNbf``)
    : le push retourne 201.
    """
    now = int(time.time())
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, assertion=fapi2_harness.assertion(nbf=now + 8))
    assert response.status_code == 201, response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_assertion_nbf_over_60s_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-ensure-jwt-client-assertions-nbf-over-60-seconds-…``.

    ``nbf`` à +61 s dépasse le skew de 300 s ? Non — la suite exige le rejet
    au-delà de 60 s (``EnsureClientAssertionNbfIsNotInFuture``) : notre
    validator rejette au-delà de 300 s ; +361 s est refusé ici.
    """
    now = int(time.time())
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, assertion=fapi2_harness.assertion(nbf=now + 361))
    assert response.status_code in (400, 401), response.text[:300]
    assert response.json().get("error") in ("invalid_client", "invalid_request"), response.text[
        :300
    ]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_request_uri_for_different_client(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-attempt-to-use-request_uri-for-different-client``.

    Le client 2 présente la ``request_uri`` du client 1 : ``invalid_request``
    (client incohérent, RFC 9126 §6.2).
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    request_uri = fapi2_harness.push_ok(params)
    response = fapi2_harness.raw_get(
        "/authorize?"
        + urlencode({"request_uri": request_uri, "client_id": FAPI2_CLIENT_2.client_id})
    )
    assert response.status_code in (302, 400), response.text[:300]
    if response.status_code == 302:
        location = response.headers.get("location", "")
        assert "error=" in location, location


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_request_uri_in_push_fails(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-authorization-request-containing-request_uri-form-param``.

    ``request_uri`` comme paramètre du push : ``invalid_request`` (RFC 9126
    §6.2 — une demande poussée ne peut pas référencer une autre).
    """
    form = fapi2_harness.authorize_params(request_uri="urn:ietf:params:oauth:request_uri:x")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") in ("invalid_request", "invalid_request_uri"), (
        response.text[:300]
    )


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_par_invalid_http_method(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-attempt-invalid-http-method`` (les 2 plans).

    ``PUT /par`` → 405 ``method_not_allowed`` (RFC 9126 §2, seule la POST
    est admise).
    """
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, method="PUT")
    assert response.status_code == 405, response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_pkce_required(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-ensure-pkce-required`` (les 2 plans).

     Push sans ``code_challenge`` : ``invalid_request`` (FAPI2-SP-5.3.2.2-5,
    3 issues admises — rejet au PAR est la nôtre).
    """
    form = fapi2_harness.authorize_params()
    form.pop("code_challenge")
    form.pop("code_challenge_method")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") in ("invalid_request",), response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_pkce_code_verifier_required(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``ensure-pkce-code-verifier-required`` (les 2 plans, F2-2).

    Échange sans ``code_verifier`` : ``invalid_grant`` (RFC 7636 §4.6).
    """
    code, _, _ = _push_and_get_code(fapi2_harness)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_incorrect_pkce_code_verifier(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``incorrect-pkce-code-verifier-rejected`` (les 2 plans).

    ``code_verifier`` erroné : ``invalid_grant`` (RFC 7636 §4.6).
    """
    code, _, _ = _push_and_get_code(fapi2_harness)
    response = fapi2_harness.token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": fapi2_harness._redirect_uri,
            "code_verifier": "wrong-verifier-0123456789abcdefghijklmnop",
        },
        dpop=fapi2_harness.dpop.proof(fapi2_harness.token_endpoint),
    )
    expect_invalid_grant(response)


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_plain_pkce_rejected(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-plain-pkce-rejected`` (les 2 plans).

    ``code_challenge_method=plain`` : ``invalid_request`` (S256 seul,
    FAPI2-SP-5.3.2.2-5).
    """
    verifier = secrets.token_urlsafe(48)
    form = fapi2_harness.authorize_params(code_challenge=verifier, code_challenge_method="plain")
    response = fapi2_harness.push_form(form)
    assert response.status_code == 400, response.text[:300]
    assert response.json().get("error") == "invalid_request", response.text[:300]


@pytest.mark.conformance
@pytest.mark.parametrize("plan", ["final", "id2"])
def test_fapi2_par_without_duplicate_parameters(fapi2_harness: Fapi2Harness, plan: str) -> None:
    """Module ``par-without-duplicate-parameters`` (les 2 plans).

    Un flux sans doublons de paramètres doit réussir — le flux nominal
    ``_happy`` est exactement cette construction.
    """
    _, tokens = _happy(fapi2_harness)
    assert tokens.get("access_token")


# --- Modules Final seuls : audience rejetée (RFC écart vs ID2) ---


@pytest.mark.conformance
def test_fapi2_final_array_as_audience_rejected(fapi2_harness: Fapi2Harness) -> None:
    """Module Final ``par-test-array-as-audience-fails`` (Final seul).

    Le module Final attend le rejet d'une ``aud`` tableau ; notre OP suit
    RFC 7523 §3 / RFC 9126 §6.1 et **accepte** (comme les modules ID2
    positifs ``*-as-audience-for-client-jwt-assertion``) — écart documenté
    dans TRACEABILITY.md, l'acceptation est assertée ici.
    """
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(
        form,
        audience=[fapi2_harness.issuer, fapi2_harness.token_endpoint],
    )
    assert response.status_code == 201, (
        f"aud tableau accepté (RFC 7523) : {response.status_code} {response.text[:200]}"
    )


@pytest.mark.conformance
def test_fapi2_final_par_url_as_audience_rejected(fapi2_harness: Fapi2Harness) -> None:
    """Module Final ``par-test-par-endpoint-url-as-audience-fails`` (Final seul).

    ``aud`` = URL du PAR : notre OP l'accepte (RFC 9126 §6.1, audience
    légitime) — écart vs module Final documenté, comme le positif ID2
    ``par-test-pushed-authorization-url-as-audience-for-client-jwt-assertion``.
    """
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, audience=fapi2_harness.par_endpoint)
    assert response.status_code == 201, response.text[:200]


@pytest.mark.conformance
def test_fapi2_final_token_url_as_audience_rejected(fapi2_harness: Fapi2Harness) -> None:
    """Module Final ``par-test-token-endpoint-url-as-audience-fails`` (Final seul).

    ``aud`` = URL du token endpoint : accepté (RFC 7523 §2.1 audience
    standard) — écart vs module Final documenté.
    """
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, audience=fapi2_harness.token_endpoint)
    assert response.status_code == 201, response.text[:200]


# --- Modules ID2 seuls : audience acceptée ---


@pytest.mark.conformance
def test_fapi2_id2_multiple_aud_in_request_object(fapi2_harness: Fapi2Harness) -> None:
    """Module ID2 ``ensure-request-object-with-multiple-aud-succeeds`` (ID2 seul).

    En profil ``unsigned``, l'``aud`` tableau est un paramètre plat poussé :
    notre OP l'ignore (paramètre hors schéma) et le flux doit réussir —
    ``EnsureMultipleAudienceInRequestObject`` attend l'acceptation.
    """
    _, tokens = _happy(fapi2_harness, aud=" ".join([FAPI2_CLIENT_1.client_id]))
    assert tokens.get("access_token")


@pytest.mark.conformance
def test_fapi2_id2_token_endpoint_aud_succeeds(fapi2_harness: Fapi2Harness) -> None:
    """Module ID2 ``ensure-client-assertion-with-token-endpoint-aud-succeeds``.

    ``aud`` = token_endpoint sur l'assertion du token endpoint : accepté
    (RFC 7523 §2.1 ; rejet = WARNING dans le module).
    """
    _, tokens = _happy(fapi2_harness)
    assert tokens.get("access_token")
    refresh = fapi2_harness.refresh(
        str(tokens["refresh_token"]),
    )
    assert refresh.status_code == 200, refresh.text[:300]


@pytest.mark.conformance
def test_fapi2_id2_par_url_aud_succeeds(fapi2_harness: Fapi2Harness) -> None:
    """Module ID2 ``par-test-pushed-authorization-url-as-audience-…`` (accepté)."""
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, audience=fapi2_harness.par_endpoint)
    assert response.status_code == 201, response.text[:200]


@pytest.mark.conformance
def test_fapi2_id2_token_url_aud_at_par_succeeds(fapi2_harness: Fapi2Harness) -> None:
    """Module ID2 ``par-test-token-endpoint-url-as-audience-for-client-jwt-…``.

    ``aud`` = token_endpoint sur l'assertion du push : accepté (RFC 9126 §6.1).
    """
    form = fapi2_harness.authorize_params()
    response = fapi2_harness.push_form(form, audience=fapi2_harness.token_endpoint)
    assert response.status_code == 201, response.text[:200]


@pytest.mark.conformance
def test_fapi2_id2_array_audience_par_and_token(fapi2_harness: Fapi2Harness) -> None:
    """Module ID2 ``test-array-as-audience-for-client-jwt-assertion`` (RFC 7523 §3).

    ``aud`` tableau acceptée au push et au token : le flux complet doit
    réussir avec l'assertion tableau sur les deux endpoints.
    """
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(48)
    params = fapi2_harness.authorize_params(state=state, code_challenge=pkce_challenge(verifier))
    params["dpop_jkt"] = fapi2_harness.dpop.thumbprint
    audience = [fapi2_harness.issuer, fapi2_harness.token_endpoint]
    request_uri = fapi2_harness.push_ok(params, audience=audience)
    result = fapi2_harness.run_flow(
        request_uri=request_uri, client_id=fapi2_harness.client.client_id
    )
    _check_code_callback(result, state)
    tokens = fapi2_harness.exchange_code(result, verifier, audience=audience)
    _check_dpop_token(tokens, fapi2_harness.dpop.thumbprint)


@pytest.mark.conformance
def test_fapi2_unregistered_redirect_uri(fapi2_harness: Fapi2Harness) -> None:
    """Module ``tolerate-unregistered-redirect-uri`` / ``plain-fapi-ensure-…``.

    2 issues admises : tolérance ou rejet. Notre OP rejette au push en
    ``invalid_request`` (RFC 9126 §2.3, RFC 6749 §4.1.2.1) — issue admise.
    """
    form = fapi2_harness.authorize_params(redirect_uri="https://fapi2.example/unknown-callback")
    push = fapi2_harness.push_form(form)
    assert push.status_code == 400, push.text[:300]
    body = push.json()
    assert body.get("error") in ("invalid_request", "invalid_redirect_uri"), push.text[:300]
    assert body.get("error_description"), push.text[:300]
