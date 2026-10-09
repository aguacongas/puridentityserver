"""Assertions dérivées des check modules officiels de la suite de certification.

Chaque fonction reproduit le comportement d'un ``testmodule`` Java de
`openid/conformance-suite` (release-v5.2.4, clone lecture seule utilisé pour
l'extraction — voir ``TRACEABILITY.md``). Le nom du check est rappelé dans
la docstring : c'est lui qui apparaît dans le rapport de certification et doit
rester traçable d'un test Python à l'autre.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any

import httpx
from harness import FlowResult

_MAX_SKEW_SECONDS = 300
_MIN_CODE_LENGTH = 16
# Longueur minimale des jetons mesurée en bits par la suite (128 bits exigés
# pour l'``access_token``, le ``refresh_token`` et l'``auth_req_id`` —
# ``EnsureMinimumAccessTokenLength`` / ``EnsureMinimumRefreshTokenLength`` /
# ``EnsureMinimumAuthenticationRequestIdLength``) : ≥ 16 caractères.
_MIN_TOKEN_LENGTH_BITS = 128
# ``expires_in`` de l'``auth_req_id`` borné à un an (356 jours) par
# ``ValidateAuthenticationRequestIdExpiresIn`` ; ``interval`` borné à 6 h par
# ``ValidateAuthenticationRequestIdInterval``.
_MAX_ACK_EXPIRES_IN = 356 * 24 * 60 * 60
_MAX_ACK_INTERVAL = 6 * 60 * 60
# ``auth_req_id`` : ``[A-Za-z0-9\-_\.]+`` (``ValidateAuthenticationRequestId``).
_AUTH_REQ_ID_PATTERN = r"[A-Za-z0-9\-_\.]+"
# ``token68`` / ``b64token`` des jetons (RFC 6749 §A.17, RFC 6750 §2.1).
_BEARER_TOKEN_PATTERN = r"[A-Za-z0-9\-._~+/]+=*"
# Claims rendus par scope (OIDC Core 1.0 §5.1.2 / §5.1.3) : objet des checks
# ``VerifyScopesReturnedInUserInfoClaims`` et
# ``VerifyScopesReturnedInAuthorizationEndpointIdToken`` — la table complète
# ``AbstractVerifyScopesReturnedInClaims.SCOPE_STANDARD_CLAIMS`` de la suite.
_SCOPE_CLAIMS: dict[str, tuple[str, ...]] = {
    "profile": (
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "preferred_username",
    ),
    "email": ("email", "email_verified"),
    "address": ("address",),
    "phone": ("phone_number", "phone_number_verified"),
}


def expect_redirect_uri_error_page(result: FlowResult) -> None:
    """``ExpectRedirectUriErrorPage`` (``oidcc-ensure-registered-redirect-uri``).

    Un code d'erreur affiché **dans le navigateur de l'utilisateur**, jamais
    renvoyé à une ``redirect_uri`` non enregistrée — la suite échoue dès que
    ``processCallback()`` est appelé ou que la redirection part vers le chemin
    d'erreur. Exigence OIDCC-3.1.2.1 / RFC 6749 §4.1.2.1.
    """
    assert result.callback_url == "", (
        f"aucune redirection ne doit partir vers l'URI inconnue : {result.callback_url}"
    )
    assert result.status_code == 400, f"page d'erreur attendue, reçu HTTP {result.status_code}"
    assert "invalid_redirect_uri" in result.body, (
        f"la page doit expliquer le rejet de la redirect_uri (corpus : {result.body[:200]!r})"
    )


def expect_second_login_page(result: FlowResult) -> None:
    """``ExpectSecondLoginPage`` (``oidcc-prompt-login``, ``oidcc-max-age-1``).

    « The server must ask the user to login for a second time » : la suite
    matche l'URL de la réponse finale sur ``{OPURL}/login*``. Le harness
    rejoue chaque passe dans la session établie par la précédente — toute page
    de connexion présentée dans la passe courante est donc bien **la seconde**,
    et son absence prouve que l'OP a laissé la session existante passer.
    """
    assert result.login_pages >= 1, (
        "une seconde page de connexion était exigée alors que l'utilisateur "
        f"était déjà authentifié (redirections : {result.hops})"
    )


def check_second_auth_time_is_later(first: int, second: int) -> None:
    """``CheckSecondIdTokenAuthTimeIsLaterIfPresent`` (prompt=login, max_age).

    Un ``auth_time`` égal ou antérieur prouve que le second id_token repose
    sur la **même** authentification : l'égalité est une erreur, une valeur
    décrémentée l'est aussi — il faut strictement postérieur.
    """
    assert second > first, (
        f"auth_time de la seconde session ({second}) doit être strictement "
        f"postérieur à celui de la première ({first})"
    )


def check_auth_time_present(auth_time: int | None) -> None:
    """``CheckIdTokenAuthTimeClaimPresentDueToMaxAge`` (``oidcc-max-age-1``).

    ``max_age`` est demandé : l'id_token doit porter ``auth_time`` (OIDC Core
    1.0 §2 : exigé quand ``max_age`` est en jeu), sinon l'âge de la session
    n'est pas vérifiable.
    """
    assert auth_time is not None, "le claim auth_time est requis quand max_age est présent"


def check_auth_time_recent(auth_time: int, now: int) -> None:
    """``CheckIdTokenAuthTimeIsRecentIfPresent`` (``oidcc-max-age-1``).

    L'authentification doit dater de moins de 5 minutes d'horloge (tolérance
    d'écart de la suite), au-delà le rejeu du check est incohérent.
    """
    assert now - auth_time <= _MAX_SKEW_SECONDS, (
        f"auth_time trop ancien : {now - auth_time}s > {_MAX_SKEW_SECONDS}s"
    )


def expect_callback_success(result: FlowResult, state: str) -> None:
    """Callback heureux du parcours « code » (33 modules Basic).

    Enchaîne ``CheckIfAuthorizationEndpointError``,
    ``CheckStateInAuthorizationResponse`` et
    ``ExtractAuthorizationCodeFromAuthorizationResponse`` de ``processCallback()`` :
    aucun ``error`` en query/fragment, le ``state`` renvoyé identique à celui
    envoyé, et un code d'autorisation présent.
    """
    assert result.error == "", (
        f"aucune erreur d'autorisation attendue : {result.error!r} ({result.hops})"
    )
    assert result.returned_state == state, (
        f"state renvoyé ({result.returned_state!r}) != state envoyé ({state!r})"
    )
    assert result.code, f"code d'autorisation absent du callback : {result.callback_url!r}"


def expect_implicit_callback(result: FlowResult, state: str, *, with_token: bool) -> None:
    """Callback heureux des flux implicites (``OIDCCServerTest``, PR 3).

    ``response_type=id_token`` / ``id_token token`` : tout arrive en **fragment**
    (RFC 6749 §4.2.2.1), sans code — ``CheckMatchingCallbackParameters`` +
    ``CheckStateInAuthorizationResponse`` + ``ExtractIdTokenFromAuthorizationResponse``,
    l'id_token y compris, et ``ExtractAccessTokenFromTokenResponse`` injecté par
    le fragment quand ``token`` est demandé (``with_token``).
    """
    assert result.error == "", (
        f"aucune erreur d'autorisation attendue : {result.error!r} ({result.hops})"
    )
    assert result.returned_state == state, (
        f"state renvoyé ({result.returned_state!r}) != state envoyé ({state!r})"
    )
    assert not result.code, f"aucun code en flux implicite : {result.callback_url!r}"
    assert result.id_token, f"id_token absent du fragment : {result.callback_url!r}"
    if with_token:
        assert result.access_token, f"access_token absent du fragment : {result.callback_url!r}"
    else:
        assert not result.access_token, (
            f"access_token ne doit pas être émis : {result.callback_url!r}"
        )


def expect_hybrid_callback(
    result: FlowResult, state: str, *, with_id_token: bool, with_token: bool
) -> None:
    """Callback heureux des flux hybrides (``OIDCCServerTest``, PR 3).

    ``response_type=code id_token`` / ``code token`` / ``code id_token token`` :
    ``response_mode`` par défaut est le fragment (OIDC Core 1.0 §3.3.2.1) : le
    code, l'id_token et l'access_token éventuels y figurent —
    ``CheckMatchingCallbackParameters``, ``CheckStateInAuthorizationResponse``,
    ``ExtractAuthorizationCodeFromAuthorizationResponse``,
    ``ExtractIdTokenFromAuthorizationResponse`` et
    ``ExtractAccessTokenFromAuthorizationResponse``.
    """
    assert result.error == "", (
        f"aucune erreur d'autorisation attendue : {result.error!r} ({result.hops})"
    )
    assert result.returned_state == state, (
        f"state renvoyé ({result.returned_state!r}) != state envoyé ({state!r})"
    )
    assert result.code, f"code absent du fragment : {result.callback_url!r}"
    if with_id_token:
        assert result.id_token, f"id_token absent du fragment : {result.callback_url!r}"
    else:
        assert not result.id_token, f"id_token ne doit pas être émis : {result.callback_url!r}"
    if with_token:
        assert result.access_token, f"access_token absent du fragment : {result.callback_url!r}"
    else:
        assert not result.access_token, (
            f"access_token ne doit pas être émis : {result.callback_url!r}"
        )


def expect_authorization_error(
    result: FlowResult, state: str, allowed_errors: tuple[str, ...]
) -> None:
    """Structure imposée à toute erreur du endpoint d'autorisation.

    Reproduit ``performGenericAuthorizationEndpointErrorResponseValidation`` :
    ``EnsureErrorFromAuthorizationEndpointResponse``,
    ``RejectAuthCodeInAuthorizationEndpointResponse`` et
    ``CheckStateInAuthorizationResponse`` — ``error`` ∈ *allowed*, ``state``
    repris à l'identique, **jamais** de ``code``.
    """
    assert result.error, (
        f"une erreur d'autorisation était attendue (hops : {result.hops}, corps : "
        f"{result.body[:200]!r})"
    )
    assert result.error in allowed_errors, (
        f"error={result.error!r} hors {allowed_errors} (OIDC Core 1.0 §3.1.2.6)"
    )
    assert not result.code, f"aucun code ne doit accompagner l'erreur : {result.callback_url!r}"
    assert result.returned_state == state, (
        f"state renvoyé ({result.returned_state!r}) != state envoyé ({state!r})"
    )


def _left_half_hash(value: str) -> str:
    """Empreinte attendue d'un claim ``*_hash`` (SHA-256, moitié gauche, base64url)."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def check_front_channel_artefact_hashes(
    id_token_claims: dict[str, Any], *, code: str, state: str
) -> None:
    """``c_hash`` (OIDC Core 1.0 §3.3.2.11) et ``s_hash`` (FAPI1-ADV-5.2.2.1-5).

    L'id_token livré dans le fragment du flow hybride porte l'empreinte
    (moitié gauche SHA-256 pour RS*/PS*) du ``code`` émis et du ``state``
    présenté — ``ExtractSHash`` échoue en FAILURE sans ``s_hash``, et
    ``CheckCHash``/``ExtractCHash`` contrôlent ``c_hash``. Sans ``state``
    dans le JAR, ni ``state`` ni ``s_hash`` ne sont émis
    (``VerifyNoSHash``).
    """
    assert id_token_claims.get("c_hash") == _left_half_hash(code), (
        f"c_hash incorrect : {id_token_claims.get('c_hash')!r} pour le code {code!r}"
    )
    if state:
        assert id_token_claims.get("s_hash") == _left_half_hash(state), (
            f"s_hash incorrect : {id_token_claims.get('s_hash')!r} pour le state {state!r} "
            "(FAPI1-ADV-5.2.2.1-5)"
        )


def expect_response_type_missing_error_page(result: FlowResult) -> None:
    """``ExpectResponseTypeMissingErrorPage`` (``oidcc-response-type-missing``).

    Sans ``response_type``, l'OP doit afficher la page d'erreur **ou** renvoyer
    une erreur de callback (ici : page, RFC 6749 §3.1.1) — jamais de code.
    """
    assert result.callback_url == "", f"aucun code ne doit être émis : {result.callback_url!r}"
    assert result.status_code == 400, f"page d'erreur attendue, reçu HTTP {result.status_code}"
    assert "Erreur" in result.body or "error" in result.body.lower(), (
        f"la page doit annoncer l'erreur (corpus : {result.body[:200]!r})"
    )


def check_token_endpoint_success(response: httpx.Response) -> dict[str, Any]:
    """Valide la réponse d'un grant réussi au token endpoint.

    Enchaîne ``CheckTokenEndpointHttpStatus200``, ``CheckForAccessTokenValue``,
    ``CheckTokenTypeIsBearer`` et ``ValidateExpiresIn`` : JSON en 200,
    ``access_token`` présent, ``token_type=Bearer``, ``expires_in`` si présent
    doit être un entier positif.
    """
    assert response.status_code == 200, f"HTTP {response.status_code} : {response.text[:300]}"
    payload = json.loads(response.text)
    assert payload.get("access_token"), f"access_token absent : {sorted(payload)}"
    assert str(payload.get("token_type", "")).lower() == "bearer", (
        f"token_type != Bearer : {payload.get('token_type')!r}"
    )
    if "expires_in" in payload:
        assert int(payload["expires_in"]) > 0, f"expires_in invalide : {payload['expires_in']!r}"
    return payload


def validate_id_token(claims: dict[str, Any], *, issuer: str, client_id: str, nonce: str) -> None:
    """``ValidateIdToken`` + ``ValidateIdTokenNonce`` + ``CheckForSubjectInIdToken``.

    ``iss`` identique au discovery, ``aud`` contenant le client, ``exp``/``iat``
    non expirés (< 5 min de skew), ``nonce`` repris ou absent des deux côtés,
    ``sub`` présent et non vide.
    """
    now = time.time()
    assert claims.get("iss") == issuer, f"iss={claims.get('iss')!r} != {issuer!r}"
    audience = claims.get("aud")
    assert client_id in ([audience] if isinstance(audience, str) else list(audience or [])), (
        f"aud={audience!r} ne contient pas {client_id!r}"
    )
    assert int(claims["exp"]) > now - _MAX_SKEW_SECONDS, f"exp expiré : {claims.get('exp')}"
    assert int(claims["iat"]) <= now + _MAX_SKEW_SECONDS, f"iat dans le futur : {claims.get('iat')}"
    sub = claims.get("sub")
    assert sub, f"sub absent ou vide : {sorted(claims)}"
    assert claims.get("nonce") == nonce, (
        f"nonce renvoyé ({claims.get('nonce')!r}) != nonce envoyé ({nonce!r})"
    )


def expect_id_token_signature(header: dict[str, Any]) -> None:
    """Vérifie le header JWS de l'id_token (``oidcc-idtoken-signature``).

    ``EnsureIdTokenSignatureIsRS256`` + ``EnsureIdTokenContainsKid`` : le
    header doit porter ``alg=RS256`` et un ``kid`` (OIDC Core 1.0 §3.1.3.7 /
    §10.1, aligné sur ``jwks_algorithms=RS256``).
    """
    assert header.get("alg") == "RS256", f"alg={header.get('alg')!r} != RS256"
    assert header.get("kid"), f"kid absent du header : {sorted(header)}"


def check_authorization_code_quality(code: str) -> None:
    """``EnsureMinimumAuthorizationCodeLength`` + ``EnsureMinimumAuthorizationCodeEntropy``.

    Le code d'autorisation doit être d'une longueur et d'une entropie
    minimales (RFC 6749 §4.1.2) — au-delà, la réutilisation est trop aisée.
    """
    assert len(code) >= _MIN_CODE_LENGTH, f"code trop court : {len(code)} < {_MIN_CODE_LENGTH}"
    assert len(set(code)) >= _MIN_CODE_LENGTH // 2, (
        f"entropie trop faible pour un code de {len(code)} caractères : {code[:8]!r}…"
    )


def _left_half_hash(value: str) -> str:
    """Left-most half of the hash de ``value`` en base64url sans padding (RS256 → SHA-256)."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def check_at_hash(claims: dict[str, Any], access_token: str) -> None:
    """``ValidateAtHash`` (``at_hash`` de ``OIDCCServerTest``, flux avec access_token).

    OIDC Core 1.0 §3.3.2.1 : le claim ``at_hash`` est la gauche du hash SHA-256
    de l'access_token (algorithme de signature RS256), encodée base64url.
    """
    assert claims.get("at_hash"), f"at_hash absent : {sorted(claims)}"
    expected = _left_half_hash(access_token)
    assert claims["at_hash"] == expected, (
        f"at_hash={claims['at_hash']!r} != left-half-SHA256(access_token)={expected!r}"
    )


def check_c_hash(claims: dict[str, Any], code: str) -> None:
    """``ValidateCHash`` (``c_hash`` de ``OIDCCServerTest``, flux hybrides).

    OIDC Core 1.0 §3.3.2.1 : ``c_hash`` = gauche du hash SHA-256 du code
    d'autorisation (RS256), encodée base64url — obligatoire dès que le code et
    un id_token sont renvoyés ensemble.
    """
    assert claims.get("c_hash"), f"c_hash absent : {sorted(claims)}"
    expected = _left_half_hash(code)
    assert claims["c_hash"] == expected, (
        f"c_hash={claims['c_hash']!r} != left-half-SHA256(code)={expected!r}"
    )


def check_userinfo_response(response: httpx.Response, expected_sub: str) -> dict[str, Any]:
    """Valide la réponse du userinfo (modules ``oidcc-userinfo-*``, ``oidcc-scope-*``).

    ``EnsureHttpStatusCodeIs200``, ``EnsureContentTypeJson``,
    ``EnsureUserInfoContainsSub`` et
    ``VerifyUserInfoAndIdTokenInTokenEndpointSameSub`` : 200 en JSON avec un
    ``sub`` identique à celui de l'id_token (OIDC Core 1.0 §5.3.1).
    """
    assert response.status_code == 200, (
        f"userinfo HTTP {response.status_code} : {response.text[:300]}"
    )
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    userinfo = json.loads(response.text)
    assert userinfo.get("sub"), f"sub absent du userinfo : {sorted(userinfo)}"
    assert userinfo["sub"] == expected_sub, (
        f"sub userinfo ({userinfo['sub']}) != sub id_token ({expected_sub})"
    )
    return userinfo


def check_scope_claims_returned(userinfo: dict[str, Any], requested_scope: str) -> None:
    """``VerifyScopesReturnedInUserInfoClaims`` (modules ``oidcc-scope-*``).

    Les claims des scopes demandés doivent figurer dans le userinfo — dans la
    suite ce check est un WARNING, ici une assertion plus stricte : le rejeu
    doit prouver le rendu effectif des claims.
    """
    for scope in requested_scope.split():
        if scope in _SCOPE_CLAIMS:
            missing = [claim for claim in _SCOPE_CLAIMS[scope] if claim not in userinfo]
            assert not missing, f"claims du scope {scope!r} absents du userinfo : {missing}"


def check_scope_claims_in_id_token(claims: dict[str, Any], requested_scope: str) -> None:
    """``VerifyScopesReturnedInAuthorizationEndpointIdToken``.

    Flux ``response_type=id_token`` (sans access_token) : les claims des
    scopes demandés doivent figurer dans l'id_token émis par le endpoint
    d'autorisation (OIDC Core 1.0 §5.4 — sans UserInfo possible, c'est la
    seule source). Même table ``SCOPE_STANDARD_CLAIMS`` que le userinfo.
    """
    for scope in requested_scope.split():
        if scope in _SCOPE_CLAIMS:
            missing = [claim for claim in _SCOPE_CLAIMS[scope] if claim not in claims]
            assert not missing, f"claims du scope {scope!r} absents de l'id_token : {missing}"


def check_scope_claims_absent_from_id_token(claims: dict[str, Any], requested_scope: str) -> None:
    """``EnsureIdTokenDoesNotContain*`` (OIDCC-5.1.1 / ``oidcc-scope-*``).

    Hors ``response_type=id_token`` pur, l'id_token ne doit pas porter les
    claims des scopes accordés : ils sont rendus par ``/userinfo``, et leur
    présence ici exposerait les identifiants au-delà du canal prévu.
    """
    for scope in requested_scope.split():
        if scope in _SCOPE_CLAIMS:
            leaked = [claim for claim in _SCOPE_CLAIMS[scope] if claim in claims]
            assert not leaked, (
                f"claims du scope {scope!r} ne doivent pas figurer dans l'id_token : {leaked}"
            )


def check_acr_claim(claims: dict[str, Any], requested_acr_values: str) -> None:
    """``ValidateIdTokenACRClaimAgainstAcrValuesRequest`` (``oidcc-*-acr-values-*``).

    ``acr`` doit être présent dans l'id_token **et** être l'une des valeurs
    de la ``acr_values`` demandée (OIDC Core 1.0 §3.1.2.1 / §2 — la suite
    exige membership, pas égalité stricte à la liste entière).
    """
    acr = claims.get("acr")
    assert acr is not None and acr != "", (
        f"acr absent de l'id_token alors que acr_values={requested_acr_values!r} : {sorted(claims)}"
    )
    allowed = requested_acr_values.split()
    assert acr in allowed, f"acr={acr!r} hors des valeurs demandées {allowed}"


def expect_invalid_grant(response: httpx.Response) -> None:
    """Valide le rejet « invalid_grant » (réutilisation de code, refresh croisé).

    ``CheckErrorFromTokenEndpointResponseErrorInvalidGrant`` +
    ``CheckTokenEndpointHttpStatus400`` +
    ``CheckTokenEndpointReturnedJsonContentType`` : réponse 400 en JSON
    portant ``error=invalid_grant`` (RFC 6749 §5.2), structure contrôlée par
    ``ValidateErrorFromTokenEndpointResponseError``.
    """
    assert response.status_code == 400, f"HTTP {response.status_code} : {response.text[:300]}"
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    payload = json.loads(response.text)
    assert payload.get("error") == "invalid_grant", (
        f"error={payload.get('error')!r} != invalid_grant : {payload}"
    )


def expect_access_token_refused(response: httpx.Response) -> None:
    """``CallProtectedResource`` + ``EnsureHttpStatusCodeIs4xx`` (codereuse).

    RFC 6749 §4.1.2 : un code réutilisé doit faire révoquer « quand c'est
    possible » les jetons déjà émis. La suite se contente d'attendre un 4xx
    (WARNING sinon) ; l'assertion est stricte ici : 401 ``invalid_token``
    avec l'en-tête ``WWW-Authenticate`` (RFC 6750 §3.1).
    """
    assert response.status_code == 401, (
        f"l'access token révoqué doit être refusé (401), reçu HTTP "
        f"{response.status_code} : {response.text[:300]}"
    )
    payload = json.loads(response.text)
    assert payload.get("error") == "invalid_token", (
        f"error={payload.get('error')!r} != invalid_token : {payload}"
    )


def check_second_id_token_consistent(
    first_claims: dict[str, Any], second_claims: dict[str, Any]
) -> None:
    """Comparaison des deux id_tokens d'une double autorisation.

    ``CheckIdTokenAuthTimeClaimsSameIfPresent`` +
    ``CheckIdTokenSubConsistentForSecondAuthorization`` : même ``sub`` et,
    si présent, même ``auth_time`` (modules : ``oidcc-prompt-none-logged-in``,
    ``oidcc-id-token-hint``, ``oidcc-max-age-10000``).
    """
    assert first_claims.get("sub") == second_claims.get("sub"), (
        f"sub incohérent entre les deux autorisations : {first_claims.get('sub')!r} != "
        f"{second_claims.get('sub')!r}"
    )
    assert first_claims.get("auth_time") == second_claims.get("auth_time"), (
        f"auth_time incohérent : {first_claims.get('auth_time')!r} != "
        f"{second_claims.get('auth_time')!r}"
    )


def check_refreshed_id_token_claims(
    first_claims: dict[str, Any], second_claims: dict[str, Any]
) -> None:
    """``CompareIdTokenClaims`` (OIDCC-12.2) pour le grant refresh token.

    OIDC Core 1.0 §12.2 : ``iss``/``sub``/``aud`` identiques, ``iat`` du
    second id_token **strictement postérieur** à celui du premier, ``auth_time``
    identique **si présent** dans le second, ``azp`` absent du premier → absent
    du second.
    """
    for claim in ("iss", "sub", "aud"):
        assert claim in first_claims, f"id_token initial sans {claim}"
        assert claim in second_claims, f"id_token rafraîchi sans {claim}"
        assert first_claims[claim] == second_claims[claim], (
            f"{claim} incohérent après refresh : {first_claims[claim]!r} != "
            f"{second_claims[claim]!r}"
        )
    assert int(second_claims["iat"]) != int(first_claims["iat"]), (
        f"iat identique après refresh : {second_claims['iat']!r} (le second iat doit "
        "représenter la nouvelle émission)"
    )
    if "auth_time" in second_claims:
        assert second_claims.get("auth_time") == first_claims.get("auth_time"), (
            f"auth_time incohérent après refresh : {first_claims.get('auth_time')!r} != "
            f"{second_claims.get('auth_time')!r}"
        )
    assert not second_claims.get("azp") or first_claims.get("azp") == second_claims.get("azp"), (
        "azp présent alors que l'id_token initial n'en portait pas (OIDC Core 1.0 §12.2)"
    )


def check_backchannel_ack(response: httpx.Response) -> dict[str, Any]:
    """Acquittement de ``/bc-authorize`` (modules ``fapi-ciba-id1-*``).

    Enchaîne ``CheckBackchannelAuthenticationEndpointHttpStatus200``,
    ``CheckBackchannelAuthenticationEndpointContentType``,
    ``CheckIfBackchannelAuthenticationEndpointResponseError``,
    ``ValidateAuthenticationRequestId`` (charset),
    ``EnsureMinimumAuthenticationRequestIdLength`` /
    ``...Entropy`` (≥ 128 bits), ``ValidateAuthenticationRequestIdExpiresIn``
    (0 < ``expires_in`` ≤ 1 an) et ``ValidateAuthenticationRequestIdInterval``
    (0 ≤ ``interval`` ≤ 6 h) — ``performValidateAuthorizationResponse()``.
    """
    assert response.status_code == 200, (
        f"HTTP {response.status_code} sur /bc-authorize : {response.text[:300]}"
    )
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    payload = json.loads(response.text)
    assert "error" not in payload, f"acquittement en erreur : {payload}"
    auth_req_id = payload.get("auth_req_id", "")
    assert isinstance(auth_req_id, str) and auth_req_id, f"auth_req_id absent : {sorted(payload)}"
    assert re.fullmatch(_AUTH_REQ_ID_PATTERN, auth_req_id), (
        f"auth_req_id hors [A-Za-z0-9._-] : {auth_req_id!r}"
    )
    assert len(auth_req_id) * 8 >= _MIN_TOKEN_LENGTH_BITS, (
        f"auth_req_id trop court : {len(auth_req_id)} caractères (< 128 bits)"
    )
    assert len(set(auth_req_id)) >= _MIN_CODE_LENGTH, (
        f"entropie trop faible pour auth_req_id : {auth_req_id[:16]!r}…"
    )
    expires_in = payload.get("expires_in")
    assert isinstance(expires_in, int) and not isinstance(expires_in, bool), (
        f"expires_in non entier : {payload.get('expires_in')!r}"
    )
    assert 0 < expires_in <= _MAX_ACK_EXPIRES_IN, f"expires_in hors bornes : {expires_in}"
    interval = payload.get("interval")
    if interval is not None:
        assert isinstance(interval, int) and not isinstance(interval, bool), (
            f"interval non entier : {payload.get('interval')!r}"
        )
        assert 0 <= interval <= _MAX_ACK_INTERVAL, f"interval hors bornes : {interval}"
    return payload


def check_pending_or_slowdown(response: httpx.Response) -> str:
    """Poll en attente : ``authorization_pending`` ou ``slow_down`` (§11).

    ``verifyTokenEndpointResponseIsPendingOrSlowDown()`` :
    ``CheckTokenEndpointHttpStatus400``, structure ``RFC6749-5.2`` de l'erreur
    (``ValidateErrorFromTokenEndpointResponseError``,
    ``ValidateErrorDescription...``, sans CRLF/TAB —
    ``CheckErrorDescription...ContainsCRLFTAB``) puis
    ``EnsureErrorTokenEndpointSlowdownOrAuthorizationPending``.
    Retourne l'``error`` observé.
    """
    return check_token_error(response, ("authorization_pending", "slow_down"), status_code=400)


def check_token_error(
    response: httpx.Response,
    expected_errors: tuple[str, ...],
    *,
    status_code: int | None = 400,
    allow_statuses: tuple[int, ...] = (),
) -> str:
    """Erreur structurée du token endpoint (RFC 6749 §5.2 / CIBA §11, §13).

    ``ValidateErrorFromTokenEndpointResponseError`` +
    ``ValidateErrorDescription...`` : JSON, ``error`` ∈ *expected_errors*,
    ``error_description`` présent sans CRLF/TAB. ``status_code`` fixe le code
    attendu (``None`` : aucun contrôle) ; ``allow_statuses`` ajoute des codes
    admissibles (``CheckTokenEndpointHttpStatusIs400Allowing401ForInvalidClientError``).
    """
    accepted = (status_code,) if status_code is not None else ()
    accepted = (*accepted, *allow_statuses)
    if accepted:
        assert response.status_code in accepted, (
            f"HTTP {response.status_code} hors {accepted} : {response.text[:300]}"
        )
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    payload = json.loads(response.text)
    error = payload.get("error")
    assert error in expected_errors, f"error={error!r} hors {expected_errors} : {payload}"
    description = payload.get("error_description")
    assert isinstance(description, str) and description, (
        f"error_description absent : {sorted(payload)}"
    )
    assert not any(char in description for char in "\r\n\t"), (
        f"error_description contient CRLF/TAB : {description!r}"
    )
    return str(error)


def check_ciba_token_success(response: httpx.Response, *, expect_refresh: bool) -> dict[str, Any]:
    """Réponse réussie du grant CIBA (``handleSuccessfulTokenEndpointResponse()``).

    ``CheckTokenEndpointHttpStatus200`` + ``CheckTokenEndpointCacheHeaders``
    (``no-store``, CIBA-10.1.1) + ``CheckForAccessTokenValue`` +
    ``ValidateExpiresIn`` + ``EnsureMinimumAccessTokenLength/Entropy`` +
    ``CheckForRefreshTokenValue`` + ``EnsureMinimumRefreshTokenLength/Entropy``
    + ``ExtractIdToken`` + ``EnsureIdTokenContainsKid`` +
    ``FAPIValidateIdTokenSigningAlg`` (PS256, FAPI-RW-8.6).
    """
    assert response.status_code == 200, f"HTTP {response.status_code} : {response.text[:300]}"
    assert "no-store" in response.headers.get("cache-control", ""), (
        f"Cache-Control sans no-store : {response.headers.get('cache-control')!r}"
    )
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    payload = json.loads(response.text)
    assert "error" not in payload, f"réponse en erreur : {payload}"
    access_token = payload.get("access_token", "")
    assert isinstance(access_token, str) and len(access_token) * 8 >= _MIN_TOKEN_LENGTH_BITS, (
        f"access_token trop court : {sorted(payload)}"
    )
    assert str(payload.get("token_type", "")).lower() == "bearer", (
        f"token_type != Bearer : {payload.get('token_type')!r}"
    )
    expires_in = payload.get("expires_in")
    assert isinstance(expires_in, int) and not isinstance(expires_in, bool) and expires_in > 0, (
        f"expires_in invalide : {payload.get('expires_in')!r}"
    )
    refresh_token = payload.get("refresh_token")
    if refresh_token:
        assert re.fullmatch(_BEARER_TOKEN_PATTERN, str(refresh_token)), (
            f"refresh_token hors b64token (RFC 6749 §A.17) : {str(refresh_token)[:24]!r}…"
        )
        assert len(str(refresh_token)) * 8 >= _MIN_TOKEN_LENGTH_BITS, (
            f"refresh_token trop court : {len(str(refresh_token))} caractères"
        )
    if expect_refresh:
        assert refresh_token, f"refresh_token absent (offline_access demandé) : {sorted(payload)}"
    return dict(payload)


def check_ciba_id_token_header(id_token: str) -> dict[str, Any]:
    """En-tête de l'id_token CIBA (``EnsureIdTokenContainsKid``, FAPI-RW-8.6).

    ``ExtractIdToken`` extrait le jeton de la réponse ``/token`` puis
    ``EnsureIdTokenContainsKid`` (OIDCD-10.1) exige un ``kid`` et
    ``FAPIValidateIdTokenSigningAlg`` (FAPI-RW-8.6) impose ``PS256`` —
    borne du profil FAPI-CIBA-ID1 §5.2.2. Retourne l'en-tête décodé.
    """
    header = id_token.split(".")[0]
    header += "=" * (-len(header) % 4)
    decoded = dict(json.loads(base64.urlsafe_b64decode(header)))
    assert decoded.get("kid"), f"kid absent de l'en-tête id_token : {decoded}"
    assert decoded.get("alg") == "PS256", (
        f"alg id_token={decoded.get('alg')!r} != PS256 (FAPI-RW-8.6)"
    )
    return decoded


def check_backchannel_error(
    response: httpx.Response,
    expected_errors: tuple[str, ...],
    *,
    allow_statuses: tuple[int, ...] = (400,),
) -> str:
    """Erreur de ``/bc-authorize`` (``validateErrorFromBackchannelAuthorizationRequestResponse()``).

    ``ValidateErrorResponseFromBackchannelAuthenticationEndpoint`` +
    ``ValidateErrorDescription...`` (JSON, ``error`` ∈ *expected_errors*,
    ``error_description`` sans CRLF/TAB), ``CheckBackchannelAuthenticationEndpoint
    HttpStatus400`` (CIBA-13 ; 401/403 admis via *allow_statuses* selon
    ``CheckBackchannelAuthenticationEndpointErrorHttpStatus`` : ``invalid_client``
    → 400/401, ``access_denied`` → 403) et
    ``CheckErrorFromBackchannelAuthenticationEndpointErrorInvalidRequest``.
    """
    return check_token_error(
        response,
        expected_errors,
        status_code=None,
        allow_statuses=allow_statuses,
    )


def check_fapi_ciba_discovery(metadata: dict[str, Any]) -> None:
    """Document de discovery du module ``FAPICIBAID1DiscoveryEndpointVerification``.

    ``GetDynamicServerConfiguration`` (200 + JSON), ``CheckDiscEndpointIssuer``
    / ``...IsValidUrl`` (OIDCD-4.3, RFC8414-2), les endpoints requis
    (``CheckDiscEndpointTokenEndpoint``, ``CheckJwksUri``,
    ``CheckDiscBackchannelAuthorizationEndpoint`` CIBA-4,
    ``CheckDiscEndpointRegistrationEndpoint`` OIDCD-3),
    ``CheckDiscEndpointIdTokenSigningAlgValuesSupportedContainsPS256OrES256``
    (FAPI-RW-8.6),
    ``CheckDiscEndpointTokenEndpointAuthMethodsSupportedContainsPrivateKeyOrTlsClient``
    (FAPI-RW-5.2.2-14), ``CheckDiscEndpointTokenEndpointAuthSigningAlgValuesSupported``
    (FAPI-RW-8.6, écart connu — issue #110, non asserté), les checks CIBA
    ``...BackchannelAuthenticationRequestSigningAlgValuesSupported`` +
    ``CheckBackchannelUserCodeParameterSupported`` +
    ``FAPICIBACheckDiscEndpointGrantTypesSupported``
    (CIBA-4) et ``CheckBackchannelTokenDeliveryPollModeSupported``
    (FAPI-RW-5.2.2-6), enfin ``CheckDiscEndpointScopesSupportedSyntax``
    (RFC6749-3.3). ``CheckTLSClientCertificateBoundAccessTokensTrue``
    (FAPI-RW-5.2.2-6) n'est pas asserté : jetons non contraints par
    certificat (écart connu — issue #110).
    """
    issuer = str(metadata.get("issuer", ""))
    assert issuer.startswith(("http://", "https://")), f"issuer invalide : {issuer!r}"
    for key in (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "backchannel_authentication_endpoint",
        "registration_endpoint",
    ):
        value = metadata.get(key)
        assert isinstance(value, str) and value.startswith(("http://", "https://")), (
            f"{key} absent ou invalide : {value!r}"
        )
    id_token_algs = list(metadata.get("id_token_signing_alg_values_supported") or [])
    assert "PS256" in id_token_algs or "ES256" in id_token_algs, (
        f"id_token_signing_alg_values_supported sans PS256/ES256 : {id_token_algs}"
    )
    auth_methods = list(metadata.get("token_endpoint_auth_methods_supported") or [])
    assert "private_key_jwt" in auth_methods, (
        f"token_endpoint_auth_methods_supported sans private_key_jwt : {auth_methods}"
    )
    bc_signing = list(
        metadata.get("backchannel_authentication_request_signing_alg_values_supported") or []
    )
    assert set(bc_signing) & {"PS256", "ES256"}, f"bc signing algs sans PS256/ES256 : {bc_signing}"
    user_code = metadata.get("backchannel_user_code_parameter_supported")
    assert user_code is None or isinstance(user_code, bool), (
        f"backchannel_user_code_parameter_supported non booléen : {user_code!r}"
    )
    grants = list(metadata.get("grant_types_supported") or [])
    assert "urn:openid:params:grant-type:ciba" in grants, (
        f"grant_types_supported sans urn:openid:params:grant-type:ciba : {grants}"
    )
    delivery = list(metadata.get("backchannel_token_delivery_modes_supported") or [])
    assert "poll" in delivery, f"backchannel_token_delivery_modes_supported sans poll : {delivery}"
    scopes = list(metadata.get("scopes_supported") or [])
    assert scopes, "scopes_supported vide"
    for scope in scopes:
        assert isinstance(scope, str) and scope == scope.strip() and " " not in scope, (
            f"scope hors RFC6749-3.3 : {scope!r}"
        )


def check_ciba_id_token(
    claims: dict[str, Any],
    *,
    issuer: str,
    client_id: str,
    requested_acr: str = "",
    auth_req_id: str = "",
) -> None:
    """id_token du grant CIBA (``PerformStandardIdTokenChecks`` + profile).

    ``ValidateIdToken`` (iss/aud/exp/iat/sub) sans ``nonce`` (non demandé en
    CIBA), ``ValidateIdTokenNotIncludeCHashAndSHash`` (aucun ``c_hash``/
    ``s_hash`` hors flux front-channel),
    ``FAPICIBAValidateIdTokenAuthRequestIdClaims`` (claim ``auth_req_id``
    absent — ou identique s'il est émis) et, sous réserve que l'OP annonce
    ``acr_values_supported``, ``FAPICIBAValidateIdTokenACRClaims``.
    """
    now = time.time()
    assert claims.get("iss") == issuer, f"iss={claims.get('iss')!r} != {issuer!r}"
    audience = claims.get("aud")
    assert client_id in ([audience] if isinstance(audience, str) else list(audience or [])), (
        f"aud={audience!r} ne contient pas {client_id!r}"
    )
    assert int(claims["exp"]) > now - _MAX_SKEW_SECONDS, f"exp expiré : {claims.get('exp')}"
    assert int(claims["iat"]) <= now + _MAX_SKEW_SECONDS, f"iat dans le futur : {claims.get('iat')}"
    sub = claims.get("sub")
    assert sub, f"sub absent ou vide : {sorted(claims)}"
    assert not claims.get("c_hash"), f"c_hash ne doit pas figurer : {sorted(claims)}"
    assert not claims.get("s_hash"), f"s_hash ne doit pas figurer : {sorted(claims)}"
    if auth_req_id:
        assert claims.get("urn:openid:params:jwt:claim:auth_req_id", "") in ("", auth_req_id), (
            "claim auth_req_id incohérent dans l'id_token"
        )
    if requested_acr:
        acr = claims.get("acr")
        assert acr is not None and acr != "", f"acr absent : {sorted(claims)}"
        assert acr in requested_acr.split(), f"acr={acr!r} hors {requested_acr!r}"


def check_protected_resource(
    response: httpx.Response,
    *,
    interaction_id: str,
    subject: str,
    expect_date: bool,
) -> dict[str, Any]:
    """``/protected-resource`` (``requestProtectedResource()``).

    ``CallProtectedResource`` (FAPI-R-6.2.1-1/-3) : 200 JSON,
    ``EnsureResourceResponseReturnedJsonContentType`` (FAPI1-BASE-6.2.1-9),
    ``CheckForDateHeaderInResourceResponse`` (FAPI-R-6.2.1-10 — ``expect_date``
    : l'en-tête ``date`` est ajouté par le serveur HTTP, absent du transport
    ASGI ``TestClient``, vérifié par le smoke contre uvicorn) et l'écho
    ``x-fapi-interaction-id`` (FAPI 1.0 §7.4).
    """
    assert response.status_code == 200, (
        f"ressource HTTP {response.status_code} : {response.text[:300]}"
    )
    assert "application/json" in response.headers.get("content-type", ""), (
        f"Content-Type non JSON : {response.headers.get('content-type')!r}"
    )
    assert response.headers.get("x-fapi-interaction-id") == interaction_id, (
        "x-fapi-interaction-id non échoyé : "
        f"{response.headers.get('x-fapi-interaction-id')!r} != {interaction_id!r}"
    )
    if expect_date:
        assert response.headers.get("date"), "en-tête Date absent (FAPI-R-6.2.1-10)"
    payload = json.loads(response.text)
    assert payload.get("sub") == subject, f"sub ressource={payload.get('sub')!r} != {subject!r}"
    return dict(payload)
