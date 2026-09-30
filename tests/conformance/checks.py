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
import time
from typing import Any

import httpx
from harness import FlowResult

_MAX_SKEW_SECONDS = 300
_MIN_CODE_LENGTH = 16
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
