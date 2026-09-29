"""Rejeu local des checks de reconnexion et de ``redirect_uri`` (issues #68, #69).

Trois modules de la suite officielle ``openid/conformance-suite`` rejoués ici
(release-v5.2.4, extraits consultés en lecture seule — ``TRACEABILITY.md``) :

- ``oidcc-ensure-registered-redirect-uri`` : la ``redirect_uri`` inconnue
  affiche une page d'erreur, jamais un 302 (RFC 6749 §4.1.2.1) ;
- ``oidcc-prompt-login`` : ``prompt=login`` impose une **seconde**
  authentification même pour un utilisateur déjà connecté ;
- ``oidcc-max-age-1`` : ``max_age`` dépassé renvoie vers le formulaire de
  connexion et l'id_token doit porter un ``auth_time`` récent.

Ces tests sont marqués ``conformance`` : exclus du gate, lancés par
``pytest -m conformance`` (et par le job ``conformance-tests`` de la CI).
"""

from __future__ import annotations

import secrets
import time

import pytest
from checks import (
    check_auth_time_present,
    check_auth_time_recent,
    check_second_auth_time_is_later,
    expect_redirect_uri_error_page,
    expect_second_login_page,
)
from harness import ConformanceHarness, FlowResult, new_verifier

# Granularité de ``auth_time`` : en secondes (``iat`` de la session). Il faut
# donc laisser passer une seconde pleine entre deux passes pour que le second
# ``auth_time`` soit mesurable, et deux secondes pour que ``max_age=1``
# soit dépassé au-delà de tout doute d'arrondi.
_AUTH_TIME_DELAY = 1.1
_MAX_AGE_DELAY = 2.1


def _claims(harness: ConformanceHarness, result: FlowResult, verifier: str) -> dict[str, object]:
    """Échange le code du callback et décode les claims de l'id_token."""
    return harness.id_token_claims(harness.exchange_code(result, verifier))


def _auth_time(claims: dict[str, object]) -> int:
    """``auth_time`` de l'id_token (exigé sur tous les parcours concernés)."""
    value = claims.get("auth_time")
    assert value is not None, f"claim auth_time absent : {sorted(claims)}"
    return int(value)


@pytest.mark.conformance
def test_ensure_registered_redirect_uri_displays_error_page(
    harness: ConformanceHarness,
) -> None:
    """``oidcc-ensure-registered-redirect-uri`` — page d'erreur, pas de 302.

    Reproduit ``CreateBadRedirectUriByAppending`` + ``ExpectRedirectUriErrorPage`` :
    l'URI poussée est ``redirect_uri`` + ``/`` + aléatoire, donc jamais
    enregistrée pour le client. Avant #68 l'OP répondait 302 ``invalid_client``
    vers cette même URI — la suite comptait l'échec (18/192 modules).
    """
    verifier = new_verifier()
    bad_redirect_uri = f"https://app.example/callback/{secrets.token_urlsafe(6)}"
    params = harness.authorize_params(verifier, redirect_uri=bad_redirect_uri)

    result = harness.run_flow(**params)

    expect_redirect_uri_error_page(result)


@pytest.mark.conformance
def test_prompt_login_forces_second_authentication(harness: ConformanceHarness) -> None:
    """``oidcc-prompt-login`` — ``prompt=login`` exige une seconde connexion.

    Reproduit ``WaitForOneSecond`` + ``ExpectSecondLoginPage`` +
    ``CheckSecondIdTokenAuthTimeIsLaterIfPresent`` : la seconde passe doit
    présenter une page de connexion **et** son id_token doit porter un
    ``auth_time`` strictement postérieur à celui de la première passe
    (égalité = même authentification = échec). Avant #68 ``prompt=login``
    était ignoré au profit du seul ``prompt=none``.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)

    first = harness.run_flow(**params)
    first_auth_time = _auth_time(_claims(harness, first, verifier))
    time.sleep(_AUTH_TIME_DELAY)

    second = harness.run_flow(**params, prompt="login")

    expect_second_login_page(second)
    second_auth_time = _auth_time(_claims(harness, second, verifier))
    check_second_auth_time_is_later(first_auth_time, second_auth_time)


@pytest.mark.conformance
def test_max_age_1_reprompts_authentication(harness: ConformanceHarness) -> None:
    """``oidcc-max-age-1`` — ``max_age=1`` dépassé : reconnexion et ``auth_time``.

    Reproduit ``WaitFor2Seconds`` + ``ExpectSecondLoginPage`` +
    ``CheckIdTokenAuthTimeClaimPresentDueToMaxAge`` +
    ``CheckSecondIdTokenAuthTimeIsLaterIfPresent`` +
    ``CheckIdTokenAuthTimeIsRecentIfPresent`` (moins de 5 minutes d'horloge).
    Avant #68 ``max_age`` n'était même pas parsé : l'OP émettait un second
    code sans reconnexion.
    """
    verifier = new_verifier()
    params = harness.authorize_params(verifier)

    first = harness.run_flow(**params)
    first_auth_time = _auth_time(_claims(harness, first, verifier))
    time.sleep(_MAX_AGE_DELAY)

    second = harness.run_flow(**params, max_age="1")

    expect_second_login_page(second)
    second_auth_time = _auth_time(_claims(harness, second, verifier))
    check_auth_time_present(second_auth_time)
    check_second_auth_time_is_later(first_auth_time, second_auth_time)
    check_auth_time_recent(second_auth_time, int(time.time()))
