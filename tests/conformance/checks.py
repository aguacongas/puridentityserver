"""Assertions dérivées des check modules officiels de la suite de certification.

Chaque fonction reproduit le comportement d'un ``testmodule`` Java de
`openid/conformance-suite` (release-v5.2.4, clone lecture seule utilisé pour
l'extraction — voir ``TRACEABILITY.md``). Le nom du check est rappelé dans
la docstring : c'est lui qui apparaît dans le rapport de certification et doit
rester traçable d'un test Python à l'autre.
"""

from __future__ import annotations

from harness import FlowResult

_MAX_SKEW_SECONDS = 300


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
