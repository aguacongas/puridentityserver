"""Routes FastAPI du rôle OpenID 2.0 de l'OP (spec de migration).

L'OP peut jouer le rôle d'OP OpenID 2.0 afin de servir la migration d'un
parc existant :

- ``GET /openid20/checkid_setup`` : ouvre l'authentification OpenID 2.0
  (le RP est redirigé vers la page de connexion de l'OP) ;
- ``GET /openid20/continue`` : appelé après la connexion, rend au RP le
  fragment de réponse OpenID 2.0 (``openid.assoc_handle``) ;
- ``GET|POST /openid20/check_authentication`` : rend l'assertion OpenID 2.0
  (``claimed_id`` / ``identity``) correspondant au handle ;
- ``GET /openid20/id/{id}`` : preuve d'autorité de l'OP sur l'identifiant
  OpenID 2.0 qu'il a servi (spec §6), au format ``{"iss": ...}``.

Les routes ne sont montées que si le support de la migration est activé
(``openid20_migration_enabled``) : sans lui, aucun chemin n'est exposé.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import RedirectResponse, Response

from puridentityserver.application.openid20_provider import (
    OpenID20ProviderError,
    OpenID20ProviderUseCase,
)
from puridentityserver.identity.config import CurrentUserOptional

_JSON_MEDIA_TYPE = "application/json"
_TEXT_MEDIA_TYPE = "text/plain"


def openid20_provider_router(
    usecase: OpenID20ProviderUseCase,
    *,
    issuer: str,
) -> APIRouter:
    """Construit le routeur FastAPI du rôle OpenID 2.0 de l'OP.

    ``issuer`` est la valeur du claim ``iss`` : c'est elle que l'endpoint
    d'autorité (spec §6) doit restituer, à l'identique de l'ID Token.
    """
    router = APIRouter(tags=["openid20"])
    _mount_setup_routes(router, usecase)
    _mount_continue_routes(router, usecase)
    _mount_assertion_routes(router, usecase)
    _mount_authority_routes(router, usecase, issuer)
    return router


def _mount_setup_routes(router: APIRouter, usecase: OpenID20ProviderUseCase) -> None:
    """Monte ``/openid20/checkid_setup`` (ouverture du flux OpenID 2.0)."""

    @router.get(
        "/openid20/checkid_setup",
        summary="Ouvre une authentification OpenID 2.0 (checkid_setup)",
        response_model=None,
    )
    async def checkid_setup(
        openid_ns: str = Query("", alias="openid.ns"),
        openid_mode: str = Query("", alias="openid.mode"),
        openid_realm: str = Query("", alias="openid.realm"),
        openid_return_to: str = Query("", alias="openid.return_to"),
    ) -> Response:
        """Redirige l'agent utilisateur vers la connexion de l'OP."""
        if openid_mode and openid_mode != "id_2":
            return _text_error("invalid_request", "Mode OpenID 2.0 non supporté")
        if not openid_return_to:
            return _text_error("invalid_request", "openid.return_to est requis")
        if openid_realm and not openid_return_to.startswith(openid_realm):
            # OpenID 2.0 §9.2 : l'URI de retour doit être sous le realm.
            return _text_error("invalid_request", "openid.return_to hors du realm")
        try:
            state = await usecase.issue_state(openid_ns, openid_realm, openid_return_to)
        except OpenID20ProviderError as error:
            return _text_error(error.error, error.error_description)
        return RedirectResponse(_login_redirect(state), status_code=302)


def _mount_continue_routes(router: APIRouter, usecase: OpenID20ProviderUseCase) -> None:
    """Monte ``/openid20/continue`` (fin du flux après connexion)."""

    @router.get(
        "/openid20/continue",
        summary="Termine l'authentification OpenID 2.0 (après connexion)",
        response_model=None,
    )
    async def continue_setup(
        state: str = Query(""),
        user: CurrentUserOptional = None,
    ) -> Response:
        """Rend au RP le fragment de réponse OpenID 2.0 (``assoc_handle``)."""
        try:
            data = await usecase.read_state(state)
        except OpenID20ProviderError as error:
            return _text_error(error.error, error.error_description)
        if user is None:
            return RedirectResponse(_login_redirect(state), status_code=302)
        subject = str(user.id)
        identifier = await usecase.ensure_identifier(subject, data["realm"])
        handle = await usecase.issue_handle(subject, data["ns"], data["realm"], identifier)
        fragment = urlencode(
            {
                "openid.ns": data["ns"],
                "openid.mode": "id_2",
                "openid.op_endpoint": f"{usecase.base_url}/openid20/check_authentication",
                "openid.claimed_id": identifier,
                "openid.identity": identifier,
                "openid.assoc_handle": handle,
            }
        )
        return RedirectResponse(f"{data['return_to']}#{fragment}", status_code=302)


def _mount_assertion_routes(router: APIRouter, usecase: OpenID20ProviderUseCase) -> None:
    """Monte ``/openid20/check_authentication`` (assertion OpenID 2.0)."""

    @router.api_route(
        "/openid20/check_authentication",
        methods=["GET", "POST"],
        summary="Rend l'assertion OpenID 2.0 d'un handle (check_authentication)",
        response_model=None,
    )
    async def check_authentication(
        request: Request,
        checkid_handle: str = Query(""),
    ) -> Response:
        """Retourne l'assertion OpenID 2.0 (format ``clé:valeur``)."""
        handle = checkid_handle
        if not handle:
            form = await request.form()
            handle = str(form.get("checkid_handle", ""))
        if not handle:
            return _text_error("invalid_request", "checkid_handle est requis")
        try:
            assertion = await usecase.read_handle(handle)
        except OpenID20ProviderError as error:
            return _text_error(error.error, error.error_description)
        claimed_id = assertion["identifier"] or assertion["claimed_id"]
        lines = (
            f"ns:{assertion['ns']}",
            f"op_endpoint:{usecase.base_url}/openid20/check_authentication",
            f"claimed_id:{claimed_id}",
            f"identity:{claimed_id}",
            "expired:false",
        )
        # Le ``openid.assoc_handle`` reçu n'est pas renvoyé : c'est une
        # donnée fournie par l'appelant, la refléter dans le corps de la
        # réponse ouvrirait une faille d'injection (XSS reflété). Le RP
        # connaît déjà le handle qu'il a transmis.
        return Response(content="\n".join(lines) + "\n", media_type=_TEXT_MEDIA_TYPE)


def _mount_authority_routes(
    router: APIRouter, usecase: OpenID20ProviderUseCase, issuer: str
) -> None:
    """Monte ``/openid20/id/{id}`` (preuve d'autorité, spec §6)."""

    @router.get(
        "/openid20/id/{identifier_id}",
        summary="Preuve d'autorité de l'OP sur un identifiant OpenID 2.0",
        response_model=None,
    )
    async def identifier_authority(identifier_id: str) -> Response:
        """Retourne ``{"iss": ...}`` : l'OP est l'autorité de l'identifiant."""
        identifier = usecase.identifier_url(identifier_id)
        association = await usecase.authority_of(identifier)
        if association is None:
            return Response(
                content=json.dumps({"error": "not_found"}),
                media_type=_JSON_MEDIA_TYPE,
                status_code=404,
            )
        return Response(content=json.dumps({"iss": issuer}), media_type=_JSON_MEDIA_TYPE)


def _login_redirect(state: str) -> str:
    """URL de la page de connexion portant l'état OpenID 2.0 en ``next``."""
    next_url = f"/openid20/continue?state={quote(state, safe='')}"
    return f"/login?next={quote(next_url, safe='')}"


def _text_error(error: str, description: str) -> Response:
    """Réponse d'erreur OpenID 2.0 (texte ``clé:valeur``)."""
    return Response(
        content=f"error:{error}\nerror_description:{description}\n",
        media_type=_TEXT_MEDIA_TYPE,
        status_code=400,
    )
