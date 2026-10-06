"""Routes FastAPI du Backchannel Authentication Endpoint (OIDC CIBA 1.0 §7, §9).

Expose ``POST /bc-authorize`` : le client y envoie sa demande d'authentification
en corps ``application/x-www-form-urlencoded`` (comme au token endpoint) avec
un — et un seul — hint, et reçoit l'acquittement JSON
``{auth_req_id, expires_in, interval}`` (§7.3). Les erreurs suivent la
Authentication Error Response (§13) : ``invalid_client`` en 401, le reste en 400.

``POST /ciba/approve`` (derrière le flag ``ciba_approval_enabled``, absent →
404) recueille la décision ``?token={auth_req_id}&type={allow|deny}`` et
retourne un 2xx vide — c'est l'URL ``automated_ciba_approval_url`` consommée
par la suite de certification (§9).

Le corps est lu manuellement (et non via ``Form``) pour garantir une réponse
JSON OAuth sur tout paramètre absent — jamais le 422 de validation FastAPI.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from starlette.datastructures import FormData

from puridentityserver.application.backchannel_authorize import (
    AuthenticationAck,
    BackchannelAuthenticationError,
    BackchannelAuthenticationParams,
    BackchannelAuthenticationUseCase,
    CibaApprovalUseCase,
)
from puridentityserver.application.resource_indicators import encode_resource_parameter
from puridentityserver.infrastructure.client_tls import extract_client_certificate
from puridentityserver.interfaces.api.error_description import ascii_error_description
from puridentityserver.interfaces.api.http_client_auth import parse_basic_auth

_JSON_MEDIA_TYPE = "application/json"


def backchannel_authorization_router(usecase: BackchannelAuthenticationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /bc-authorize`` (CIBA §7)."""
    router = APIRouter(tags=["backchannel-authentication"])

    @router.post(
        "/bc-authorize",
        summary="Backchannel Authentication Endpoint (OIDC CIBA 1.0 §7)",
        response_model=None,
    )
    async def backchannel_authorization(request: Request) -> Response:
        """Authentifie le client, résout le hint et retourne l'``auth_req_id``."""
        form = await request.form()
        header_id, header_secret = parse_basic_auth(request)
        params = BackchannelAuthenticationParams(
            client_id=_form_value(form, "client_id") or header_id,
            scope=_form_value(form, "scope"),
            login_hint=_form_value(form, "login_hint"),
            login_hint_token=_form_value(form, "login_hint_token"),
            id_token_hint=_form_value(form, "id_token_hint"),
            binding_message=_form_value(form, "binding_message"),
            acr_values=_form_value(form, "acr_values"),
            resource=encode_resource_parameter([str(v) for v in form.getlist("resource")]),
            client_notification_token=_form_value(form, "client_notification_token"),
            requested_expiry=_form_value(form, "requested_expiry"),
            client_secret=_form_value(form, "client_secret") or header_secret,
            client_assertion_type=_form_value(form, "client_assertion_type"),
            client_assertion=_form_value(form, "client_assertion"),
            request=_form_value(form, "request"),
            request_uri=_form_value(form, "request_uri"),
            tls_certificate=extract_client_certificate(request),
        )
        result = await usecase.execute(params)
        if isinstance(result, BackchannelAuthenticationError):
            return _error_response(result)
        return _ack_response(result)

    return router


def ciba_approval_router(usecase: CibaApprovalUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /ciba/approve`` (CIBA §9)."""
    router = APIRouter(tags=["backchannel-authentication"])

    @router.post(
        "/ciba/approve",
        summary="Décision utilisateur sur une demande CIBA",
        response_model=None,
    )
    async def ciba_approval(
        token: Annotated[str, Query()] = "",
        decision: Annotated[str, Query(alias="type")] = "allow",
    ) -> Response:
        """Applique ``type=allow|deny`` sur l'``auth_req_id`` ``token`` (2xx vide)."""
        if decision not in ("allow", "deny"):
            return Response(
                content=_json_error("invalid_request", "Paramètre type invalide"),
                media_type=_JSON_MEDIA_TYPE,
                status_code=400,
            )
        if not await usecase.execute(token, allow=decision == "allow"):
            return Response(
                content=_json_error("invalid_request", "auth_req_id inconnu"),
                media_type=_JSON_MEDIA_TYPE,
                status_code=404,
            )
        return Response(status_code=200)

    return router


def _form_value(form: FormData, name: str) -> str:
    """Première valeur d'un champ du corps form, ou chaîne vide."""
    value = form.get(name)
    if value is None or isinstance(value, str):
        return value or ""
    return str(value)


def _ack_response(result: AuthenticationAck) -> Response:
    """Sérialise l'acquittement ``/bc-authorize`` (CIBA §7.3)."""
    return Response(
        content=json.dumps(
            {
                "auth_req_id": result.auth_req_id,
                "expires_in": result.expires_in,
                "interval": result.interval,
            },
            separators=(",", ":"),
        ),
        media_type=_JSON_MEDIA_TYPE,
        headers={"Cache-Control": "no-store"},
    )


def _json_error(error: str, error_description: str) -> bytes:
    """Sérialise une erreur JSON courte (corps des réponses ``/ciba/approve``)."""
    return json.dumps(
        {"error": error, "error_description": ascii_error_description(error_description)},
        separators=(",", ":"),
    ).encode("utf-8")


def _error_response(error: BackchannelAuthenticationError) -> Response:
    """Sérialise une Authentication Error Response (CIBA §13, §7.3)."""
    return Response(
        content=json.dumps(
            {
                "error": error.error,
                "error_description": ascii_error_description(error.error_description),
            },
            separators=(",", ":"),
        ),
        media_type=_JSON_MEDIA_TYPE,
        status_code=error.status_code,
        headers={"Cache-Control": "no-store"},
    )
