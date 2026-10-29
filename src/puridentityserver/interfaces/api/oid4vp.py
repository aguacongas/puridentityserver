"""Routes FastAPI minimales pour OpenID4VP (slice 0, issue #172/#223 et suivantes)."""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

if TYPE_CHECKING:
    from puridentityserver.application.oid4vp import OID4VPVerifierUseCase


_JSON_MEDIA_TYPE = "application/json"


def oid4vp_router(
    *,
    oid4vp_usecase: OID4VPVerifierUseCase | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI de présentation OpenID4VP."""
    router = APIRouter(tags=["oid4vp"])
    usecase = oid4vp_usecase

    @router.post(
        "/presentation_requests",
        summary="Crée une demande de présentation signée (OID4VP)",
        response_model=None,
    )
    async def presentation_requests(request: Request) -> JSONResponse:
        if usecase is None:
            return _error(501, "not_implemented", "OID4VP désactivé")
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        presentation_definition = payload.get("presentation_definition")
        response_mode = str(payload.get("response_mode") or "direct_post")
        result = await usecase.create_presentation_request(
            presentation_definition=presentation_definition,
            response_mode=response_mode,
        )
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)

    @router.post(
        "/vp_response",
        summary="Réception direct_post de la présentation (OID4VP)",
        response_model=None,
    )
    async def vp_response(request: Request) -> JSONResponse:
        if usecase is None:
            return _error(501, "not_implemented", "OID4VP désactivé")
        fields = await _read_fields(request)
        vp_token = fields.get("vp_token")
        result = usecase.validate_presentation_response(
            vp_token=vp_token,
        )
        if isinstance(result, str):
            return _error(400, result, "Réponse de présentation invalide.")
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)

    return router


async def _read_fields(request: Request) -> dict[str, Any]:
    """Lit les champs direct_post (form ou JSON)."""
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}
    try:
        form = await request.form()
    except Exception:
        return {}
    data: dict[str, Any] = {}
    for key in form:
        value = form.get(key)
        if isinstance(value, str):
            data[key] = value
        else:
            values = form.getlist(key)
            if len(values) == 1 and isinstance(values[0], str):
                data[key] = values[0]
            else:
                data[key] = [str(v) for v in values if isinstance(v, str)]
    # presentation_submission may be JSON string.
    if isinstance(data.get("presentation_submission"), str):
        with contextlib.suppress(Exception):
            data["presentation_submission"] = json.loads(data["presentation_submission"])
    return data


def _error(status_code: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        media_type=_JSON_MEDIA_TYPE,
    )
