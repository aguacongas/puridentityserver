"""Routes FastAPI du Device Authorization Grant (RFC 8628 §3.1)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Form, Response

from puridentityserver.application.device_authorize import (
    DeviceAuthorizationError,
    DeviceAuthorizationRequest,
    DeviceAuthorizationUseCase,
)


def device_authorization_router(usecase: DeviceAuthorizationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /device_authorization``."""
    router = APIRouter(tags=["device-authorization"])

    @router.post("/device_authorization", summary="Endpoint d'autorisation de l'appareil")
    async def device_authorization(
        client_id: str = Form(...),
        client_secret: str = Form(default=""),
        scope: str = Form(default=""),
    ) -> Response:
        request = DeviceAuthorizationRequest(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
        result = await usecase.execute(request)
        if isinstance(result, DeviceAuthorizationError):
            return Response(
                content=json.dumps(
                    {
                        "error": result.error,
                        "error_description": result.error_description,
                    }
                ),
                media_type="application/json",
                status_code=400,
            )
        return Response(
            content=json.dumps(
                {
                    "device_code": result.device_code,
                    "user_code": result.user_code,
                    "verification_uri": result.verification_uri,
                    "verification_uri_complete": result.verification_uri_complete,
                    "expires_in": result.expires_in,
                    "interval": result.interval,
                }
            ),
            media_type="application/json",
        )

    return router
