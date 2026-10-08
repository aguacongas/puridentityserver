"""Route FastAPI de l'endpoint UserInfo (RFC 6750 §2, §3, RFC 9449 §7)."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Header, Request, Response

from puridentityserver.application.userinfo import (
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from puridentityserver.infrastructure.client_tls import extract_client_certificate
from puridentityserver.interfaces.api.dpop_proof import extract_dpop_proof


def userinfo_router(usecase: UserInfoUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /userinfo``."""
    router = APIRouter(tags=["userinfo"])

    @router.get("/userinfo", summary="Endpoint UserInfo (claims de l'utilisateur)")
    async def userinfo(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        return await _handle_userinfo(request, _split_authorization(authorization))

    @router.post("/userinfo", summary="Endpoint UserInfo (POST, RFC 6750 §2.1)")
    async def userinfo_post(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        """POST /userinfo : Bearer en en-tête (§2.1.1) ou en corps form (§2.1.2).

        L'en-tête ``Authorization`` prime ; à défaut, le paramètre
        ``access_token`` du corps ``application/x-www-form-urlencoded`` est
        lu (RFC 6750 §2.1, méthode 2), présenté comme un ``Bearer``.
        """
        scheme, token = _split_authorization(authorization)
        if token is None:
            body_token = (await request.form()).get("access_token")
            if isinstance(body_token, str) and body_token:
                scheme, token = "bearer", body_token
        return await _handle_userinfo(request, (scheme, token))

    async def _handle_userinfo(request: Request, scheme_token: tuple[str, str | None]) -> Response:
        scheme, token = scheme_token
        if not token:
            return _bearer_error(
                "invalid_request",
                "Token absent : en-tête Authorization 'Bearer'/'DPoP' ou "
                "access_token en corps form attendu",
            )
        proof, proof_error = extract_dpop_proof(request.headers)
        if proof_error is not None:
            return _bearer_error("invalid_request", proof_error)
        result = await usecase.execute(
            UserInfoRequest(
                access_token=token,
                auth_scheme=scheme,
                dpop_proof=proof,
                htu=str(request.url),
                htm=request.method,
                tls_certificate=extract_client_certificate(request),
            )
        )
        if isinstance(result, UserInfoError):
            return _bearer_error(result.error, result.error_description, result.challenge)
        return _success_response(result)

    return router


def _split_authorization(authorization: str | None) -> tuple[str, str | None]:
    """Scheme et jeton d'un en-tête ``Authorization: <scheme> <token>`` (RFC 6750 §2.1).

    ``bearer`` et ``dpop`` (RFC 9449 §7.1) sont reconnus ; tout autre
    scheme produit un jeton absent, trahi par un ``invalid_request``.
    """
    if not authorization:
        return "", None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    scheme = scheme.lower()
    if scheme not in ("bearer", "dpop") or not token:
        return scheme, None
    return scheme, token


def _success_response(result: UserInfoResponse) -> Response:
    """Sérialise les claims au format JSON (RFC 6750 §3.1)."""
    return Response(
        content=json.dumps(result.claims, ensure_ascii=False),
        media_type="application/json",
    )


def _bearer_error(error: str, description: str, challenge: str = "") -> Response:
    """Réponse d'erreur avec en-tête ``WWW-Authenticate`` (RFC 6750 §3, RFC 9449 §7).

    L'en-tête HTTP doit rester ASCII : seuls les codes d'erreur standard
    y figurent ; la description lisible passe dans le corps JSON. Un
    ``challenge`` fourni par le cas d'utilisation (``DPoP error=…``)
    remplace le ``Bearer`` par défaut.
    """
    return Response(
        content=json.dumps({"error": error, "error_description": description}),
        media_type="application/json",
        status_code=401,
        headers={"WWW-Authenticate": challenge or f'Bearer error="{error}"'},
    )
