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
from puridentityserver.infrastructure.client_tls import (
    ClientCertificateHeaderNames,
    extract_client_certificate,
)
from puridentityserver.interfaces.api.dpop_proof import extract_dpop_proof
from puridentityserver.interfaces.api.forwarded import public_url
from puridentityserver.interfaces.api.security import split_authorization


def userinfo_router(
    usecase: UserInfoUseCase,
    client_certificate_headers: ClientCertificateHeaderNames | None = None,
    *,
    trust_proxy_headers: bool = False,
) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /userinfo``.

    ``trust_proxy_headers`` active la reconstruction de l'URL publique
    derrière un reverse proxy (claim ``htu`` DPoP, RFC 9449 §4.3) — voir
    ``Settings.trust_proxy_headers``.
    """
    certificate_headers = client_certificate_headers or ClientCertificateHeaderNames()
    router = APIRouter(tags=["userinfo"])

    @router.get("/userinfo", summary="Endpoint UserInfo (claims de l'utilisateur)")
    async def userinfo(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        return await _handle_userinfo(request, split_authorization(authorization))

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
        scheme, token = split_authorization(authorization)
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
                htu=public_url(request, trust_proxy_headers=trust_proxy_headers),
                htm=request.method,
                tls_certificate=extract_client_certificate(request, certificate_headers),
            )
        )
        if isinstance(result, UserInfoError):
            return _bearer_error(result.error, result.error_description, result.challenge)
        return _success_response(result)

    return router


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
