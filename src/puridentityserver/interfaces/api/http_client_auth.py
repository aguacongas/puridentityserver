"""Extraction des identifiants client de l'en-tête ``Authorization: Basic``.

Partagée par les endpoints acceptant l'authentification client par en-tête
(RFC 7617) : ``/token`` et le backchannel authentication endpoint (CIBA §7.1).
"""

from __future__ import annotations

import base64

from fastapi import Request


def parse_basic_auth(request: Request) -> tuple[str, str]:
    """Identifiants client depuis l'en-tête ``Authorization: Basic`` (RFC 7617).

    Retourne ``(client_id, client_secret)`` ; paires vides si l'en-tête est
    absent ou illisible (la décision revient à l'authentification déclarée
    du client).
    """
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("basic "):
        return "", ""
    try:
        decoded = base64.b64decode(authorization.split(None, 1)[1], validate=True).decode("utf-8")
    except ValueError:
        return "", ""
    username, separator, password = decoded.partition(":")
    if not separator:
        return "", ""
    return username, password
