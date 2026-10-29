#!/usr/bin/env python3
"""Smoke test placeholder pour le grant pre-authorized code OID4VCI."""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
CODE = os.environ.get("PRE_AUTHORIZED_CODE", "")


def main() -> int:
    """Point d entree du smoke test."""
    if not CODE:
        print("PRE_AUTHORIZED_CODE manquant")
        return 1
    data = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": CODE,
            "client_id": "puridentityserver-oid4vci-client",
        }
    ).encode()
    request = urllib.request.Request(BASE_URL + "/token", data=data, method="POST")  # ruff: ignore[suspicious-url-open-usage]
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
            print(response.status, response.read().decode())
    except Exception as exc:
        print("erreur:", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
