#!/usr/bin/env python3
"""Smoke test pour `acr_values_supported` et emission id_token (voir README.md)."""

from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:8000"


def _main(base_url: str) -> int:
    base = base_url.rstrip("/")
    with urllib.request.urlopen(base + "/.well-known/openid-configuration", timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
        data = json.loads(response.read().decode())
    supported = data.get("acr_values_supported", [])
    print("acr_values_supported =", supported)
    assert "puridentityserver:pwd" in supported, "value supportee attendue"
    client_id = "sample-pkce-client"
    redirect_uri = "http://127.0.0.1:5173/callback"
    url = (
        base
        + "/authorize?response_type=code"
        + f"&client_id={client_id}"
        + f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
        + "&scope=openid+profile"
        + "&acr_values=puridentityserver:pwd"
        + "&state=smoke-acr&nonce=smoke-nonce"
        + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        + "&code_challenge_method=S256"
    )
    print("URL a ouvrir :")
    print(url)
    print("\nEtapes attendues:")
    print("1. ouvrir URL, login alice/password")
    print("2. recuperer le `code` et faire POST /token avec grant_type=authorization_code")
    print("3. decoder id_token (jwt) et verifier acr=puridentityserver:pwd")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=BASE_URL)
    args = ap.parse_args()

    raise SystemExit(_main(args.base_url))
