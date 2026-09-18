r"""Test manuel de la SPA statique et du CORS dérivé des URIs du client.

Smoke test du sample ``spa-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8117, une
seule client seed — ``sample-spa-client`` avec ``redirect_uris`` sur le port
5177 et ``web_origins`` ``localhost:5177``), puis vérifie que le CORS est
dérivé automatiquement des URIs enregistrées :

1. ``GET /.well-known/openid-configuration`` avec l'origine du SPA
   (``http://127.0.0.1:5177``, déduite de la ``redirect_uri``) -> ``200``
   avec ``access-control-allow-origin`` et les en-têtes exposés ;
2. prelude ``OPTIONS /token`` depuis cette origine -> ``200``
   (``POST`` autorisé, ``Authorization``/``Content-Type`` acceptés) ;
3. prelude depuis l'alias ``http://localhost:5177`` (``web_origins``)
   -> ``200`` ;
4. prelude depuis une origine étrangère -> ``400`` sans en-tête CORS ;
5. ``POST /token`` (grant invalide) depuis l'origine du SPA -> réponse du
   serveur (``400``) **avec** les en-têtes CORS (requête simple autorisée).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/spa-client/smoke_test.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8117

SPA_ORIGIN = "http://127.0.0.1:5177"
SPA_ALIAS = "http://localhost:5177"
EVIL_ORIGIN = "http://evil.example"

_DEADLINE = 60.0

_CLIENTS: tuple[dict[str, object], ...] = (
    {
        "client_id": "sample-spa-client",
        "redirect_uris": ["http://127.0.0.1:5177/"],
        "web_origins": ["http://localhost:5177"],
        "scopes": "openid profile email offline_access",
        "client_type": "public",
    },
)

_STEP = 0


def _step(label: str) -> None:
    """Affiche l'étape courante du scénario."""
    global _STEP
    _STEP += 1
    print(f"  [{_STEP}/5] {label}")


def _run_scenario(server_url: str) -> None:
    """Joue le scénario CORS complet contre ``server_url``."""
    with httpx.Client(base_url=server_url) as http:
        headers = {"Origin": SPA_ORIGIN}
        response = http.get("/.well-known/openid-configuration", headers=headers)
        assert response.status_code == 200, response.text
        assert response.headers["access-control-allow-origin"] == SPA_ORIGIN
        exposed = response.headers["access-control-expose-headers"].lower()
        assert "location" in exposed and "www-authenticate" in exposed
        _step("GET discovery avec l'origine du SPA -> CORS autorisé")

        response = http.options(
            "/token",
            headers={
                **headers,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, authorization",
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["access-control-allow-origin"] == SPA_ORIGIN
        assert "POST" in response.headers["access-control-allow-methods"].upper()
        allowed = response.headers["access-control-allow-headers"].lower()
        assert "content-type" in allowed and "authorization" in allowed
        _step("Prelude /token depuis 127.0.0.1:5177 -> 200")

        response = http.options(
            "/token",
            headers={
                "Origin": SPA_ALIAS,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["access-control-allow-origin"] == SPA_ALIAS
        _step("Prelude /token depuis l'alias localhost:5177 (web_origins) -> 200")

        response = http.options(
            "/token",
            headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "POST"},
        )
        assert response.status_code == 400, response.text
        assert "access-control-allow-origin" not in response.headers
        _step("Prelude /token depuis une origine étrangère -> 400 sans CORS")

        response = http.post("/token", data={"grant_type": "bogus"}, headers=headers)
        assert response.status_code == 400
        assert response.headers["access-control-allow-origin"] == SPA_ORIGIN
        _step("POST /token (grant invalide) -> 400 du serveur avec CORS sur la réponse")


def main() -> None:
    """Lance le serveur de test (client seed SPA), puis le termine."""
    started_at = time.monotonic()
    with (
        watchdog(_DEADLINE),
        run_server(port=SERVER_PORT, clients=_CLIENTS),
    ):
        print(f"\nScénario CORS de la SPA démo (deadline={_DEADLINE}s)...")
        _run_scenario(f"http://{HOST}:{SERVER_PORT}")
        print(f"=== SCÉNARIO OK en {time.monotonic() - started_at:.1f}s ===")


if __name__ == "__main__":
    main()
