#!/usr/bin/env python3
"""Initiateur OpenID4VP pour la suite de certification (issue #224).

La suite `vp1finalverifier` est un test « verifier » : elle attend qu'une
demande de présentation (`request_uri`) lui soit LIVRÉE par le biais de son
endpoint émulated `/test/a/{alias}/authorize`. Ce script joue le rôle du
porteur : il crée la demande auprès de PurIdentityServer puis livre le
`request_uri` au module en attente, déclenchant ainsi le cycle complet
(fetch du request object → vérifications → émission du credential →
soumission de la présentation → verdict).

Le driver (`run-test-plan.py`) l'invoque à chaque état WAITING d'un module
`oid4vp-*` via le patch `certification/conformance-oid4vp-initiator.patch`.

Sorties : 0 si la livraison a réussi (ou si le module n'est pas concerné),
non nul sinon — le module échoue alors par son propre état.

Usage (appelé par le driver, mais autonome) :
    python oid4vp_initiator.py --module oid4vp-1final-verifier-happy-flow
        --module-id abc123 --alias puridentityserver-oid4vp
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

_LOGGER = logging.getLogger("oid4vp_initiator")

# Délais (secondes) : création de la demande côté OP, puis livraison du
# GET /authorize — la suite enchaîne fetch RO + validations + émission du
# credential + POST de la présentation dans la même requête synchrone.
CREATE_TIMEOUT = 60
DELIVER_TIMEOUT = 300


def _build_ssl_context() -> ssl.SSLContext | None:
    """Contexte SSL : vérification désactivée seulement en mode dev.

    La suite locale sert un certificat auto-signé ; le mode dev est signalé
    par ``CONFORMANCE_DEV_MODE`` ou ``DISABLE_SSL_VERIFY`` (les deux
    harnesss locaux les positionnent). En hébergé, le certificat est public :
    le contexte par défaut du système fait foi.

    Returns:
        Un contexte sans vérification si le mode dev est actif, sinon
        ``None`` (contexte par défaut d'``urlopen``).
    """
    if not (os.environ.get("CONFORMANCE_DEV_MODE") or os.environ.get("DISABLE_SSL_VERIFY")):
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _post_json(
    url: str,
    payload: dict[str, object],
    *,
    timeout: int,
    ssl_ctx: ssl.SSLContext | None,
) -> dict[str, object]:
    """POST JSON vers l'OP.

    Args:
        url: Endpoint à appeler.
        payload: Corps JSON.
        timeout: Délai maximal en secondes.
        ssl_ctx: Contexte SSL (``None`` = défaut système).

    Returns:
        Le dictionnaire JSON décodé.

    Raises:
        SystemExit: En cas d'échec HTTP ou de corps invalide.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read(500) if hasattr(error, "read") else b""
        raise SystemExit(
            f"[oid4vp-initiator] creation refusee : HTTP {error.code} {detail!r}"
        ) from error
    except (urllib.error.URLError, OSError) as error:
        raise SystemExit(
            f"[oid4vp-initiator] creation de la demande impossible ({url}) : {error}"
        ) from error
    if status != 201:
        raise SystemExit(f"[oid4vp-initiator] creation refusee : HTTP {status} {body[:300]!r}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as error:
        raise SystemExit(f"[oid4vp-initiator] corps non JSON : {body[:300]!r}") from error
    if not isinstance(data, dict):
        raise SystemExit(f"[oid4vp-initiator] corps inattendu : {body[:300]!r}")
    return data


def _deliver_authorization_request(
    url: str,
    *,
    timeout: int,
    ssl_ctx: ssl.SSLContext | None,
) -> None:
    """Livraison synchrone du GET /authorize à la suite.

    La suite traite la requête de bout en bout (fetch du request object,
    validations, émission du credential, soumission de la présentation,
    verdict) puis répond 200.

    Args:
        url: URL complète de l'endpoint émulated (query comprise).
        timeout: Délai maximal en secondes.
        ssl_ctx: Contexte SSL (``None`` = défaut système).

    Raises:
        SystemExit: En cas d'échec de connexion.
    """
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            status = response.status
            body = response.read(500)
    except urllib.error.HTTPError as error:
        # 404 = alias inconnu : la livraison a rate (module non demarre ou
        # alias faux) -> sortie non nulle. Les autres 4xx/5xx viennent du
        # module apres traitement : son propre etat fait foi, on se contente
        # de tracer la reponse.
        if error.code == 404:
            raise SystemExit(
                f"[oid4vp-initiator] livraison refusee : HTTP 404 pour {url}"
            ) from error
        detail = error.read(500) if hasattr(error, "read") else b""
        _LOGGER.error("livraison refusee : HTTP %s %r", error.code, detail)
        return
    except (urllib.error.URLError, OSError) as error:
        raise SystemExit(f"[oid4vp-initiator] livraison impossible ({url}) : {error}") from error
    if not 200 <= status < 300:
        _LOGGER.error("livraison : HTTP %s %r", status, body)


def _authorize_url(
    *,
    suite_base: str,
    alias: str,
    client_id: str,
    request_uri: str,
    request_uri_method: str | None,
) -> str:
    """Construit l'URL de livraison du AR vers la suite.

    Args:
        suite_base: URL de base de la suite (``CONFORMANCE_SERVER``).
        alias: Alias du module courant.
        client_id: ``client_id`` de la demande (``x509_hash:...``).
        request_uri: ``request_uri`` de la demande.
        request_uri_method: ``post`` uniquement pour le module dédié.

    Returns:
        L'URL complète avec query encodée.
    """
    query: dict[str, str] = {"client_id": client_id, "request_uri": request_uri}
    if request_uri_method:
        query["request_uri_method"] = request_uri_method
    base = suite_base.rstrip("/") + f"/test/a/{urllib.parse.quote(alias)}/authorize"
    return base + "?" + urllib.parse.urlencode(query)


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : crée la demande puis livre le ``request_uri``.

    Args:
        argv: Arguments de ligne de commande (défaut : ``sys.argv[1:]``).

    Returns:
        0 en cas de livraison réussie, 1 sinon.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Initiateur OpenID4VP de la suite de certification"
    )
    parser.add_argument(
        "--module",
        required=True,
        help="Nom complet du module (ex. oid4vp-1final-verifier-happy-flow)",
    )
    parser.add_argument(
        "--module-id", required=True, help="Identifiant d'instance du module dans la suite"
    )
    parser.add_argument("--alias", required=True, help="Alias réservé par le module")
    args = parser.parse_args(argv)

    suite_base = os.environ.get("CONFORMANCE_SERVER")
    if not suite_base:
        raise SystemExit("[oid4vp-initiator] CONFORMANCE_SERVER absent de l'environnement")
    op_base = os.environ.get("OID4VP_INITIATOR_OP_URL", "http://127.0.0.1:8000").rstrip("/")

    ssl_ctx = _build_ssl_context()

    # 1) Création de la demande côté OP (payload vide = défauts DCQL PID).
    created = _post_json(
        f"{op_base}/oid4vp/presentation_requests",
        {},
        timeout=CREATE_TIMEOUT,
        ssl_ctx=None,  # l'OP local est toujours en HTTP clair
    )
    request_uri = created.get("request_uri")
    client_id = created.get("client_id")
    if not isinstance(request_uri, str) or not isinstance(client_id, str):
        raise SystemExit(f"[oid4vp-initiator] reponse inattendue : {created!r}")

    # 2) Livraison : request_uri_method=post UNIQUEMENT pour le module dédié
    # (les autres modules lèveraient un paramètre inattendu).
    request_uri_method = (
        "post" if args.module == "oid4vp-1final-verifier-request-uri-method-post" else None
    )
    url = _authorize_url(
        suite_base=suite_base,
        alias=args.alias,
        client_id=client_id,
        request_uri=request_uri,
        request_uri_method=request_uri_method,
    )
    _LOGGER.info("module=%s id=%s livraison=%s", args.module, args.module_id, url)
    _deliver_authorization_request(url, timeout=DELIVER_TIMEOUT, ssl_ctx=ssl_ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main())
