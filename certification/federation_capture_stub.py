"""Mini-fédération locale pour les captures REVIEW du plan federation.

La suite de conformance n'héberge la trust chain d'un RP fédéré (entity
configuration du RP, entity configuration de l'ancre, subordinate statement
du fetch endpoint) que pendant l'exécution d'un module du plan : le job de
captures tourne hors plan, les fetchs de l'OP retomberaient en 404. Ce
module héberge lui-même les statements sous une entité locale (HTTPS sur le
certificat du harness, déjà dans la confiance de l'OP via ``SSL_CERT_FILE``)
et l'ancre du stub devient la seconde trust anchor de l'OP de certification
(générée par ``certification/local/setup.sh``) : l'OP résout la chaîne du RP
de capture et sert ses vraies pages de refus pour les 13 request objects
défectueux des modules REVIEW fédérés.

Le stub ne sert que trois documents — l'entity configuration du RP, celle de
l'ancre et le subordinate statement de l'ancre — et renvoie 404 partout
ailleurs, y compris pour les Entity Identifiers invalides des scénarios
``INVALID`` (le comportement de la suite). Les clés et statements ne vivent
que le temps d'une exécution : rien n'est persisté.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

_LOGGER = logging.getLogger("federation_capture_stub")

#: Port local du stub (ancre ``https://localhost:9444/federation-capture-anchor``).
STUB_PORT = 9444

#: Base des Entity Identifiers hébergés par le stub.
STUB_BASE = f"https://localhost:{STUB_PORT}"
#: Chemin de l'ancre de confiance du stub.
ANCHOR_PATH = "/federation-capture-anchor"
#: Chemin du RP de capture.
RP_PATH = "/federation-capture-rp"
#: Chemin de l'entity configuration (spec §8.1, ``/.well-known`` délégué).
ENTITY_CONFIGURATION_PATH = "/.well-known/openid-federation"
#: Chemin du fetch endpoint de l'ancre (spec §5.2.2).
FETCH_PATH = "/federation/fetch"
#: Chemin du callback hébergé par le stub.
CALLBACK_PATH = "/cb"

#: Entity Identifier de l'ancre du stub (seconde trust anchor de l'OP).
ANCHOR_ENTITY_ID = f"{STUB_BASE}{ANCHOR_PATH}"
#: Entity Identifier du RP de capture (``client_id`` des scénarios).
RP_ENTITY_ID = f"{STUB_BASE}{RP_PATH}"
#: Callback hébergé par le stub (inutilisé : les refus sont des pages 400).
CALLBACK_URI = f"{STUB_BASE}{CALLBACK_PATH}"

#: Valeur de l'en-tête ``typ`` d'un entity statement (spec §3).
_ENTITY_STATEMENT_TYP = "entity-statement+jwt"
#: Durée de vie des statements servis (le run de captures dure quelques
#: dizaines de secondes ; une heure offre une marge large).
_STATEMENT_TTL_SECONDS = 3600
#: Algorithme de signature des statements et des request objects (RS256,
#: standard du profil fédéré de la suite).
_ALGORITHM = "RS256"

#: Page servie sur le callback du stub : la capture y injecte l'URL reçue.
_CALLBACK_HTML = (
    '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
    "<title>PurIdentityServer - callback de capture fédérée</title></head>"
    "<body><h1>Callback du stub de capture fédérée</h1>"
    "<p>La demande d'autorisation a été refusée par l'OP : le motif "
    "<code>error=</code> figure dans l'URL affichée en haut de page.</p>"
    "</body></html>"
)


def _key_pair(kid: str) -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    """Génère une paire RSA et son JWK public portant ``kid``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    public["kid"] = kid
    return key, public


def _sign(private_key: rsa.RSAPrivateKey, kid: str, claims: dict[str, Any]) -> str:
    """Signe un entity statement (``typ`` + ``kid`` en en-tête, RS256)."""
    return str(
        pyjwt.encode(
            claims,
            private_key,
            algorithm=_ALGORITHM,
            headers={"typ": _ENTITY_STATEMENT_TYP, "kid": kid},
        )
    )


class _StubHTTPServer(ThreadingHTTPServer):
    """Serveur HTTPS portant les documents du stub."""

    tokens: dict[str, str]
    subordinate_token: str


class _StubHandler(BaseHTTPRequestHandler):
    """Routes HTTP du stub : les trois statements, une page callback, 404 ailleurs."""

    server: _StubHTTPServer

    def do_GET(self) -> None:
        """Route la requête vers le document du stub, ou 404."""
        parsed = urlparse(self.path)
        if parsed.path == CALLBACK_PATH:
            self._respond(200, "text/html; charset=utf-8", _CALLBACK_HTML.encode("utf-8"))
            return
        if parsed.path == f"{ANCHOR_PATH}{FETCH_PATH}":
            subject = parse_qs(parsed.query).get("sub", [""])[0]
            token = self.server.subordinate_token if subject == RP_ENTITY_ID else ""
        else:
            token = self.server.tokens.get(parsed.path, "")
        if not token:
            self._respond(404, "text/plain", b"stub de capture federation : entite inconnue")
            return
        self._respond(200, "application/entity-statement+jwt", token.encode("utf-8"))

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        """Écrit une réponse HTTP complète."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        """Route les accès HTTP vers le logger du stub (sortie calme)."""
        _LOGGER.debug("stub : " + fmt, *args)


class FederationCaptureStub:
    """Mini-fédération (ancre + RP) hébergée localement pour les captures.

    Gestionnaire de contexte : les clés et statements sont générés à
    l'entrée, le serveur HTTPS (certificat du harness) s'arrête à la sortie.
    Les propriétés ``rp_private_key`` et ``foreign_private_key`` servent à
    signer les request objects des scénarios depuis le script de captures.
    """

    def __init__(self, *, cert_path: Path, key_path: Path) -> None:
        """Génère les clés et statements du stub.

        Args:
            cert_path: Certificat TLS du harness (nginx mTLS local), déjà
                accepté par l'OP via ``SSL_CERT_FILE``.
            key_path: Clé privée correspondante.
        """
        self._cert_path = cert_path
        self._key_path = key_path
        self._anchor_key, anchor_jwk = _key_pair("capture-anchor")
        self._rp_key, rp_jwk = _key_pair("capture-rp")
        self._foreign_key, _ = _key_pair("capture-foreign")
        rp_jwks = {"keys": [rp_jwk]}
        now = int(time())
        claims_base = {"iat": now, "exp": now + _STATEMENT_TTL_SECONDS}
        rp_metadata = {
            "openid_relying_party": {
                "redirect_uris": [CALLBACK_URI],
                "jwks": rp_jwks,
                "token_endpoint_auth_method": "private_key_jwt",
                "request_object_signing_alg": _ALGORITHM,
            }
        }
        self._tokens = {
            # Entity configuration de l'ancre : auto-signée, sans
            # authority_hints (auto-racine), son fetch endpoint dessert le
            # subordinate statement du RP (spec §5.2.2, §8.1).
            f"{ANCHOR_PATH}{ENTITY_CONFIGURATION_PATH}": _sign(
                self._anchor_key,
                "capture-anchor",
                {
                    "iss": ANCHOR_ENTITY_ID,
                    "sub": ANCHOR_ENTITY_ID,
                    "jwks": {"keys": [anchor_jwk]},
                    "metadata": {
                        "federation_entity": {
                            "federation_fetch_endpoint": f"{ANCHOR_ENTITY_ID}{FETCH_PATH}",
                        }
                    },
                    **claims_base,
                },
            ),
            # Entity configuration du RP : auto-signée par sa clé, rattachée
            # à l'ancre par authority_hints (spec §3.1.1).
            f"{RP_PATH}{ENTITY_CONFIGURATION_PATH}": _sign(
                self._rp_key,
                "capture-rp",
                {
                    "iss": RP_ENTITY_ID,
                    "sub": RP_ENTITY_ID,
                    "jwks": rp_jwks,
                    "authority_hints": [ANCHOR_ENTITY_ID],
                    "metadata": rp_metadata,
                    **claims_base,
                },
            ),
        }
        # Subordinate statement de l'ancre : atteste les clés du RP
        # (liaison EC du sujet → supérieur, spec §10.2 étape 6).
        self._subordinate = _sign(
            self._anchor_key,
            "capture-anchor",
            {
                "iss": ANCHOR_ENTITY_ID,
                "sub": RP_ENTITY_ID,
                "jwks": rp_jwks,
                "metadata": rp_metadata,
                **claims_base,
            },
        )
        self._server: _StubHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        """Base HTTPS du stub (port local, certificat du harness)."""
        return STUB_BASE

    @property
    def rp_entity_id(self) -> str:
        """Entity Identifier du RP de capture (``client_id`` des scénarios)."""
        return RP_ENTITY_ID

    @property
    def callback_uri(self) -> str:
        """Callback hébergé par le stub (``redirect_uri`` du RP de capture)."""
        return CALLBACK_URI

    @property
    def rp_private_key(self) -> rsa.RSAPrivateKey:
        """Clé privée du RP de capture (signature des request objects)."""
        return self._rp_key

    @property
    def rp_kid(self) -> str:
        """Identifiant de clé (``kid``) publiée dans le JWKS du RP."""
        return "capture-rp"

    @property
    def foreign_private_key(self) -> rsa.RSAPrivateKey:
        """Clé privée hors JWKS du RP (scénario « signé par d'autres clés »)."""
        return self._foreign_key

    def __enter__(self) -> FederationCaptureStub:
        """Démarre le serveur HTTPS du stub sur le port local."""
        server = _StubHTTPServer(("localhost", STUB_PORT), _StubHandler)
        server.tokens = dict(self._tokens)
        server.subordinate_token = self._subordinate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(self._cert_path), keyfile=str(self._key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        _LOGGER.info("stub fédération : ancre %s démarrée", ANCHOR_ENTITY_ID)
        return self

    def __exit__(self, *exc: object) -> None:
        """Arrête le serveur et joint le thread."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        _LOGGER.info("stub fédération arrêté")
