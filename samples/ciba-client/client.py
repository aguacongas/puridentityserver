"""Client de démonstration : CIBA (OIDC CIBA 1.0 — backchannel).

Enchaîne le flow CIBA contre le serveur configuré (défaut
``http://127.0.0.1:8000``) :

1. ``POST /bc-authorize`` (Basic auth, ``login_hint``) → ``auth_req_id`` ;
2. approbation de la demande via l'endpoint démo ``/ciba/approve``
   (la commande ``curl`` équivalente est affichée) ;
3. poll sur ``/token`` (grant ``urn:openid:params:grant-type:ciba``)
   jusqu'aux jetons, un refus ou l'expiration.

Mode ping : ``CIBA_MODE=ping`` démarre un listener local qui reçoit la
notification JSON du serveur (``client_notification_token`` + endpoint
``sample-ciba-ping-client``) avant le poll final.

Mode signé (``CIBA_SIGNED=1``) : le client s'enregistre d'abord par
Dynamic Client Registration (clé RSA éphémère, JWKS embarqué,
``token_endpoint_auth_method=private_key_jwt``,
``backchannel_authentication_request_signing_alg=PS256``), puis envoie
une demande ``request`` signée (JAR) sous la forme FAPI-CIBA-ID1
``{request, client_assertion, client_assertion_type}`` — sans
``client_id`` ni secret dans le corps — et authentifie son poll par
assertion. Aucune clé n'est écrite sur disque (générée à la volée).

Utilise ``httpx`` pour les appels HTTP et ``pyjwt`` pour décoder
l'``id_token``.

Usage::

    python client.py                        # défaut http://127.0.0.1:8000
    python client.py https://auth.example   # issuer explicite
    CIBA_MODE=ping python client.py         # mode ping (listener local)
    CIBA_SIGNED=1 python client.py          # request object signé (DCR)
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

_DEFAULT_ISSUER = "http://127.0.0.1:8000"
CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_NOTIFICATION_PATH = "/notify"
_SIGNING_KID = "sample-ciba-signing"


def _discovery(issuer: str) -> dict[str, object]:
    """Charge le document de discovery."""
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with httpx.Client(timeout=10) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def _start_ping_listener(port: int) -> tuple[ThreadingHTTPServer, threading.Event]:
    """Démarre le listener local qui reçoit la notification CIBA (mode ping)."""
    received = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length).decode("utf-8", "replace")
            bearer = self.headers.get("Authorization", "")
            print(f"\n[ping] Notification reçue ({self.path})")
            print(f"       Authorization : {bearer[:40]}...")
            try:
                print(f"       Corps : {json.dumps(json.loads(payload), indent=2)}")
            except ValueError:
                print(f"       Corps : {payload}")
            self.send_response(200)
            self.end_headers()
            received.set()

        def log_message(self, fmt: str, *args: object) -> None:
            """Supprime le log par défaut sur stderr."""

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[ping] Listener démarré sur http://127.0.0.1:{port}{_NOTIFICATION_PATH}")
    return server, received


def _signing_material() -> tuple[RSAPrivateKey, dict[str, object]]:
    """Paire RSA éphémère + JWKS public (kid, alg PS256) — aucune clé persistée."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    n = base64.urlsafe_b64encode(
        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=")
    e = base64.urlsafe_b64encode(
        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    ).rstrip(b"=")
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "PS256",
                "kid": _SIGNING_KID,
                "n": n.decode("ascii"),
                "e": e.decode("ascii"),
            }
        ]
    }
    return private, jwks


def _register_signed_client(
    issuer: str,
    jwks: dict[str, object],
    mode: str,
    notification_endpoint: str,
) -> dict[str, object]:
    """Enregistre le client démo en mode signé (DCR, RFC 7591)."""
    registrar_token = os.environ.get("CIBA_REGISTRATION_TOKEN", "dev-registrar-token")
    metadata: dict[str, object] = {
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code", CIBA_GRANT],
        "scope": "openid profile",
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": jwks,
        "backchannel_token_delivery_mode": mode,
        "backchannel_authentication_request_signing_alg": "PS256",
    }
    if mode == "ping":
        metadata["backchannel_client_notification_endpoint"] = notification_endpoint
    resp = httpx.post(
        f"{issuer.rstrip('/')}/register",
        json=metadata,
        headers={"Authorization": f"Bearer {registrar_token}"},
        timeout=10,
    )
    if resp.status_code != 201:
        print(f"ERREUR registration {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def _signed_form(
    issuer: str,
    token_endpoint: str,
    client_id: str,
    private: RSAPrivateKey,
    login_hint: str,
    notification_token: str = "",
) -> dict[str, str]:
    """Construit le corps form FAPI-CIBA-ID1 : ``request`` signé + assertion (§7.1).

    Ni ``client_id`` ni secret dans le corps : le serveur déduit l'appelant
    de l'``iss`` de l'assertion, puis vérifie la signature du request object.
    """
    now = int(time.time())
    assertion = str(
        jwt.encode(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": [issuer, token_endpoint],
                "iat": now,
                "exp": now + 300,
            },
            private,
            algorithm="PS256",
            headers={"kid": _SIGNING_KID},
        )
    )
    claims: dict[str, object] = {
        "iss": client_id,
        "aud": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": secrets.token_urlsafe(16),
        "scope": "openid profile",
        "login_hint": login_hint,
    }
    if notification_token:
        claims["client_notification_token"] = notification_token
    request_object = str(
        jwt.encode(claims, private, algorithm="PS256", headers={"kid": _SIGNING_KID})
    )
    return {
        "request": request_object,
        "client_assertion": assertion,
        "client_assertion_type": _ASSERTION_TYPE,
    }


def _request_authentication(
    client: httpx.Client,
    endpoint: str,
    data: dict[str, str],
    auth: tuple[str, str] | None,
) -> dict[str, object]:
    """Lance la backchannel authentication request (§7.1)."""
    resp = client.post(endpoint, data=data, auth=auth)
    if resp.status_code >= 400:
        print(f"ERREUR {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def _approve(base_url: str, auth_req_id: str, decision: str) -> None:
    """Prend la décision sur la demande via l'endpoint démo /ciba/approve."""
    resp = httpx.post(
        f"{base_url}/ciba/approve",
        params={"token": auth_req_id, "type": decision},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"ERREUR approbation {resp.status_code} : {resp.text}", file=sys.stderr)
        sys.exit(1)


def _poll_tokens(
    client: httpx.Client,
    token_endpoint: str,
    auth_req_id: str,
    interval: int,
    auth: tuple[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, object]:
    """Interroge le token endpoint jusqu'à succès, refus ou expiration (§11)."""
    delay = max(interval, 1)
    data: dict[str, str] = {
        "grant_type": CIBA_GRANT,
        "auth_req_id": auth_req_id,
        **(extra or {}),
    }
    while True:
        resp = client.post(
            token_endpoint,
            data=data,
            auth=auth,
        )
        body = resp.json()
        error = body.get("error")
        if error is None:
            return body
        if error in ("access_denied", "expired_token", "invalid_grant"):
            print(f"\nErreur : {error} — {body.get('error_description', '')}")
            sys.exit(1)
        if error == "slow_down":
            delay += 5
        print(f"  ... {error} (prochaine tentative dans {delay}s)")
        time.sleep(delay)


def _decode_claims(token: str) -> dict[str, object]:
    """Décode le payload JWT sans vérifier la signature (démo uniquement)."""
    return jwt.decode(token, options={"verify_signature": False})


def _signed_setup(issuer: str, mode: str, notify_port: int) -> tuple[str, RSAPrivateKey]:
    """Enregistre le client démo en mode signé (DCR) et retourne ``(client_id, clé)``."""
    private, jwks = _signing_material()
    registration = _register_signed_client(
        issuer,
        jwks,
        mode,
        f"http://127.0.0.1:{notify_port}{_NOTIFICATION_PATH}",
    )
    client_id = str(registration["client_id"])
    print(f"[1b] Client enregistré (DCR) — client_id = {client_id} (PS256, private_key_jwt)")
    return client_id, private


def _launch_request(
    client: httpx.Client,
    issuer: str,
    bc_endpoint: str,
    token_endpoint: str,
    *,
    client_id: str,
    client_secret: str,
    login_hint: str,
    notification_token: str,
    signed: bool,
    private: RSAPrivateKey | None,
) -> tuple[dict[str, object], str]:
    """Lance la backchannel authentication request (§7.1).

    Mode signé : corps ``{request, client_assertion, client_assertion_type}``
    sans ``client_id`` ; sinon ``scope``/``login_hint`` en Basic auth.
    Retourne l'acquittement et l'assertion à réutiliser au poll ("" sinon).
    """
    if signed and private is not None:
        form = _signed_form(
            issuer,
            token_endpoint,
            client_id,
            private,
            login_hint,
            notification_token,
        )
        return _request_authentication(client, bc_endpoint, form, None), str(
            form["client_assertion"]
        )
    data: dict[str, str] = {"scope": "openid profile", "login_hint": login_hint}
    if notification_token:
        data["client_notification_token"] = notification_token
    return _request_authentication(client, bc_endpoint, data, (client_id, client_secret)), ""


def _poll_options(
    *, client_id: str, client_secret: str, signed: bool, assertion: str
) -> tuple[tuple[str, str] | None, dict[str, str] | None]:
    """Prépare l'authentification du poll (secret Basic ou assertion, §10.1)."""
    if signed:
        return None, {
            "client_id": client_id,
            "client_assertion": assertion,
            "client_assertion_type": _ASSERTION_TYPE,
        }
    return (client_id, client_secret), None


def main() -> None:
    """Point d'entrée du client démo : flow CIBA (poll ou ping, signé ou non)."""
    issuer = os.environ.get("CIBA_ISSUER", _DEFAULT_ISSUER).strip().rstrip("/")
    client_id = os.environ.get("CIBA_CLIENT_ID", "sample-ciba-client")
    client_secret = os.environ.get("CIBA_CLIENT_SECRET", "ciba-demo-secret")
    login_hint = os.environ.get("CIBA_LOGIN_HINT", "alice.martin@example.com")
    mode = os.environ.get("CIBA_MODE", "poll").strip().lower()
    signed = os.environ.get("CIBA_SIGNED", "").strip().lower() in ("1", "true", "yes")
    notify_port = int(os.environ.get("CIBA_NOTIFY_PORT", "8118"))

    print(
        f"CIBA (OIDC CIBA 1.0) contre {issuer} — mode {mode}"
        f"{' (request object signé)' if signed else ''}\n"
    )

    metadata = _discovery(issuer)
    bc_endpoint = str(metadata["backchannel_authentication_endpoint"])
    token_endpoint = str(metadata["token_endpoint"])
    print(f"[1] Discovery chargé — backchannel_authentication_endpoint = {bc_endpoint}")
    if signed:
        algorithms = metadata.get(
            "backchannel_authentication_request_signing_alg_values_supported", []
        )
        print(f"    request object signé admis : {algorithms}")

    listener: ThreadingHTTPServer | None = None
    received = threading.Event()
    notification_token = ""
    if mode == "ping":
        notification_token = secrets.token_urlsafe(32)
        listener, received = _start_ping_listener(notify_port)

    private: RSAPrivateKey | None = None
    if signed:
        client_id, private = _signed_setup(issuer, mode, notify_port)

    with httpx.Client(base_url=issuer, timeout=15) as client:
        ack, assertion = _launch_request(
            client,
            issuer,
            bc_endpoint,
            token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            login_hint=login_hint,
            notification_token=notification_token,
            signed=signed,
            private=private,
        )
        auth_req_id = str(ack["auth_req_id"])
        interval = int(ack.get("interval", 5))
        print(
            f"[2] Demande créée — auth_req_id = {auth_req_id[:40]}… "
            f"(expire dans {ack['expires_in']}s, interval = {interval}s)"
        )
        print("    Approbation manuelle possible depuis un autre terminal :")
        print(f'    curl -X POST "{issuer}/ciba/approve?token={auth_req_id}&type=allow"')

        choice = input("\n    Approuver cette demande ? [O/n] ").strip().lower()
        decision = "deny" if choice in ("n", "no", "non") else "allow"
        _approve(issuer, auth_req_id, decision)
        print(f"[3] Décision envoyée : {decision}")

        if mode == "ping":
            if received.wait(timeout=30):
                print("[4] Notification ping reçue — récupération des jetons")
            else:
                print("[4] Aucune notification (timeout 30s) — tentative de poll anyway")

        poll_auth, poll_extra = _poll_options(
            client_id=client_id,
            client_secret=client_secret,
            signed=signed,
            assertion=assertion,
        )
        print("\n  [5] Poll en cours... ", end="", flush=True)
        tokens = _poll_tokens(client, token_endpoint, auth_req_id, interval, poll_auth, poll_extra)

        print("OK !\n")
        print("Tokens reçus :")
        print(f"  access_token : {tokens['access_token'][:50]}...")
        if tokens.get("id_token"):
            print(f"  id_token     : {tokens['id_token'][:50]}...")
        if tokens.get("refresh_token"):
            print(f"  refresh_token: {tokens['refresh_token'][:50]}...")
        print(f"  expires_in   : {tokens.get('expires_in')}")
        print(f"  scope        : {tokens.get('scope', '')}")

        if tokens.get("id_token"):
            claims = _decode_claims(tokens["id_token"])
            print("\nClaims du id_token (décodage sans vérification) :")
            print(json.dumps(claims, indent=2, ensure_ascii=False))

    if listener is not None:
        listener.shutdown()


if __name__ == "__main__":
    main()
