"""Mini-client CIBA local pour rejouer les modules FAPI-CIBA-ID1 (issue #109).

Le harness joue le rôle du client de la suite officielle
(`openid/conformance-suite`, plan ``fapi-ciba-id1-test-plan``) contre
l'application locale :

1. ``POST /register`` (DCR RFC 7591, ``private_key_jwt``, JWKS RSA éphémère
   ``PS256``, ``response_types=[]``, grant ``urn:openid:params:grant-type:
   ciba``) — miroir de ``registerClient()`` du plan ;
2. ``POST /bc-authorize`` avec ``{request, client_assertion,
   client_assertion_type}`` (JAR ``PS256`` + assertion fraîche, sans
   ``client_id`` dans le corps) — ``performAuthorizationRequest()`` ;
3. décision via ``POST /ciba/approve?token={auth_req_id}&type={allow|deny}``
   (``automated_ciba_approval_url`` du plan ``certification/plans/ciba.json``) ;
4. poll ``/token`` (grant CIBA) puis appel de ``/protected-resource``.

Deux cibles : l'application locale montée en ``TestClient`` (défaut) ou, si
``PURIDENTITYSERVER_CONFORMANCE_URL`` est défini, un OP réel déjà démarré
(``httpx``) — même pilote, seul le transport change, comme
``harness.ConformanceHarness``.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

CIBA_GRANT = "urn:openid:params:grant-type:ciba"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: Valeurs du plan ``certification/plans/ciba.json`` : hint du ``client``,
#: portée template (``CopyScopeFromDynamicRegistrationTemplate...``),
#: ``binding_message`` par défaut (``AddBindingMessage...DEFAULT_BINDING_MESSAGE``)
#: et ACR du ``client2`` (``CopyAcrValueFromDynamicRegistrationTemplate...``).
HINT_VALUE = "alice.martin@example.com"
CLIENT_SCOPE = "openid profile offline_access"
BINDING_MESSAGE = "1234"
ACR_VALUE = "loa2"

#: Durée de vie du JAR (``exp - nbf``) — borne FAPI-CIBA-ID1 §5.2.2 : 60 min.
_JAR_LIFETIME = 300


@dataclass(frozen=True)
class CibaClient:
    """Client CIBA éphémère : ``client_id``, paire RSA et ``kid`` associés."""

    client_id: str
    private_key: RSAPrivateKey
    kid: str
    scope: str = CLIENT_SCOPE


class CibaHarness:
    """Pilote le flow CIBA (DCR → JAR → ``/bc-authorize`` → poll → ressource)."""

    def __init__(self, app: FastAPI) -> None:
        """Prépare le transport : ``TestClient`` local ou OP distant (env var)."""
        remote = os.environ.get("PURIDENTITYSERVER_CONFORMANCE_URL", "").rstrip("/")
        self.remote = bool(remote)
        self._client: httpx.Client = (
            httpx.Client(base_url=remote, follow_redirects=False, timeout=30.0)
            if remote
            else TestClient(app, follow_redirects=False)
        )
        self._discovery: dict[str, Any] | None = None

    def __enter__(self) -> CibaHarness:
        """Démarre le lifespan de l'application (seed des comptes)."""
        if isinstance(self._client, TestClient):
            self._client.__enter__()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Arrête le transport (fermeture différée de l'OP distant)."""
        if isinstance(self._client, TestClient):
            self._client.__exit__(None, None, None)
        else:
            self._client.close()

    def discovery(self) -> dict[str, Any]:
        """Document ``/.well-known/openid-configuration`` (``GetDynamicServerConfiguration``)."""
        if self._discovery is None:
            response = self._client.get("/.well-known/openid-configuration")
            assert response.status_code == 200, (
                f"discovery HTTP {response.status_code} : {response.text[:300]}"
            )
            self._discovery = dict(response.json())
        return self._discovery

    @property
    def issuer(self) -> str:
        """``issuer`` du document de discovery."""
        return str(self.discovery()["issuer"])

    @property
    def token_endpoint(self) -> str:
        """``token_endpoint`` du document de discovery."""
        return str(self.discovery()["token_endpoint"])

    def register(
        self,
        *,
        name: str,
        grant_types: tuple[str, ...] = (CIBA_GRANT,),
        scope: str = CLIENT_SCOPE,
    ) -> CibaClient:
        """Enregistre un client éphémère (``registerClient()``, DCR sans access token).

        ``grant_types`` ajoute ``refresh_token`` pour le module
        ``fapi-ciba-id1-refresh-token`` (``AddRefreshTokenGrantType...``).
        """
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = f"{name}-{secrets.token_hex(4)}"
        jwks = {"keys": [_public_jwk(private, kid)]}
        response = self._client.post(
            "/register",
            json={
                "client_name": name,
                "grant_types": list(grant_types),
                "response_types": [],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": jwks,
                "backchannel_token_delivery_mode": "poll",
                "backchannel_user_code_parameter": False,
                "backchannel_authentication_request_signing_alg": "PS256",
                "id_token_signed_response_alg": "PS256",
                "token_endpoint_auth_signing_alg_values": ["PS256"],
            },
        )
        assert response.status_code == 201, (
            f"DCR refusé ({response.status_code}) : {response.text[:300]}"
        )
        payload = dict(response.json())
        client_id = str(payload.get("client_id", ""))
        assert client_id, f"client_id absent de la réponse DCR : {sorted(payload)}"
        return CibaClient(client_id=client_id, private_key=private, kid=kid, scope=scope)

    def jar_claims(self, client: CibaClient, **overrides: object) -> dict[str, Any]:
        """Claims par défaut d'un JAR (scope, hint, ``binding_message``, bornes)."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": client.client_id,
            "aud": self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + _JAR_LIFETIME,
            "jti": secrets.token_urlsafe(16),
            "scope": client.scope,
            "login_hint": HINT_VALUE,
            "binding_message": BINDING_MESSAGE,
        }
        claims.update(overrides)
        return claims

    def jar(
        self,
        client: CibaClient,
        *,
        remove: tuple[str, ...] = (),
        algorithm: str = "PS256",
        key: RSAPrivateKey | None = None,
        kid: str | None = None,
        headers: dict[str, str] | None = None,
        **overrides: object,
    ) -> str:
        """Signe un JAR ``PS256`` (mutations : claims retirés/ remplacés, alg).

        ``key``/``kid`` permettent de signer avec la clé d'un **autre** client
        (``EnsureRequestObjectSignedByOtherClientFails``) ; ``algorithm="none"``
        produit un jeton non signé (``SignatureAlgorithmIsNoneFails``) ;
        ``headers`` complète l'en-tête (``typ`` « OautH-auThZ-REQ+jWt » du
        second client, ``SignRequestObjectIncludeMediaType``).
        """
        claims = self.jar_claims(client, **overrides)
        for name in remove:
            claims.pop(name, None)
        signed_headers: dict[str, str] = {"kid": kid if kid is not None else client.kid}
        if headers:
            signed_headers.update(headers)
        if algorithm == "none":
            unsigned_key: Any = None
            return str(pyjwt.encode(claims, unsigned_key, algorithm="none"))
        signing_key: Any = key if key is not None else client.private_key
        return str(pyjwt.encode(claims, signing_key, algorithm=algorithm, headers=signed_headers))

    def assertion(
        self,
        client: CibaClient,
        *,
        audience: str | Sequence[str] | None = None,
        algorithm: str = "PS256",
        kid: str | None = None,
        **overrides: object,
    ) -> str:
        """Assertion ``private_key_jwt`` fraîche (RFC 7523 §2.1, ``iss`` = ``sub``)."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": client.client_id,
            "sub": client.client_id,
            "aud": audience if audience is not None else [self.issuer, self.token_endpoint],
            "iat": now,
            "exp": now + 300,
            "jti": secrets.token_urlsafe(16),
        }
        claims.update(overrides)
        headers = {"kid": kid if kid is not None else client.kid}
        return str(pyjwt.encode(claims, client.private_key, algorithm=algorithm, headers=headers))

    def bc_form(
        self,
        client: CibaClient,
        jar: str,
        *,
        with_assertion: bool = True,
        assertion_algorithm: str = "PS256",
        assertion_audience: str | Sequence[str] | None = None,
        with_request: bool = True,
    ) -> dict[str, str]:
        """Corps form ``/bc-authorize`` : ``{request, client_assertion, type}``."""
        form: dict[str, str] = {}
        if with_request:
            form["request"] = jar
        if with_assertion:
            form["client_assertion"] = self.assertion(
                client,
                audience=assertion_audience,
                algorithm=assertion_algorithm,
            )
            form["client_assertion_type"] = ASSERTION_TYPE
        return form

    def bc_authorize(self, form: dict[str, str]) -> httpx.Response:
        """``POST /bc-authorize`` (``CallBackchannelAuthenticationEndpoint``)."""
        return self._client.post("/bc-authorize", data=form)

    def approve(self, auth_req_id: str, action: str = "allow") -> httpx.Response:
        """``POST /ciba/approve?token={auth_req_id}&type={action}`` (§9)."""
        return self._client.post("/ciba/approve", params={"token": auth_req_id, "type": action})

    def poll(
        self,
        client: CibaClient,
        auth_req_id: str,
        *,
        assertion_algorithm: str = "PS256",
        assertion_audience: str | Sequence[str] | None = None,
        with_assertion: bool = True,
    ) -> httpx.Response:
        """``POST /token`` (grant CIBA) avec une assertion fraîche (§10.1)."""
        data: dict[str, str] = {
            "grant_type": CIBA_GRANT,
            "auth_req_id": auth_req_id,
            "client_id": client.client_id,
        }
        if with_assertion:
            data["client_assertion"] = self.assertion(
                client,
                audience=assertion_audience,
                algorithm=assertion_algorithm,
            )
            data["client_assertion_type"] = ASSERTION_TYPE
        return self._client.post("/token", data=data)

    def refresh(self, client: CibaClient, refresh_token: str) -> httpx.Response:
        """``POST /token`` (grant ``refresh_token``, assertion fraîche)."""
        return self._client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client.client_id,
                "client_assertion": self.assertion(client),
                "client_assertion_type": ASSERTION_TYPE,
            },
        )

    def resource(self, access_token: str, *, interaction_id: str = "") -> httpx.Response:
        """``GET /protected-resource`` (Bearer + ``x-fapi-interaction-id``, FAPI §7.4)."""
        headers = {"Authorization": f"Bearer {access_token}"}
        if interaction_id:
            headers["x-fapi-interaction-id"] = interaction_id
        return self._client.get("/protected-resource", headers=headers)

    def tokens(self, client: CibaClient, auth_req_id: str, *, attempts: int = 20) -> dict[str, Any]:
        """Approuve puis poll jusqu'aux jetons (``waitForPollingAuthenticationToComplete``)."""
        self.approve(auth_req_id, "allow")
        for _ in range(attempts):
            response = self.poll(client, auth_req_id)
            if response.status_code == 200:
                return dict(response.json())
            error = dict(response.json()).get("error", "")
            assert error in ("authorization_pending", "slow_down"), (
                f"poll en attente attendu, reçu {response.status_code} : {response.text[:300]}"
            )
            time.sleep(0.05)
        raise AssertionError(f"jetons jamais émis pour {auth_req_id[:16]}…")


def _public_jwk(private: RSAPrivateKey, kid: str) -> dict[str, str]:
    """JWK public ``RSA`` (``use=sig``, ``alg=PS256``) de ``private``."""
    numbers = private.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "PS256",
        "kid": kid,
        "n": _b64url(numbers.n),
        "e": _b64url(numbers.e),
    }


def _b64url(value: int) -> str:
    """Entier big-endian encodé base64url sans padding (RFC 7515 §2)."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")
