"""Mini-client FAPI 2.0 Security Profile local (issue #111).

Le harness joue le rôle du client FAPI2 de la suite officielle
(`openid/conformance-suite`, plans ``fapi2-security-profile-final-test-plan``
et ``fapi2-security-profile-id2-test-plan``) contre l'application locale, en
profil baseline ``fapi_request_method=unsigned`` : la demande d'autorisation
est poussée en **paramètres de formulaire plats** (sans request object) à
``POST /par``, puis référencée par ``request_uri``.

Differences avec ``fapi_harness`` (FAPI1 Advanced) :

- ``response_type=code`` seul (FAPI2-SP-5.3.2.2-2), ``nonce`` optionnel ;
- PKCE ``S256`` toujours présent (FAPI2-SP-5.3.2.2-5) ;
- ``dpop_jkt`` optionnel au push (RFC 9449 §10), preuve DPoP ``ES256`` sur
  ``/token`` et ``/protected-resource`` quand la demande lie le jeton ;
- ``iss`` (RFC 9207) attendu au callback.

Deux clients statiques (clés RSA committées partagées avec FAPI1) portent
``fapi2_enabled=True`` et authentifient en ``private_key_jwt``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Sequence
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fapi_harness import (
    ASSERTION_TYPE,
    FAPI_CLIENT_1,
    FAPI_CLIENT_2,
    FAPI_SCOPE,
    FapiClient,
)
from fastapi import FastAPI
from harness import ConformanceHarness, FlowResult, pkce_challenge

#: Portée FAPI2 : ``offline_access`` alimente le module ``refresh-token``.
FAPI2_SCOPE = FAPI_SCOPE

FAPI2_REDIRECT_URI = "https://fapi2.example/callback"
FAPI2_REDIRECT_URI_OTHER = "https://fapi2.example/callback?dummy1=lorem&dummy2=ipsum"


def _ec_jwk(key: EllipticCurvePrivateKey, kid: str) -> dict[str, str]:
    """JWK public EC P-256 (``use=sig``, ``alg=ES256``) dérivé de la clé."""
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": _b64url_int(numbers.x),
        "y": _b64url_int(numbers.y),
    }


def _b64url_int(value: int) -> str:
    """Coordonnée P-256 encodée base64url sans padding, longueur fixe 32 octets.

    RFC 7518 §6.2.1 : ``x``/``y`` font la pleine taille de la courbe avec
    zéros de tête — encodage à longueur variable (0,8 % des clés) rendait la
    ``jwk`` illisible pour l'OP (``Coords should be 32 bytes …``).
    """
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def _ec_thumbprint(jwk: dict[str, str]) -> str:
    """Empreinte RFC 7638 d'un JWK EC (champs ``crv``/``kty``/``x``/``y`` triés)."""
    members = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(members.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class DpopSigner:
    """Clé EC éphémère du client et fabrication des preuves DPoP (RFC 9449).

    Une instance par harness : la même clé produit le ``dpop_jkt`` de la
    demande poussée, les preuves ``/token`` et les preuves ressource — c'est
    la liaison ``FAPI2SenderConstrainMethod=dpop`` de la suite.
    """

    def __init__(self) -> None:
        """Génère la clé P-256 privée et dérive JWK + empreinte (plus une clé étrangère)."""
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = _ec_jwk(self.key, "fapi2-dpop")
        self.thumbprint = _ec_thumbprint(self.jwk)
        self.foreign_key = ec.generate_private_key(ec.SECP256R1())

    def proof(
        self,
        htu: str,
        htm: str = "POST",
        *,
        ath: str = "",
        iat: int | None = None,
        jti: str = "",
        typ: str = "dpop+jwt",
        key: EllipticCurvePrivateKey | None = None,
        htu_override: str | None = None,
    ) -> str:
        """Preuve ``dpop+jwt`` ``ES256`` pour ``htu``/``htm``.

        ``ath`` ajoute l'empreinte du token (preuve ressource) ; ``iat``/
        ``jti``/``typ`` surchargent les valeurs par défaut (modules de skew et
        ``dpop-negative-tests``) ; ``htu_override`` trahi l'``htu`` (mauvaise
        URL) ; ``key`` signe avec une autre clé (``ensure-token-endpoint-fails-
        with-mismatched-dpop-jkt``).
        """
        signing_key = key if key is not None else self.key
        headers: dict[str, str] = {
            "typ": typ,
            "jwk": self.jwk if key is None else _ec_jwk(signing_key, "fapi2-dpop"),
        }
        claims: dict[str, Any] = {
            "jti": jti or secrets.token_urlsafe(16),
            "htm": htm,
            "htu": htu_override if htu_override is not None else htu,
            "iat": iat if iat is not None else int(time.time()),
        }
        if ath:
            claims["ath"] = ath
        return str(pyjwt.encode(claims, signing_key, algorithm="ES256", headers=headers))


FAPI2_CLIENT_1 = FapiClient(
    client_id="fapi2-app",
    redirect_uri=FAPI2_REDIRECT_URI,
    private_pem=FAPI_CLIENT_1.private_pem,
    kid="fapi2-client1",
    scope=FAPI2_SCOPE,
)
FAPI2_CLIENT_2 = FapiClient(
    client_id="fapi2-app-2",
    redirect_uri=FAPI2_REDIRECT_URI_OTHER,
    private_pem=FAPI_CLIENT_2.private_pem,
    kid="fapi2-client2",
    scope=FAPI2_SCOPE,
)


def _fapi2_seed_of(client: FapiClient) -> dict[str, object]:
    """Entrée ``clients_seed`` d'un client FAPI2 (``fapi2_enabled``, PS256)."""
    return {
        "client_id": client.client_id,
        "redirect_uris": [FAPI2_REDIRECT_URI, FAPI2_REDIRECT_URI_OTHER],
        "scopes": FAPI2_SCOPE,
        "client_type": "confidential",
        "token_endpoint_auth_method": "private_key_jwt",
        "fapi2_enabled": True,
        "require_consent": True,
        "id_token_signed_response_alg": "PS256",
        "jwks": [client.jwk],
        "authorization_code_lifetime_seconds": 60,
    }


FAPI2_CLIENT_SEED = _fapi2_seed_of(FAPI2_CLIENT_1)
FAPI2_CLIENT_2_SEED = _fapi2_seed_of(FAPI2_CLIENT_2)


class Fapi2Harness(ConformanceHarness):
    """Pilote le flow FAPI2 (PAR en params plats, PKCE, DPoP, ``private_key_jwt``)."""

    def __init__(self, app: FastAPI, *, client: FapiClient = FAPI2_CLIENT_1) -> None:
        """Client FAPI2 lié par défaut ; ``switch`` bascule vers le second."""
        super().__init__(
            app,
            client_id=client.client_id,
            client_secret="",
            redirect_uri=client.redirect_uri,
        )
        self.client = client
        self.dpop = DpopSigner()
        self.verifier = secrets.token_urlsafe(48)
        self._last_request_uri = ""
        self._discovery: dict[str, Any] | None = None

    def switch(self, client: FapiClient) -> None:
        """Change le client courant (modules « second client » / cross-client)."""
        self.client = client
        self._client_id = client.client_id
        self._redirect_uri = client.redirect_uri

    def discovery(self) -> dict[str, Any]:
        """Document ``/.well-known/openid-configuration``."""
        if self._discovery is None:
            response = self._client.get("/.well-known/openid-configuration")
            assert response.status_code == 200, (
                f"discovery HTTP {response.status_code} : {response.text[:300]}"
            )
            self._discovery = dict(response.json())
        return self._discovery

    @property
    def issuer(self) -> str:
        """``issuer`` du discovery."""
        return str(self.discovery()["issuer"])

    @property
    def token_endpoint(self) -> str:
        """``token_endpoint`` du discovery."""
        return str(self.discovery()["token_endpoint"])

    @property
    def par_endpoint(self) -> str:
        """``pushed_authorization_request_endpoint`` du discovery."""
        return str(self.discovery().get("pushed_authorization_request_endpoint", ""))

    @property
    def protected_resource_url(self) -> str:
        """URL absolue de la ressource protégée locale."""
        return f"{self.issuer}/protected-resource"

    def assertion(
        self,
        *,
        audience: str | Sequence[str] | None = None,
        algorithm: str = "PS256",
        kid: str | None = None,
        key: RSAPrivateKey | None = None,
        remove: tuple[str, ...] = (),
        **overrides: object,
    ) -> str:
        """Assertion ``private_key_jwt`` fraîche (RFC 7523 §2.1, ``iss``=``sub``).

        ``aud`` par défaut l'``issuer`` ; les modules audience passent le
        ``token_endpoint``, le ``par_endpoint`` ou un tableau. ``remove``
        retire des claims (``RemoveSubFromClientAssertionClaims``),
        ``overrides`` les remplace (``AddWrongAud…``, ``nbf``…).
        """
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": audience if audience is not None else self.issuer,
            "iat": now,
            "exp": now + 300,
            "jti": secrets.token_urlsafe(16),
        }
        claims.update(overrides)
        for name in remove:
            claims.pop(name, None)
        headers = {"kid": kid if kid is not None else self.client.kid}
        signing_key: Any = key if key is not None else self.client.private_key
        return str(pyjwt.encode(claims, signing_key, algorithm=algorithm, headers=headers))

    def authorize_params(self, **overrides: str) -> dict[str, str]:
        """Paramètres plats d'une demande FAPI2 (``code`` + PKCE ``S256``).

        Équivalent de ``CreateAuthorizationEndpointRequestFromClientInformation``
        + ``SetupPkceAndAddToAuthorizationRequest`` de la suite : ``state``
        aléatoire, ``nonce`` aléatoire (optionnel en FAPI2, présent par
        défaut), ``code_challenge`` ``S256`` du vérificateur courant.
        """
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": self.client.scope,
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": pkce_challenge(self.verifier),
            "code_challenge_method": "S256",
        }
        params.update(overrides)
        return params

    def push_form(
        self,
        form: dict[str, str],
        *,
        with_assertion: bool = True,
        audience: str | Sequence[str] | None = None,
        assertion: str | None = None,
        method: str = "POST",
    ) -> httpx.Response:
        """``POST /par`` en params plats (``BuildUnsignedPAREndpointRequest``).

        ``method`` rejoue ``par-attempt-invalid-http-method`` ; ``assertion``
        fournit une ``client_assertion`` déjà construite (modules de rejet).
        """
        payload = dict(form)
        if with_assertion:
            payload["client_assertion"] = (
                assertion if assertion is not None else self.assertion(audience=audience)
            )
            payload["client_assertion_type"] = ASSERTION_TYPE
        return self._client.request(method, "/par", data=payload)

    def push_ok(
        self,
        form: dict[str, str],
        *,
        with_assertion: bool = True,
        audience: str | Sequence[str] | None = None,
        assertion: str | None = None,
    ) -> str:
        """Pousse et retourne le ``request_uri`` (201, PAR-2.2)."""
        response = self.push_form(
            form,
            with_assertion=with_assertion,
            audience=audience,
            assertion=assertion,
        )
        assert response.status_code == 201, (
            f"POST /par refusé ({response.status_code}) : {response.text[:300]}"
        )
        payload = dict(response.json())
        assert "error" not in payload, f"réponse /par en erreur : {payload}"
        request_uri = str(payload.get("request_uri", ""))
        assert request_uri, f"request_uri absente de la réponse : {sorted(payload)}"
        self._last_request_uri = request_uri
        return request_uri

    def start_authorization(
        self,
        params: dict[str, str] | None = None,
        *,
        verifier: str = "",
        deny_consent: bool = False,
        push: bool = True,
        **extra: str,
    ) -> FlowResult:
        """Enchaîne ``POST /par`` puis ``GET /authorize?request_uri=…``.

        ``push=False`` saute le push (modules ``…without-using-par-fails``) ;
        ``params`` surcharge les paramètres plats poussés ; ``extra`` ajoute
        des paramètres à l'appel ``/authorize`` (modules divergents — notre OP
        les ignore quand ``request_uri`` est présent : la demande poussée
        prime, RFC 9126 §6.2).
        """
        form = params if params is not None else self.authorize_params()
        if not push:
            return self.run_flow(deny_consent=deny_consent, **form, **extra)
        request_uri = self.push_ok(form)
        auth_params = {"request_uri": request_uri, "client_id": self._client_id}
        auth_params.update(extra)
        return self.run_flow(deny_consent=deny_consent, **auth_params)

    def token_request(
        self,
        data: dict[str, str],
        auth_method: str = "private_key_jwt",
        *,
        audience: str | Sequence[str] | None = None,
        assertion: str | None = None,
        dpop: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """POST ``/token`` avec ``private_key_jwt`` (défaut) et preuve DPoP optionnelle.

        ``dpop`` fournit la ``DPoP`` header déjà construite ; ``assertion``
        une ``client_assertion`` déjà construite ; ``headers`` ajoute des
        en-têtes (cas ``DPoP``/``Bearer`` inversés).
        """
        payload = dict(data)
        if auth_method == "private_key_jwt":
            payload["client_assertion"] = (
                assertion
                if assertion is not None
                else self.assertion(audience=self.issuer if audience is None else audience)
            )
            payload["client_assertion_type"] = ASSERTION_TYPE
        request_headers = dict(headers or {})
        if dpop is not None:
            request_headers["DPoP"] = dpop
        return self._client.post("/token", data=payload, headers=request_headers)

    def exchange_code(
        self,
        result: FlowResult,
        verifier: str | None = None,
        auth_method: str = "private_key_jwt",
        *,
        audience: str | Sequence[str] | None = None,
        assertion: str | None = None,
        dpop: bool = True,
        dpop_proof: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Échange le code du callback (PKCE + ``private_key_jwt`` + DPoP).

        ``dpop=False`` omet la preuve (tokens non bound — ``ensure-holder-of-
        key-required``) ; ``dpop_proof`` la fournit déjà construite (preuve
        déloyale des modules ``mismatched``).
        """
        if not result.code:
            raise AssertionError(f"aucun code dans le callback : {result.callback_url!r}")
        use_verifier = self.verifier if verifier is None else verifier
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": self._redirect_uri,
        }
        if use_verifier:
            payload["code_verifier"] = use_verifier
        if auth_method == "client_id":
            payload["client_id"] = self._client_id
        if extra:
            payload.update(extra)
        proof = (
            dpop_proof
            if dpop_proof is not None
            else (self.dpop.proof(self.token_endpoint) if dpop else None)
        )
        response = self.token_request(
            payload,
            auth_method,
            audience=audience,
            assertion=assertion,
            dpop=proof,
        )
        if response.status_code != 200:
            raise AssertionError(
                f"échange du code refusé ({response.status_code}) : {response.text[:300]}"
            )
        return dict(response.json())

    def refresh(
        self,
        refresh_token: str,
        *,
        auth_method: str = "private_key_jwt",
        dpop: bool = True,
        dpop_proof: str | None = None,
    ) -> httpx.Response:
        """``POST /token`` (grant ``refresh_token``) avec preuve DPoP optionnelle."""
        proof = (
            dpop_proof
            if dpop_proof is not None
            else (self.dpop.proof(self.token_endpoint) if dpop else None)
        )
        return self.token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            auth_method,
            dpop=proof,
        )

    def resource(
        self,
        access_token: str,
        *,
        interaction_id: str = "",
        scheme: str = "",
        dpop: bool = True,
        dpop_proof: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """``GET /protected-resource`` (scheme + ``x-fapi-interaction-id`` + DPoP).

        ``scheme`` vide : ``DPoP`` quand une preuve est jointe (token bound,
        RFC 9449 §7.1), sinon ``Bearer`` ; ``scheme`` explicite inverse la
        casse du ``token_type`` (``SetAccessTokenTypeToInvertedCase``,
        RFC 9110 §11.1). ``dpop=False`` envoie sans preuve (rejet attendu).
        """
        proof = (
            dpop_proof
            if dpop_proof is not None
            else (self._resource_proof(access_token) if dpop else None)
        )
        effective_scheme = scheme or ("DPoP" if proof is not None else "Bearer")
        request_headers = {"Authorization": f"{effective_scheme} {access_token}"}
        if interaction_id:
            request_headers["x-fapi-interaction-id"] = interaction_id
        if proof is not None:
            request_headers["DPoP"] = proof
        if headers:
            request_headers.update(headers)
        return self._client.get("/protected-resource", headers=request_headers)

    def userinfo(
        self,
        access_token: str,
        *,
        scheme: str | None = None,
        dpop: bool = True,
    ) -> httpx.Response:
        """``GET /userinfo`` avec preuve DPoP optionnelle (token bound).

        ``scheme`` par défaut ``DPoP`` quand une preuve est jointe (RFC 9449
        §7.2 : un token lié exige le scheme ``DPoP``), ``Bearer`` sinon.
        """
        if scheme is None:
            scheme = "DPoP" if dpop else "Bearer"
        request_headers = {"Authorization": f"{scheme} {access_token}"}
        if dpop:
            request_headers["DPoP"] = self._userinfo_proof(access_token)
        return self._client.get("/userinfo", headers=request_headers)

    def _resource_proof(self, access_token: str) -> str:
        """Preuve DPoP ressource (``htu`` = URL réelle vue par le RS, ``ath``)."""
        from puridentityserver.domain.dpop import access_token_hash

        base = str(self._client.base_url).rstrip("/")
        return self.dpop.proof(
            f"{base}/protected-resource",
            "GET",
            ath=access_token_hash(access_token),
        )

    def _userinfo_proof(self, access_token: str) -> str:
        """Preuve DPoP userinfo (``htu`` = URL réelle vue par le RS)."""
        from puridentityserver.domain.dpop import access_token_hash

        base = str(self._client.base_url).rstrip("/")
        return self.dpop.proof(f"{base}/userinfo", "GET", ath=access_token_hash(access_token))
