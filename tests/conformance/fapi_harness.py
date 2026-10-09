"""Mini-client FAPI 1.0 Advanced Final local (issue #110).

Le harness joue le rôle du client FAPI de la suite officielle
(`openid/conformance-suite`, plan ``fapi1-advanced-final-test-plan``) contre
l'application locale, avec les deux variantes ``fapi_auth_request_method`` :

- ``by_value`` : ``GET /authorize?…&request=<JAR>`` (+ doublons
  ``response_type``/``client_id``/``scope``/``redirect_uri`` exigés par
  RFC 6749 §3.1 / OIDC « Request Object ») ;
- ``pushed`` : ``POST /par`` (forme ``{request, client_assertion,
  client_assertion_type}``, ``BuildRequestObjectPostToPAREndpoint``), puis
  ``GET /authorize?request_uri=…&client_id=…``.

Deux clients statiques (clés RSA committées, JWKS dérivés des PEM au
chargement — la suite lit ``client.jwks`` statiques) authentifient en
``private_key_jwt`` : ``aud`` par défaut l'``issuer`` sur ``/par``
(``UpdateClientAuthenticationAssertionClaimsWithISSAud``) et le
``token_endpoint`` sur ``/token`` (``CreateClientAuthenticationAssertionClaims``).

Deux cibles : l'application locale montée en ``TestClient`` (défaut) ou, si
``PURIDENTITYSERVER_CONFORMANCE_URL`` est défini, un OP réel déjà démarré —
même pilote, seul le transport change.
"""

from __future__ import annotations

import base64
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import FastAPI
from harness import ConformanceHarness, FlowResult, pkce_challenge

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: Portée du JAR (``client.scope`` de la suite) — ``offline_access`` alimente
#: le module ``fapi1-advanced-final-refresh-token``.
FAPI_SCOPE = "openid profile offline_access"

#: Borne ``exp - nbf`` du JAR (``AddExpToRequestObject`` : ``exp = now + 5 min``,
#: ``AddNbfToRequestObject`` : ``nbf = now`` — FAPI1-ADV-5.2.2-13/-17).
_JAR_LIFETIME = 300

_PEM_CLIENT_1 = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5z4T6xsnr3U7T
Q2Oyo2o7yKPiWFZIeenBKv218G4cZ1snefHyh/scX8LEtq8FIxRQYlgEad/q782H
BUgtoqfK12E4fPPsrzJXRnHXs+/V57yEdjztuwCjowAhw3P/3L4CD6S90ZMZ7DtR
FNMu6fMSZ4KhwXQJ2PHMqnZqBNdNqh1NlorQoLNNh8BVxlkerjNg5ItT74MByvar
ar4xrV9ChmBmpJGegN1ngsN9rj+HiDsZxTChS10B/9DnWTm3PkreqLoV+YhEMDB4
+K/N/dGtmT/sRPnn+re86OupPp7Byx4J+dxhXBDOdvr7OhGuGw0y6aVvJd/D8IRO
ucOvpG7XAgMBAAECggEALM5dX0mrbGyP8wLXmj6sweDWoCC0IcMAOrv+tS5WpxPH
V+Qgk172DzgKU/xHhSIZ5m5okhvjypfsBEiiSJrmAlRglcoP2f2/UmtizWSPC5JX
k8udUqha9Zq7T+j9YnAdA4s5KyrL4Z7lCN7QNApnOoNqbU4kiLFfUX6zkko7jvby
6cCR1FUrugsNHeUKWaLOOc0lxUEFzj71EO/lF21w3FNXTsHwALpuP0FnT5lNogdX
tojNtMtYonokOre41udb0eCLlYSmayWv35Jg4DofX9asxGye7FBYt15iC2I/Hn7M
7m829AdbapTrtdzCpky4PlFD97MFJN5NvDsxRP9yXQKBgQDdsQEzZES385dPWZHt
tGOuCqKCgjUb4jOJsYylLe4Yrow5swDTnsysmSuunNG+Ebqu3LKlF8+3KSDZoWo4
CqEgerZtpk8RVfsAVtCNEjYP/hPWxsIMHaMaafV9aLX8i0zA+fR7Te6h9AtWhag/
ULonnxS+iyg/oIUSuyRuT41q+wKBgQDWkPw2KQtqWeLZDE3QyQtWz9VD9pNzlYoz
yZIwYm3xuUF5FHDGrcVMENm/z0BR4OT//XeOypwpB3A+J2hRys44cG4RNjqOIXOP
zNlcbrSsLqIpgeNCI6zP+YG/dg70ikJ4GEWiVmWgQs8hsE61lhv8XFV8COqaOC3z
ZwFIgqOE1QKBgHEE4yrTDGGHcvVGIapAk6zPySelv/OWL1YcSSqQrtiwa9ailmJM
i+XWNLnRQvCWU0kARKb7665h7lhk/STS7nADf2uJJLge0FbM64dv6FXg3zZYn+bT
WSqHKFsl/dlhHuEmzOfrxCOWqg0TGMImorC+XjIB+aPubsks1RbTwbHvAoGBAKs9
FHvo79pVmCxenG/HM0x6G5rc27rAGobQFOKWe2YR0kXeYU6+ehoFzLI+pfdyg3Al
ilgkLNK1xAdmjePQ9hmm6MDFxZ+O5NpbwxD4rSpJIVP8/DDZpd5pIvp5LuBMw1Vz
EYfIadyn1QTu3zIedYFG81ZFC24+7bU2fJiw4e1tAoGANSGM9dcfCTV/DuuKIRER
um01jxmivRp1uUfQYmh8LM2ferS+4YU7/jfMJnzrF/jzz8TLgT5PLPg8QvRfBVLF
JascUzJ5cvuhrt0IcoDTZtVhh66meQ1ZdT2pk+oqMSUPin1mPJ/Q4IgS9HbLvt5H
e+VQ4R06rB040X2XcGkxPc4=
-----END PRIVATE KEY-----"""

_PEM_CLIENT_2 = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSngIipGFP4I5L
QlZ+1pD3pd90jb7MOnKfOrxRIKkDQmRoLrqXIY0x8UFLC4z+AlWhKy9c1HhkOIbM
lT68wWv3ARoLi5ILUKeEu108CBUqcC814OwA2VVzeVgmXmbREa4Nr/ZgeXbsTWV+
udpB5wBgCT6mZTM7v7tZ24qkXS+wooiZKDymd/uScGMle1K2jsrcO9DEI4UbFPpG
OaLalGSB1G4/gFtqUxsQXblJWldzUDUdL3mix0hY8JoYcXZI2uGBfeIE9In975s4
9oHaGutsAn1q3t0Jh1lOnXQ2pI8OsU1Kd8avwfu+l6cNptI6v2CYMXFtLv4zApqM
KNb1bownAgMBAAECggEAC5fK7PaOAgQ4O4hBPpC3lgoOogRoq3vOx1jyTfzgO1+y
Kyc3T2OiDqJa7QiLutziCGcEyl/06H9RXCgdi0I88RxMagpFVajGL8DTFvTS8Be7
YYR/OQ9oFrJn2bokf/7bImxnFqmuPr+Ghf0w4vkWGjMoEadMX045v8PH09g/7GxM
LngRpddIuACMArf5u204w43fGQDg0/qVw0BuHO70gkjbn+KIOswliu2V6SgbMNDH
ITc9/wpZZpi7Pr4Yhx8i0FG16f8Fk+F3dyySHOVhqMvcFVdVfOg4MailqwMFrZp3
79LRh7LeJB/OQeP5X2FTrNKLoX74prRwagQCsmYtMQKBgQD/jSFryl+kvQlCu4iW
aQ1x09xo+cm3AyfkkhrCkBD2Pi4nS+wwoBnZPmIUXdJv7wLDlvAPMZ/mebFlyBuj
6Cuw09xPa7TDy1XLypdFWT9I3iOTuLhb8S0OJRbFLo58BtnKSbY57vvf/zFC6ws5
cOBfeK2gB9x0vyt4OjNX1EvjTQKBgQDS/K4ZcPbNooxcB9N6cN+gCe+oZwvxa9mo
hXVPqLp+NvfA0b2CRK9qepEWafHbPsHtVnwHovKlgcxYKmQpV/Slt5OZbqZsDavh
1kO0YUpBjc9tUxi5qXn2DuzICThTbIJibqc+UmqSqh0gaEfQYKYoAI7PK1Lbj2SD
v6Sjh6TLQwKBgQCOzkAh6zpdZeHZ79BZNSV1OY5O/19QrSvK2DaqCTXhVUgXX58C
YUVwmCLY/MEPGgJyaFOIOhQACHswxI1ln+VicFIJ88dVLrioJHM6JrBtuO0qrKwh
fPnPkLxTvjuTZYSpPV3erAUG3KWbnptsIv7PezGTXzE78GSLUALHDvTFdQKBgHCT
EfHRLF6cFHgmVNhH0Yn6wzz/fofaG9CnJOjUBm3Btn/TaWJQc6hErZVgAgQRgDe6
pYMNlpponzeLptXIcGjbgo2jVHji8osVYBqmrpA7simK5O5rVv/LBtvUz5DznL4Y
fHPsVaDb056vBWJRr1Y4tfokC5nK8L67SoVWor8xAoGAAqeDBeI+kF+zzML032t5
hIMA5Ef/M20sv41tEs8349kQRXSU8T+iOzaVOK0hgDpYR9maZR/Ld1ykz1axUPwm
OYONrRayIMQGja0kn+V6zvMm+kcitX6DTQw/CoIicM2I1ZX2jSO/cp8yTEYOPXK6
xjyWiW2v6JdsSl54kLSVBGA=
-----END PRIVATE KEY-----"""

REDIRECT_URI = "https://fapi.example/callback"
#: Second client de la suite : même base + query étrangère
#: (``client2.redirect_uri`` des plans de certification).
REDIRECT_URI_OTHER = "https://fapi.example/callback?dummy1=lorem&dummy2=ipsum"


def _b64url(value: int) -> str:
    """Entier big-endian encodé base64url sans padding (RFC 7515 §2)."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class FapiClient:
    """Client FAPI seedé : identité, redirect_uri, clé privée statique."""

    client_id: str
    redirect_uri: str
    private_pem: str
    kid: str
    scope: str = FAPI_SCOPE

    @property
    def private_key(self) -> RSAPrivateKey:
        """Clé privée RSA chargée depuis le PEM committé."""
        key: Any = serialization.load_pem_private_key(
            self.private_pem.encode("ascii"), password=None
        )
        return key

    @property
    def jwk(self) -> dict[str, str]:
        """JWK public dérivé (``use=sig``, ``alg=PS256``) — seed ``jwks``."""
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "PS256",
            "kid": self.kid,
            "n": _b64url(numbers.n),
            "e": _b64url(numbers.e),
        }


FAPI_CLIENT_1 = FapiClient(
    client_id="fapi-app",
    redirect_uri=REDIRECT_URI,
    private_pem=_PEM_CLIENT_1,
    kid="fapi-client1",
)
FAPI_CLIENT_2 = FapiClient(
    client_id="fapi-app-2",
    redirect_uri=REDIRECT_URI_OTHER,
    private_pem=_PEM_CLIENT_2,
    kid="fapi-client2",
)


def _seed_of(client: FapiClient) -> dict[str, object]:
    """Entrée ``clients_seed`` d'un client FAPI (clés statiques, PS256).

    ``require_consent`` : l'écran de consentement est le point de refus
    rejoué par ``fapi1-advanced-final-user-rejects-authentication`` (il
    n'existe pas de bouton « annuler » sur l'écran de connexion).
    """
    return {
        "client_id": client.client_id,
        "redirect_uris": [REDIRECT_URI, REDIRECT_URI_OTHER],
        "scopes": FAPI_SCOPE,
        "client_type": "confidential",
        "token_endpoint_auth_method": "private_key_jwt",
        "fapi_enabled": True,
        "require_consent": True,
        "id_token_signed_response_alg": "PS256",
        "jwks": [client.jwk],
    }


#: Clients FAPI ajoutés au seed de ``build_app()`` (``conftest``) — la suite
#: officielle lit ``client``/``client2`` statiques (``GetStaticClient*``).
FAPI_CLIENT_SEED = _seed_of(FAPI_CLIENT_1)
FAPI_CLIENT_2_SEED = _seed_of(FAPI_CLIENT_2)


class FapiHarness(ConformanceHarness):
    """Pilote le flow FAPI 1.0 Advanced (JAR, PAR, ``private_key_jwt``)."""

    def __init__(self, app: FastAPI, *, client: FapiClient = FAPI_CLIENT_1) -> None:
        """Client FAPI lié par défaut ; ``switch`` bascule vers le second."""
        super().__init__(
            app,
            client_id=client.client_id,
            client_secret="",
            redirect_uri=client.redirect_uri,
        )
        self.client = client
        self._discovery: dict[str, Any] | None = None

    def switch(self, client: FapiClient) -> None:
        """Change le client courant (modules « second client » / cross-client)."""
        self.client = client
        self._client_id = client.client_id
        self._redirect_uri = client.redirect_uri

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

    @property
    def par_endpoint(self) -> str:
        """``pushed_authorization_request_endpoint`` du discovery."""
        return str(self.discovery().get("pushed_authorization_request_endpoint", ""))

    def jar_claims(self, verifier: str = "", **overrides: object) -> dict[str, Any]:
        """Claims par défaut du JAR (``CreateAuthorizationRequest*Steps``).

        ``response_type=code id_token`` (non-JARM), ``state``/``nonce``
        aléatoires, bornes ``nbf=now``/``exp=now+300`` ; ``verifier`` non vide
        ajoute le défi PKCE ``S256`` (``SetupPkceAndAddToAuthorizationRequest``,
        variante ``pushed`` uniquement).
        """
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self._client_id,
            "aud": self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + _JAR_LIFETIME,
            "jti": secrets.token_urlsafe(16),
            "response_type": "code id_token",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": self.client.scope,
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
        }
        if verifier:
            claims["code_challenge"] = pkce_challenge(verifier)
            claims["code_challenge_method"] = "S256"
        claims.update(overrides)
        return claims

    def jar(
        self,
        verifier: str = "",
        *,
        remove: tuple[str, ...] = (),
        algorithm: str = "PS256",
        key: RSAPrivateKey | None = None,
        kid: str | None = None,
        headers: dict[str, str] | None = None,
        **overrides: object,
    ) -> str:
        """Signe un JAR ``PS256`` (mutations : claims retirés/remplacés, alg).

        ``key``/``kid`` permettent de signer avec la clé d'un **autre** client
        (``EnsureMatchingKeyInAuthorizationRequest``) ; ``algorithm="none"``
        produit un jeton non signé
        (``EnsureRequestObjectSignatureAlgorithmIsNotNone``).
        """
        claims = self.jar_claims(verifier, **overrides)
        for name in remove:
            claims.pop(name, None)
        signed_headers: dict[str, str] = {"kid": kid if kid is not None else self.client.kid}
        if headers:
            signed_headers.update(headers)
        if algorithm == "none":
            return str(pyjwt.encode(claims, None, algorithm="none"))
        signing_key: Any = key if key is not None else self.client.private_key
        return str(pyjwt.encode(claims, signing_key, algorithm=algorithm, headers=signed_headers))

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

        ``aud`` par défaut l'``issuer`` (variante ``/par``) ; les modules
        ``…TokenEndpointAsAudience…`` passent le ``token_endpoint``.
        ``remove`` retire des claims (``RemoveSubFromClientAssertionClaims``),
        ``overrides`` les remplace (``AddWrongIssToClientAssertionClaims``…),
        ``key``/``kid`` signent avec la clé d'un **autre** client
        (``EnsureClientIdInTokenEndpoint`` : ``iss``=client 2 signé clé 1).
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

    def par_form(
        self,
        jar: str,
        *,
        with_assertion: bool = True,
        audience: str | Sequence[str] | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Corps form ``/par`` : ``{request}`` + authentification client."""
        form: dict[str, str] = {"request": jar}
        if with_assertion:
            form["client_assertion"] = self.assertion(audience=audience)
            form["client_assertion_type"] = ASSERTION_TYPE
        if extra:
            form.update(extra)
        return form

    def push(
        self,
        jar: str,
        *,
        with_assertion: bool = True,
        audience: str | Sequence[str] | None = None,
        extra: dict[str, str] | None = None,
        method: str = "POST",
    ) -> httpx.Response:
        """``POST /par`` (``CallPAREndpoint``) ; ``method`` rejoue ``EnsureParHTTPError``."""
        return self._client.request(
            method,
            "/par",
            data=self.par_form(jar, with_assertion=with_assertion, audience=audience, extra=extra),
        )

    def push_ok(
        self,
        jar: str,
        *,
        with_assertion: bool = True,
        audience: str | Sequence[str] | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        """Pousse et retourne le ``request_uri`` (201, PAR-2.2).

        Enchaîne ``CheckPAREndpointResponse201WithNoError``,
        ``CheckForRequestUriValue`` et ``CheckForPARResponseExpiresIn``.
        """
        response = self.push(jar, with_assertion=with_assertion, audience=audience, extra=extra)
        assert response.status_code == 201, (
            f"POST /par refusé ({response.status_code}) : {response.text[:300]}"
        )
        payload = dict(response.json())
        assert "error" not in payload, f"réponse /par en erreur : {payload}"
        request_uri = str(payload.get("request_uri", ""))
        assert request_uri, f"request_uri absente de la réponse : {sorted(payload)}"
        expires_in = payload.get("expires_in")
        assert (
            isinstance(expires_in, int) and not isinstance(expires_in, bool) and expires_in > 0
        ), f"expires_in invalide : {payload.get('expires_in')!r}"
        return request_uri

    def start_authorization(
        self, method: str, jar: str, *, deny_consent: bool = False, **extra: str
    ) -> FlowResult:
        """Première requête ``/authorize`` de la variante ``method``.

        ``by_value`` : ``request`` + doublons RFC 6749/OIDC
        (``BuildRequestObjectByValueRedirectToAuthorizationEndpoint``) ;
        ``pushed`` : ``request_uri`` + ``client_id``
        (``BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint``,
        PAR-4). ``deny_consent`` refuse l'écran de consentement
        (``ExpectAccessDeniedError…DueToUserRejectingRequest``).
        """
        if method == "by_value":
            params = {
                "request": jar,
                "client_id": self._client_id,
                "redirect_uri": self._redirect_uri,
                "response_type": "code id_token",
                "scope": self.client.scope,
            }
        elif method == "pushed":
            params = {
                "request_uri": self.push_ok(jar),
                "client_id": self._client_id,
            }
        else:
            raise AssertionError(f"variante fapi_auth_request_method inconnue : {method!r}")
        params.update(extra)
        return self.run_flow(deny_consent=deny_consent, **params)

    def exchange_code(
        self,
        result: FlowResult,
        verifier: str = "",
        auth_method: str = "private_key_jwt",
        *,
        audience: str | Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Échange le code du callback contre les jetons (PKCE si ``verifier``).

        ``private_key_jwt`` (défaut FAPI) joint l'assertion ``aud`` =
        ``token_endpoint`` ; ``client_id`` n'envoie que le ``client_id`` sans
        assertion (``EnsureClientIdInTokenEndpoint``, rejet attendu).
        ``audience`` surcharge l'``aud`` de l'assertion
        (``EnsureClientAssertionWithIssAudSucceeds``,
        ``…ArrayAsAudience…``).
        """
        if not result.code:
            raise AssertionError(f"aucun code dans le callback : {result.callback_url!r}")
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": self._redirect_uri,
        }
        if verifier:
            payload["code_verifier"] = verifier
        if auth_method == "client_id":
            payload["client_id"] = self._client_id
        response = self.token_request(payload, auth_method, audience=audience)
        if response.status_code != 200:
            raise AssertionError(
                f"échange du code refusé ({response.status_code}) : {response.text[:300]}"
            )
        return dict(response.json())

    def token_request(
        self,
        data: dict[str, str],
        auth_method: str = "private_key_jwt",
        *,
        audience: str | Sequence[str] | None = None,
        assertion: str | None = None,
    ) -> httpx.Response:
        """POST ``/token`` avec ``private_key_jwt`` (défaut) ou ``client_id`` seul.

        ``assertion`` fournit une ``client_assertion`` déjà construite
        (mutations des modules ``ensure-client-assertion-*-fails``) au lieu
        de l'assertion fraîche standard.
        """
        payload = dict(data)
        if auth_method == "private_key_jwt":
            payload["client_assertion"] = (
                assertion
                if assertion is not None
                else self.assertion(audience=self.token_endpoint if audience is None else audience)
            )
            payload["client_assertion_type"] = ASSERTION_TYPE
        return self._client.post("/token", data=payload)

    def refresh(self, refresh_token: str, auth_method: str = "private_key_jwt") -> httpx.Response:
        """``POST /token`` (grant ``refresh_token``, assertion fraîche)."""
        return self.token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}, auth_method
        )

    def resource(
        self,
        access_token: str,
        *,
        interaction_id: str = "",
        scheme: str = "Bearer",
    ) -> httpx.Response:
        """``GET /protected-resource`` (Bearer + ``x-fapi-interaction-id``, FAPI §7.4).

        ``scheme`` inverse la casse du ``token_type``
        (``SetAccessTokenTypeToInvertedCase``, RFC 9110 §11.1).
        """
        headers = {"Authorization": f"{scheme} {access_token}"}
        if interaction_id:
            headers["x-fapi-interaction-id"] = interaction_id
        return self._client.get("/protected-resource", headers=headers)
