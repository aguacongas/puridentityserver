"""Vérification de JWT Bearer : locale (clés du serveur) ou distante (JWKS).

Deux implémentations du port ``BearerTokenVerifier`` :

- ``LocalBearerVerifier`` valide un jeton signé par l'issuer courant à
  l'aide des clés de signature locales (aucun appel réseau) ;
- ``JwksBearerVerifier`` valide un jeton émis par un issuer tiers en
  récupérant le JWKS publié par cet issuer (discovery puis ``PyJWKClient``,
  qui met les clés en cache et gère la rotation).

``build_bearer_verifier`` choisit l'implémentation selon la configuration :
validation locale quand l'issuer de gestion est celui du serveur, distante
sinon (déploiement administration séparé).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urljoin
from urllib.request import urlopen

import jwt as pyjwt
from jwt import PyJWKClient  # type: ignore[attr-defined]  # non exposé par types-PyJWT

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.domain.bearer import BearerTokenVerifier
from puridentityserver.interfaces.domain.tokens import TokenManager

_HTTP_TIMEOUT = 10


class LocalBearerVerifier:
    """Valide un jeton signé par l'issuer courant (clés locales, sans réseau)."""

    def __init__(self, token_manager: TokenManager, issuer: str) -> None:
        """Injection du gestionnaire de jetons et de l'issuer attendu."""
        self._token_manager = token_manager
        self._issuer = issuer

    async def verify(self, token: str) -> dict[str, object] | None:
        """Valide le jeton contre les clés locales (signature, ``iss``, ``exp``)."""
        return await self._token_manager.validate_access_token(token=token, issuer=self._issuer)


class JwksBearerVerifier:
    """Valide un jeton d'un issuer tiers via le JWKS publié par cet issuer."""

    def __init__(self, *, issuer: str, jwks_url: str = "", audience: str = "") -> None:
        """Mémorise l'issuer de confiance, l'URL JWKS (facultative) et l'audience."""
        self._issuer = issuer
        self._jwks_url = jwks_url
        self._audience = audience
        self._client: PyJWKClient | None = None
        self._client_lock = asyncio.Lock()

    async def verify(self, token: str) -> dict[str, object] | None:
        """Valide le jeton distant (signature JWKS, ``iss``, ``exp``, ``aud``)."""
        try:
            client = await self._client_instance()
            signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, token)
            claims = pyjwt.decode(
                token,
                signing_key,
                issuer=self._issuer,
                audience=self._audience or None,
                options={"verify_aud": bool(self._audience)},
            )
        except (pyjwt.PyJWTError, OSError, ValueError):
            return None
        return claims

    async def _client_instance(self) -> PyJWKClient:
        """Construit (une seule fois) le client JWKS, en découvrant l'URL au besoin."""
        async with self._client_lock:
            if self._client is None:
                url = self._jwks_url or await self._discover_jwks_url()
                self._client = PyJWKClient(url, timeout=_HTTP_TIMEOUT)
            return self._client

    async def _discover_jwks_url(self) -> str:
        """Lit ``jwks_uri`` dans le document de discovery de l'issuer."""
        metadata_url = urljoin(self._issuer.rstrip("/") + "/", ".well-known/openid-configuration")
        metadata = await asyncio.to_thread(_fetch_json, metadata_url)
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise ValueError(f"jwks_uri absent du discovery de {self._issuer}")
        return jwks_uri


def _fetch_json(url: str) -> dict[str, object]:
    """Récupère un document JSON (bloquant, exécuté hors de la boucle asyncio)."""
    with urlopen(url, timeout=_HTTP_TIMEOUT) as response:  # ruff: ignore[suspicious-url-open-usage] (URL de configuration)
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def build_bearer_verifier(settings: Settings, token_manager: TokenManager) -> BearerTokenVerifier:
    """Choisit la vérification locale (même issuer) ou distante (issuer tiers)."""
    issuer = settings.management_issuer
    if settings.management_jwt_jwks_url or issuer != settings.issuer:
        return JwksBearerVerifier(
            issuer=issuer,
            jwks_url=settings.management_jwt_jwks_url,
            audience=settings.management_jwt_audience,
        )
    return LocalBearerVerifier(token_manager, issuer)
