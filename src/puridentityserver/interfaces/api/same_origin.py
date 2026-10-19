"""Garde same-origin des formulaires HTML (protection CSRF, issue #184).

Un site tiers peut soumettre un formulaire ``application/x-www-form-urlencoded``
vers l'OP sans preflight CORS (requête simple, RFC 7231 §9.1). Les
endpoints ``/login`` et ``/signup`` n'exigent aucune session préalable :
le ``SameSite`` du cookie de session ne protège donc pas contre le login
ou signup CSRF — le POST part sans cookie, le ``Set-Cookie`` de la
réponse est accepté par le navigateur de la victime. ``/consent`` et
``/device``, qui exigent la session, sont couverts par ``SameSite`` mais
bénéficient de la même défense explicite.

La garde examine deux en-têtes de navigation, **seulement quand ils sont
présents** (les clients machine — ``curl``, ``TestClient``, la suite de
conformité — n'en envoient aucun et passent) :

1. ``Sec-Fetch-Site`` : allow-liste ``same-origin`` / ``none`` ; toute
   autre valeur (``cross-site``, ``same-site``, inconnue) est refusée —
   fail-closed ;
2. à défaut ``Origin`` : son origine normalisée (port par défaut écarté)
   doit égaler l'origin publique de la requête (en-têtes ``X-Forwarded-*``
   suivis quand ``trust_proxy_headers`` est actif).

Tout navigateur moderne envoie au moins ``Origin`` sur un POST : la
couverture est complète là où l'attaque est possible. Repli théorique
IE11 (EOL, ni ``Origin`` ni ``Sec-Fetch``) documenté dans l'issue.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from puridentityserver.interfaces.api.forwarded import public_url

# Chemins HTML dont le POST est vérifié (routes exactes des formulaires).
_PROTECTED_PATHS = frozenset({"/login", "/signup", "/consent", "/device"})

# Seules ces valeurs de ``Sec-Fetch-Site`` attestent d'un initiateur fiable.
_ACCEPTED_SITE_VALUES = frozenset({"same-origin", "none"})

# Ports par défaut écartés de la comparaison d'origines (RFC 3986 §6.2.3).
_DEFAULT_PORTS = {"http": "80", "https": "443"}


class SameOriginFormGuardMiddleware:
    """Refuse (403) les POST cross-site vers les formulaires HTML de l'OP.

    À monter via ``app.add_middleware(SameOriginFormGuardMiddleware,
    trust_proxy_headers=…)`` — hors des POST des quatre chemins protégés,
    la requête est relaie telle quelle.
    """

    def __init__(self, app: ASGIApp, *, trust_proxy_headers: bool = False) -> None:
        """Lie l'application ASGI en aval et le drapeau de proxy de confiance.

        Args:
            app: application ASGI appelée pour toute requête acceptée.
            trust_proxy_headers: suit ``X-Forwarded-*`` pour reconstruire
                l'origin publique (``Settings.trust_proxy_headers``).
        """
        self.app = app
        self.trust_proxy_headers = trust_proxy_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Vérifie la requête puis relaie ou répond ``403``.

        Args:
            scope: scope ASGI de la requête.
            receive: canal d'entrée ASGI.
            send: canal de sortie ASGI.
        """
        if (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and scope.get("path") in _PROTECTED_PATHS
        ):
            reason = _cross_site_reason(
                Request(scope), trust_proxy_headers=self.trust_proxy_headers
            )
            if reason is not None:
                await PlainTextResponse(
                    f"Requête refusée (protection CSRF) : {reason}",
                    status_code=403,
                )(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _cross_site_reason(request: Request, *, trust_proxy_headers: bool) -> str | None:
    """Motif de refus si le POST vient d'un autre site, sinon ``None``.

    Args:
        request: requête HTTP examinée.
        trust_proxy_headers: suit ``X-Forwarded-*`` pour l'origin publique.

    Returns:
        Motif lisible du refus, ou ``None`` quand l'origine est fiable.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        value = site.strip().lower()
        if value not in _ACCEPTED_SITE_VALUES:
            return f"sec-fetch-site={value}"
        return None
    origin = request.headers.get("origin")
    if origin is None:
        return None
    expected = _normalized_origin(public_url(request, trust_proxy_headers=trust_proxy_headers))
    if _normalized_origin(origin) != expected:
        return f"origin={origin}"
    return None


def _normalized_origin(url: str) -> str:
    """Normalise une URL (ou un ``Origin``) à son origine comparable.

    Schéma et autorité en minuscules, port par défaut écarté, tout le reste
    (path, query) ignoré. Une valeur non-URL (``null``, forge) est
    simplement basculée en minuscules : la comparaison échoue donc — c'est
    voulu, une origine illisible n'est pas digne de confiance.

    Args:
        url: URL ou valeur d'en-tête ``Origin`` à normaliser.

    Returns:
        Origine sous forme ``schéma://autorité``.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    if not scheme or not netloc:
        return url.strip().lower()
    default_port = _DEFAULT_PORTS.get(scheme)
    if default_port and netloc.endswith(f":{default_port}"):
        netloc = netloc[: -len(default_port) - 1]
    return f"{scheme}://{netloc}"
