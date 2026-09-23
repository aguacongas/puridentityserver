"""Cas d'utilisation : Session Management OIDC 1.0 — iframe de supervision navigateur.

Calcule et vérifie les valeurs ``session_state`` (OIDC Session Management
1.0 §2 et §3.2) : empreinte salée reliant le client, l'origine de la page
qui supervise (RFC 6454 §4) et l'état de session navigateur — ici le
``sid`` de la session cookie (utilisé comme « OP User Agent state »).

Le calcul reste côté serveur (endpoint de session status) : rien d'utile
pour la ré-identification n'est exposé à JavaScript (le cookie de session
reste HttpOnly, cf. §5.1 et §6).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlparse

_SALT_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class SessionManagementUseCase:
    """Génère et vérifie les valeurs ``session_state`` côté serveur."""

    def create_session_state(
        self,
        *,
        client_id: str,
        origin: str,
        session_id: str,
    ) -> str:
        """Génère une valeur ``session_state`` fraîche (sel aléatoire).

        Format ``<base64url(SHA256(client_id " " origin " " sid " " salt))>.<salt>``
        : la valeur ne contient jamais d'espace (l'échange RP↔OP se fait sur
        un message concaténé ``client_id + " " + session_state``) et est
        opaque au client (§2).
        """
        salt = secrets.token_urlsafe(32)
        return self._encode(client_id, origin, session_id, salt)

    def verify_session_state(
        self,
        *,
        client_id: str,
        origin: str,
        session_id: str,
        session_state: str,
    ) -> bool:
        """Compare le ``session_state`` soumis à la valeur recalculée.

        Le sel est extrait de la valeur elle-même ; la comparaison s'effectue
        en temps constant. Une valeur malformée (espace, sans sel, sel hors
        alphabet base64url) est rejetée sans calcul.
        """
        if not session_state or " " in session_state or "." not in session_state:
            return False
        value, salt = session_state.rsplit(".", 1)
        if not value or not salt or any(char not in _SALT_ALPHABET for char in salt):
            return False
        expected = self._encode(client_id, origin, session_id, salt)
        return secrets.compare_digest(expected, session_state)

    def _encode(self, client_id: str, origin: str, session_id: str, salt: str) -> str:
        """Empreinte ``base64url(SHA256(...))`` suivi du sel, séparés par un point."""
        payload = f"{client_id} {origin} {session_id} {salt}".encode()
        digest = hashlib.sha256(payload).digest()
        encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return f"{encoded}.{salt}"


def origin_of_url(url: str) -> str:
    """Origin (RFC 6454 §4) d'une URL : schéma + hôte + port non par défaut."""
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme
    host = parsed.hostname or ""
    if port is not None and (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        port = None
    suffix = f":{port}" if port is not None else ""
    return f"{scheme}://{host}{suffix}"
