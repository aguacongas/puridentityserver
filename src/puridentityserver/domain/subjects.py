"""Dérivation des subject identifiers (OIDC Core 1.0 §8.1, ESID 1.0 §4).

L'OP émet trois types de ``sub`` selon le ``subject_type`` du client
(``subject_types_supported`` du discovery) :

- ``public`` : le sujet local tel quel, corrélable entre tous les clients ;
- ``pairwise`` : dérivation HMAC-SHA256 sous le seed serveur
  ``subject_pairwise_seed``, indexée par le secteur du client — même
  client et même utilisateur donnent toujours la même ``sub``, deux
  clients de secteurs différents des ``sub`` différentes (Core §8.1) ;
- ``ephemeral`` : dérivation HMAC-SHA256 indexée par la matière de
  session d'authentification (``sid`` du navigateur, identifiant de
  flow) — constante pendant la session, jamais réutilisée entre deux
  authentifications (ESID 1.0 §4 : aléa cryptographique dans l'entrée
  du hash, probabilité de devinette bornée à 2⁻¹²⁸, clé secrète pour que
  la paire ``(sub, sid)`` ne révèle rien de l'identité).

La dérivation n'est jamais inversée : ``/userinfo`` résout le profil
utilisateur sur le sujet **réel** (portée de l'access token) et n'expose
que la ``sub`` dérivée. Les replis sur la ``sub`` réelle ne couvrent que
les états inatteignables d'un client enregistré validé à l'entrée
(client public, seed ou secteur absent) : jamais de dégradation
silencieuse.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from puridentityserver.domain.authorization import Client, SubjectType

# Préfixes de séparation de domaine : la même entrée n'engendre jamais la
# même valeur entre un secteur pairwise et une matière ephemeral.
_DOMAIN_PAIRWISE = "pairwise"
_DOMAIN_EPHEMERAL = "ephemeral"


def _derive_subject(seed: str, domain: str, *parts: str) -> str:
    r"""HMAC-SHA256 base64url sans padding de ``parts`` sous le ``seed``.

    43 caractères = 256 bits de sortie, supérieurs au plancher de 160 bits
    de l'ESID 1.0 §4 ; l'entrée est séparée par ``\x00`` pour éviter toute
    collision d'assemblage.
    """
    message = "\x00".join((domain, *parts)).encode("utf-8")
    digest = hmac.new(seed.encode("utf-8"), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pairwise_subject(seed: str, sector: str, subject: str) -> str:
    """``sub`` pairwise : HMAC du ``(secteur, sujet)`` sous le seed (Core §8.1)."""
    return _derive_subject(seed, _DOMAIN_PAIRWISE, sector, subject)


def ephemeral_subject(seed: str, subject: str, material: str) -> str:
    """``sub`` ephemeral : HMAC du ``(sujet, matière de session)`` (ESID 1.0 §4)."""
    return _derive_subject(seed, _DOMAIN_EPHEMERAL, subject, material)


def display_subject(client: Client, subject: str, *, material: str = "", seed: str = "") -> str:
    """``sub`` à exposer pour ``subject`` sur les emissions du ``client``.

    ``material`` est la matière de session d'authentification du flow en
    cours (``sid``, identifiant de flow) ; ``seed`` est le seed de
    dérivation du serveur. La ``sub`` réelle est retournée pour un client
    ``public`` ou dès que la dérivation est impossible (seed absent).
    """
    if not subject:
        return subject
    if client.subject_type is SubjectType.PAIRWISE:
        sector = client.subject_sector()
        if not sector or not seed:
            return subject
        return pairwise_subject(seed, sector, subject)
    if client.subject_type is SubjectType.EPHEMERAL:
        if not seed:
            return subject
        return ephemeral_subject(seed, subject, material)
    return subject


def access_token_subject_claims(
    client: Client, subject: str, *, material: str = ""
) -> dict[str, str]:
    """Claims privés d'access token permettant à ``/userinfo`` de dériver.

    ``client_id`` identifie le client du jeton (portée d'émission de la
    ``sub``) ; ``subject_material`` porte la matière de session
    ephemeral. Rien n'est ajouté pour un client ``public`` : le payload
    des clients existants reste strictement identique.
    """
    if client.subject_type is SubjectType.PUBLIC or not subject:
        return {}
    claims = {"client_id": client.client_id}
    if client.subject_type is SubjectType.EPHEMERAL and material:
        claims["subject_material"] = material
    return claims
