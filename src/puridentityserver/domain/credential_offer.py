"""Entité de l'offre de credential OpenID4VCI 1.0 §4.1.1.

L'offre de credential est le message que l'émetteur transmet au wallet
(hors bande, par QR code ou lien) pour initier une émission. Elle peut
être transmise par valeur (``credential_offer``) ou par référence
(``credential_offer_uri``), la référence étant déréférencée par un
``GET`` non authentifié (OID4VCI 1.0 §4.1.2).

L'entité ne porte aucune cryptographie : le code pré-autorisé et
l'empreinte du code de transaction sont produits par le cas d'usage et
persistés avec l'offre.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from puridentityserver.domain.authorization import PRE_AUTHORIZED_CODE_GRANT_TYPE

#: Durée de vie par défaut d'une offre et de son code pré-autorisé, en secondes.
CREDENTIAL_OFFER_TTL = 300

#: Longueur du code de transaction (``tx_code``) généré par l'émetteur.
TX_CODE_LENGTH = 6

#: Description affichée par le wallet à côté du champ de code de transaction.
TX_CODE_DESCRIPTION = "Code transmis par l'emetteur sur un canal separe"


@dataclass(frozen=True, slots=True)
class CredentialOffer:
    """Offre de credential persistée, adressable par ``offer_id``.

    ``pre_authorized_code`` est le secret que le wallet échange au token
    endpoint : il n'est jamais haché ici car la référence de l'offre doit
    pouvoir le restituer à son destinataire. ``tx_code_required`` indique
    qu'un code de transaction est exigé en plus (OID4VCI 1.0 §4.1.1) ;
    l'empreinte du code reste dans l'entité ``AuthorizationCode``.
    """

    offer_id: str
    credential_configuration_ids: tuple[str, ...]
    subject: str
    pre_authorized_code: str
    client_id: str = ""
    tx_code_required: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self, now: datetime) -> bool:
        """Indique si l'offre est expirée à l'instant ``now``."""
        return now > self.expires_at


def credential_offer_payload(offer: CredentialOffer, issuer: str) -> dict[str, object]:
    """Construit l'objet ``credential_offer`` JSON (OID4VCI 1.0 §4.1.1).

    ``accepted_credential_configuration_ids`` n'est pas émis : l'offre
    désigne la configuration par identifiant, ce que le wallet consomme
    directement.
    """
    normalized = issuer.rstrip("/")
    grant: dict[str, object] = {
        "pre-authorized_code": offer.pre_authorized_code,
        "authorization_server": normalized,
    }
    if offer.tx_code_required:
        grant["tx_code"] = {
            "input_mode": "numeric",
            "length": TX_CODE_LENGTH,
            "description": TX_CODE_DESCRIPTION,
        }
    return {
        "credential_issuer": normalized,
        "credential_configuration_ids": list(offer.credential_configuration_ids),
        "grants": {PRE_AUTHORIZED_CODE_GRANT_TYPE: grant},
    }
