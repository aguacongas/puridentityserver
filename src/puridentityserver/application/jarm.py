"""Cas d'utilisation : enveloppe JARM des réponses d'autorisation (JARM Final 1.0).

Relie la politique de ``response_mode=jwt`` au registre des clients :
l'algorithme ``authorization_signed_response_alg`` du client décide si sa
demande peut être signée (refus ``unsupported_response_mode`` sinon), le
signeur d'enveloppes fournit le JWS lui-même.
"""

from __future__ import annotations

from collections.abc import Mapping

from puridentityserver.domain.authorization import Client, ResponseMode
from puridentityserver.domain.jwks import JARM_SIGNING_ALGORITHMS
from puridentityserver.interfaces.domain.jarm import JarmEnvelopeSigner
from puridentityserver.interfaces.repositories.readers import ClientReader


def jarm_signing_alg(client: Client, requested_mode: str) -> str:
    """Algorithme JARM du client si ``response_mode=jwt`` lui est signable, sinon ``""``.

    ``response_mode=jwt`` n'est retenu que pour un client déclarant un
    ``authorization_signed_response_alg`` publié par l'OP parmi
    ``authorization_signing_alg_values_supported`` (JARM Final 1.0 §4) ;
    tout autre mode ou algorithme inconnu rend ``""`` — la demande est
    alors refusée ou retombe sur ``query`` / ``fragment``.
    """
    if requested_mode != ResponseMode.JWT.value:
        return ""
    if client.authorization_signed_response_alg not in JARM_SIGNING_ALGORITHMS:
        return ""
    return client.authorization_signed_response_alg


class JarmSigner:
    """Signe les réponses d'autorisation en ``response_mode=jwt`` (succès et erreurs)."""

    def __init__(self, envelope: JarmEnvelopeSigner, clients: ClientReader) -> None:
        """Injection du signeur d'enveloppes et du registre des clients."""
        self._envelope = envelope
        self._clients = clients

    async def sign(self, client: Client, params: Mapping[str, str]) -> str:
        """Enveloppe les paramètres de réponse pour le client résolu.

        Raises:
            ValueError: ``authorization_signed_response_alg`` absent ou non
                signable — l'appelant oppose d'abord :func:`jarm_signing_alg`.
        """
        algorithm = jarm_signing_alg(client, ResponseMode.JWT.value)
        if not algorithm:
            raise ValueError(
                f"Client {client.client_id!r} sans authorization_signed_response_alg signable"
            )
        return await self._envelope.sign_envelope(
            audience=client.client_id,
            algorithm=algorithm,
            params=params,
        )

    async def sign_by_client_id(self, client_id: str, params: Mapping[str, str]) -> str | None:
        """Enveloppe pour un client résolu par identifiant ; ``None`` si non signable.

        Un ``client_id`` inconnu ou sans algorithme JARM déclaré produit
        ``None`` : l'appelant retombe sur le transport ``query`` / ``fragment``.
        """
        client = await self._clients.find_by_id(client_id)
        if client is None or not jarm_signing_alg(client, ResponseMode.JWT.value):
            return None
        return await self.sign(client, params)
