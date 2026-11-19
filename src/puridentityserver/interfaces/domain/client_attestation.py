"""Port de vérification des en-têtes d'attestation client (§6, §9).

Le token endpoint et le PAR endpoint s'appuient sur ce port pour
l'authentification ``attest_jwt_client_auth`` : deux en-têtes HTTP
portent l'attestation — ``OAuth-Client-Attestation`` (JWT signé par un
attester de confiance, §5.1) et ``OAuth-Client-Attestation-PoP`` (preuve
de possession signée par la clé ``cnf`` de l'attestation, §5.2)
(draft-ietf-oauth-attestation-based-client-auth).
"""

from __future__ import annotations

from typing import Protocol

#: Type MIME JWT exigé dans l'en-tête ``OAuth-Client-Attestation`` (§5.1).
CLIENT_ATTESTATION_TYPE = "oauth-client-attestation+jwt"

#: Type MIME JWT exigé dans l'en-tête ``OAuth-Client-Attestation-PoP`` (§5.2).
CLIENT_ATTESTATION_POP_TYPE = "oauth-client-attestation-pop+jwt"


class ClientAttestationVerifier(Protocol):
    """Vérifie la paire d'en-têtes d'attestation client (§6.2, §9)."""

    def subject_of(self, attestation: str) -> str:
        """Retourne le ``sub`` **non vérifié** de l'attestation (``""`` si illisible).

        Sert uniquement à localiser le client quand le corps de la requête
        omet ``client_id`` (draft-ietf-oauth-attestation-based-client-auth
        §6.3 : le paramètre y est optionnel) — aucune décision de sécurité
        sur cette valeur : ``verify`` exige ensuite que la signature soit
        valide et que ``sub`` soit égal au ``client_id`` retenu (§9-13).
        """
        ...

    def instance_key_of(self, attestation: str) -> str:
        """Retourne l'empreinte RFC 7638 de ``cnf.jwk`` (``""`` si illisible).

        Cette empreinte identifie l'instance client (OAuth2-ATCA §10.3) :
        un refresh token émis sous une attestation doit être renouvelé avec
        la même ``cnf.jwk``, sinon le token endpoint refuse. La valeur n'est
        lue qu'après ``verify``, qui a déjà contrôlé la signature du jeton et
        l'absence de paramètre privé dans ``cnf.jwk`` (§9-6).
        """
        ...

    async def verify(self, *, attestation: str, pop: str, client_id: str) -> str | None:
        """Retourne ``None`` si la paire est valide, sinon le détail du refus.

        ``client_id`` est le client identifié sur la requête : il doit
        valoir le ``sub`` de l'attestation et l'``iss`` du PoP (§9-13).
        Le ``jti`` du PoP est mémorisé en anti-replay (§9-12) — un même
        PoP rejoué est refusé.
        """
        ...
