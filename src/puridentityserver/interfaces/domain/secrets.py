"""Port de chiffrement des secrets clients au repos (aucune valeur en clair).

Les clients dont la méthode d'authentification exige la connaissance du
secret en clair au moment de la vérification (``client_secret_jwt``,
grant jwt-bearer signé HMAC — RFC 7523) font l'objet d'un stockage
chiffré : le serveur doit posséder l'équivalent de la clé HMAC pour
vérifier l'assertion, mais ne la conserve jamais en clair dans le
registre clients.
"""

from __future__ import annotations

from typing import Protocol


class SecretCipher(Protocol):
    """Chiffre et déchiffre un secret client avec la clé de scellement du serveur.

    La rotation de clé est supportée : le déchiffrement résout la clé
    d'origine (identifiant préfixé dans le jeton) tant que celle-ci est
    encore portée par le trousseau, permettant de conserver les clés
    sortantes le temps du drain avant leur retrait.
    """

    async def encrypt(self, value: str) -> str:
        """Chiffre ``value`` et retourne le jeton opaque à persister."""
        ...

    async def decrypt(self, token: str) -> str:
        """Déchiffre ``token`` et retourne la valeur en clair."""
        ...

    async def is_current(self, token: str) -> bool:
        """Indique si ``token`` est chiffré avec la clé la plus récente."""
        ...

    async def reencrypt(self, token: str) -> str:
        """Rechiffre ``token`` sous la clé la plus récente (identité s'il y est déjà)."""
        ...
