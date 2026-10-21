"""Migration OpenID 2.0 vers OpenID Connect (spec de migration, version finale).

La spec « OpenID 2.0 to OpenID Connect Migration 1.0 » permet à un RP
OpenID 2.0 de migrer l'identifiant d'un utilisateur vers un `sub` OpenID
Connect : le RP demande le scope ``openid2`` (avec le paramètre
``openid2_realm`` le cas échéant), l'OP renvoie alors l'identifiant OpenID 2.0
de l'utilisateur dans le claim ``openid2_id`` de l'ID Token.

Le domaine ne contient que des entités pures, sans dépendance vers FastAPI,
SQLAlchemy ou PyJWT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

#: Scope OpenID Connect demandant l'identifiant OpenID 2.0 (spec §2).
OPENID20_SCOPE = "openid2"

#: Paramètre de requête portant le `openid.realm` de l'OP OpenID 2.0 (spec §2).
OPENID20_REALM_PARAMETER = "openid2_realm"

#: Claim de l'ID Token portant l'identifiant OpenID 2.0 (spec §4).
OPENID20_ID_CLAIM = "openid2_id"


@dataclass(frozen=True, slots=True)
class OpenID20Identifier:
    """Identifiant OpenID 2.0 associé à un compte OpenID Connect.

    ``subject`` est la `sub` OpenID Connect (« OpenID Connect Identifier »),
    ``identifier`` l'identifiant OpenID 2.0 vérifié (« verified claimed
    identifier ») et ``realm`` le `openid.realm` de l'OP OpenID 2.0 (vide
    quand l'OP n'en impose pas).
    """

    subject: str
    identifier: str
    realm: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
