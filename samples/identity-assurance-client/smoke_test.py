r"""Test manuel : identité assurance (OpenID Identity Assurance 1.0).

Smoke test du sample ``identity-assurance-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8125, un
client public, un profil utilisateur porteur de ``verified_claims``) puis joue
le parcours de la spec « OpenID Identity Assurance Schema Definition 1.0 ».

Le scénario vérifie :

1. le discovery publie la metadata eKYC (``trust_frameworks_supported``,
   ``claims_in_verified_claims_supported``, ``evidence_supported``,
   ``documents_supported``, ``documents_check_methods_supported``) ;
2. une demande ``claims`` portant ``verified_claims`` dans le member
   ``id_token`` produit un ``id_token`` **conforme** (membre racine
   ``verified_claims``, ``verification.trust_framework`` renseigné) ;
3. la même demande dans le member ``userinfo`` produit un ``/userinfo``
   porteur du membre, et **rien** ne fuit dans l'autre localisation ;
4. sans demande, le membre est absent de l'``id_token`` comme du ``/userinfo`` ;
5. un claim demandé avec une ``value`` non satisfaite est **omis** (le membre
   ``verified_claims`` reste présent, avec un élément ``claims`` vide) ;
6. un claim demandé mais inconnu de l'OP est omis, sans erreur.

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/identity-assurance-client/smoke_test.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8125
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

CLIENT_ID = "sample-identity-assurance-client"
REDIRECT_URI = f"{SERVER_URL}/callback"

_HTTP_TIMEOUT = 10
_DEADLINE = 90

#: Client public (PKCE) de la démonstration.
_CLIENT = {
    "client_id": CLIENT_ID,
    "redirect_uris": [REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "public",
}

#: Profil `verified_claims` conforme au schéma de la spec.
_VERIFIED_CLAIMS = {
    "verification": {
        "trust_framework": "de_aml",
        "assurance_level": "substantial",
        "evidence": [
            {
                "type": "document",
                "check_details": [{"check_method": "pvp"}],
                "document_details": {"type": "de_erp_replacement_idcard"},
            }
        ],
    },
    "claims": {"given_name": "Alice", "family_name": "Martin"},
}

#: Profils du user store : `alice` porte des claims vérifiés, `bob` non.
_USERS_SEED = {
    "alice": {
        "name": "Alice Martin",
        "given_name": "Alice",
        "family_name": "Martin",
        "email": "alice.martin@example.com",
        "verified_claims": _VERIFIED_CLAIMS,
    },
    "bob": {
        "name": "Bob Durand",
        "given_name": "Bob",
        "email": "bob.durand@example.com",
    },
}

#: Comptes de connexion (le pont identité ⊕ user store reprend la clé).
_USERS = {
    "alice": {"email": "alice@example.com", "password": "password"},
    "bob": {"email": "bob@example.com", "password": "password"},
}


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 d'un verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _login(http: httpx.Client, email: str = "alice@example.com") -> None:
    """Authentifie l'utilisateur de test (cookie de session)."""
    response = http.post(
        f"{SERVER_URL}/login",
        data={"username": email, "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text


def _claims_parameter(location: str, member: dict[str, object]) -> str:
    """Paramètre `claims` JSON demandant le membre `verified_claims`."""
    return json.dumps({location: {"verified_claims": member}})


def _id_token_and_userinfo(
    http: httpx.Client, claims_parameter: str | None
) -> tuple[dict[str, object], dict[str, object]]:
    """Flux code + userinfo : renvoie les claims de l'id_token et du userinfo."""
    verifier = "identity-assurance-verifier-0123456789"
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-ekyc",
        "nonce": "n-ekyc-0123456789",
        "code_challenge": _s256_challenge(verifier),
        "code_challenge_method": "S256",
    }
    if claims_parameter is not None:
        params["claims"] = claims_parameter
    response = http.get(f"{SERVER_URL}/authorize", params=params, follow_redirects=False)
    assert response.status_code == 302, response.text
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token = http.post(
        f"{SERVER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    id_token = str(token.json()["id_token"])
    id_token_claims = pyjwt.decode(id_token, options={"verify_signature": False})
    info = http.get(
        f"{SERVER_URL}/userinfo",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
    )
    assert info.status_code == 200, info.text
    return dict(id_token_claims), dict(info.json())


def _run_scenario() -> None:
    """Joue le scénario de l'identité assurance."""
    with httpx.Client(follow_redirects=False, timeout=_HTTP_TIMEOUT) as http:
        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert "de_aml" in metadata["trust_frameworks_supported"], metadata
        assert "given_name" in metadata["claims_in_verified_claims_supported"], metadata
        assert metadata["evidence_supported"] == ["document"], metadata
        assert metadata["documents_supported"] == ["de_erp_replacement_idcard"], metadata
        assert metadata["documents_check_methods_supported"] == ["pvp"], metadata
        print("  [1/6] metadata eKYC publiee dans le discovery")

        _login(http)
        id_token_claims, userinfo = _id_token_and_userinfo(
            http, _claims_parameter("id_token", {"claims": {"given_name": None}})
        )
        rendered = id_token_claims["verified_claims"]
        assert rendered["verification"]["trust_framework"] == "de_aml", rendered
        assert rendered["claims"] == {"given_name": "Alice"}, rendered
        assert "verified_claims" not in userinfo, userinfo
        print("  [2/6] id_token : verified_claims rendu (trust_framework + claims)")

        _login(http)
        id_token_claims, userinfo = _id_token_and_userinfo(
            http, _claims_parameter("userinfo", {"claims": {"given_name": None}})
        )
        assert "verified_claims" not in id_token_claims, id_token_claims
        assert userinfo["verified_claims"]["claims"] == {"given_name": "Alice"}, userinfo
        print("  [3/6] userinfo : verified_claims rendu dans la seule localisation")

        _login(http)
        id_token_claims, userinfo = _id_token_and_userinfo(http, None)
        assert "verified_claims" not in id_token_claims, id_token_claims
        assert "verified_claims" not in userinfo, userinfo
        print("  [4/6] sans demande : aucun verified_claims rendu")

        _login(http)
        id_token_claims, _ = _id_token_and_userinfo(
            http, _claims_parameter("id_token", {"claims": {"given_name": {"value": "Bob"}}})
        )
        rendered = id_token_claims["verified_claims"]
        assert rendered["claims"] == {}, rendered
        print("  [5/6] valeur non satisfaite : le claim est omis (IA-5.7.4)")

        _login(http)
        id_token_claims, _ = _id_token_and_userinfo(
            http, _claims_parameter("id_token", {"claims": {"inconnu": None}})
        )
        rendered = id_token_claims["verified_claims"]
        assert rendered["claims"] == {}, rendered
        print("  [6/6] claim inconnu : omis sans erreur")


def main() -> int:
    """Lance le serveur de test puis joue le scénario."""
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=(_CLIENT,),
            users=_USERS,
            users_seed=_USERS_SEED,
        ),
    ):
        _run_scenario()
    print("\n=== SCENARIO OK ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
