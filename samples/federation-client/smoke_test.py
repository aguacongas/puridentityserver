r"""Test manuel : fédération (OpenID Federation 1.1) côté supérieur.

Smoke test du sample ``federation-client``.

Lance un serveur PurIdentityServer en sous-processus avec une configuration
**spécifique à ce test** (générée par ``smoke_common.py`` : port 8126,
``federation_enabled``, un client seedé fédéré — ``client_id`` = Entity
Identifier https + ``jwks`` inline — et un client classique) puis joue le
parcours de l'OP en tant que **supérieur** de ses subordonnés (spec « OpenID
Federation 1.1 », §5.1.1 et §8).

Le scénario vérifie :

1. l'entity statement de l'OP (``/.well-known/openid-federation``) : ``typ``
   ``entity-statement+jwt``, ``iss`` = ``sub`` = l'issuer, ``jwks`` de
   signature, ``metadata.openid_provider`` et ``metadata.federation_entity``
   (fetch/list/resolve) — signature vérifiable avec les clés publiées ;
2. le discovery publie ``federation_registration_endpoint`` et
   ``client_registration_types_supported`` (§5.1.3) ;
3. ``GET /federation/list`` rend les Entity Identifier des clients fédérés
   (le client classique est exclu, §8.2.2) ;
4. ``GET /federation/fetch?sub=`` rend le subordinate statement signé du
   subordonné (§8.1) : signature valide avec les clés de l'OP, ``jwks``
   attestés et metadata ``openid_relying_party`` résolues ;
5. contrats d'erreur du fetch (§8.9) : ``sub`` manquant ou valant l'identité
   de l'OP → 400 ``invalid_request`` ; subordonné inconnu → 404 ``not_found`` ;
6. ``GET /federation/resolve`` sans paramètre obligatoire → 400
   ``invalid_request`` (§8.3) ;
7. resolve vers une ancre injoignable → 404 ``not_found`` : aucune chaîne ne
   peut être construite (§10.1) ;
8. ``GET /authorize`` avec un request object refusable (algorithme ``HS256``
   non supporté) dont la ``redirect_uri`` est enregistrée → redirection 302
   ``invalid_request_object`` vers la callback du RP (issue #211 : le RP
   fédéré ne place sa ``redirect_uri`` que dans le request object, §12.1.1.1) ;
9. même demande avec une ``redirect_uri`` hors registre → page 400, aucune
   redirection (le registre reste l'autorité sur la cible).

Le sous-processus est terminé dans tous les cas (``finally``) et un
garde-fou borne la durée totale.

Usage (depuis n'importe où dans le dépôt) :

    uv run python samples/federation-client/smoke_test.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from smoke_common import HOST, run_server, watchdog

SERVER_PORT = 8126
SERVER_URL = f"http://{HOST}:{SERVER_PORT}"

ENTITY_IDENTIFIER = SERVER_URL
_FEDERATED_CLIENT_ID = "https://rp.example"
_ANCHOR = "https://ta.example"

_HTTP_TIMEOUT = 10
_DEADLINE = 120

#: Client fédéré : Entity Identifier https + clés inline (subordonné).
_FEDERATED_CLIENT_BASE = {
    "client_id": _FEDERATED_CLIENT_ID,
    "redirect_uris": [f"{_FEDERATED_CLIENT_ID}/cb"],
}

#: Client classique : sans Entity Identifier ni clés, donc pas un subordonné.
_PLAIN_CLIENT = {"client_id": "web-app"}


def _federated_client_jwk() -> dict[str, str]:
    """Génère la paire EC P-256 du RP et retourne sa clé publique JWK."""
    key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    public_jwk["kid"] = pyjwt.PyJWK.from_dict(public_jwk).key_id or "sample-rp"
    return public_jwk


def _decode(token: str, key_jwks: dict[str, object]) -> dict[str, object]:
    """Décode un JWT en vérifiant sa signature avec la première clé de ``key_jwks``."""
    jwk = key_jwks["keys"][0]
    assert isinstance(jwk, dict)
    key = pyjwt.PyJWK.from_dict(jwk).key
    return dict(pyjwt.decode(token, key=key, algorithms=["ES256", "RS256"]))


def _unverified_jwks(token: str) -> dict[str, object]:
    """Retourne les ``jwks`` publiés dans les claims d'un JWT non vérifié."""
    claims = pyjwt.decode(token, options={"verify_signature": False})
    jwks = claims["jwks"]
    assert isinstance(jwks, dict)
    return dict(jwks)


def _invalid_request_object(redirect_uri: str) -> str:
    """Construit un request object refusable (algorithme ``HS256`` non supporté).

    L'OP n'accepte que ``RS256``/``none`` (OIDC Core 1.0 §10.1) : la
    ``redirect_uri`` portée par le jeton sert de candidat à la redirection
    d'erreur, validée contre les ``redirect_uris`` du registre (issue #211).
    """
    claims = {
        "iss": _FEDERATED_CLIENT_ID,
        "client_id": _FEDERATED_CLIENT_ID,
        "aud": SERVER_URL,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": redirect_uri,
        "exp": int(time.time()) + 300,
        "jti": "sample-211",
    }
    return str(
        pyjwt.encode(claims, "sample-secret-0123456789abcdef0123456789ab", algorithm="HS256")
    )


def _run_scenario(rp_jwk: dict[str, str]) -> None:
    """Joue le parcours de l'OP en supérieur de la fédération."""
    with httpx.Client(timeout=_HTTP_TIMEOUT) as http:
        response = http.get(f"{SERVER_URL}/.well-known/openid-federation")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/entity-statement+jwt")
        header = pyjwt.get_unverified_header(response.text)
        assert header["typ"] == "entity-statement+jwt", header
        claims = _decode(response.text, _unverified_jwks(response.text))
        assert claims["iss"] == ENTITY_IDENTIFIER, claims
        assert claims["sub"] == ENTITY_IDENTIFIER, claims
        assert claims["metadata"]["openid_provider"]["issuer"] == ENTITY_IDENTIFIER, claims
        federation = claims["metadata"]["federation_entity"]
        assert federation["federation_fetch_endpoint"] == f"{SERVER_URL}/federation/fetch"
        assert federation["federation_list_endpoint"] == f"{SERVER_URL}/federation/list"
        assert federation["federation_resolve_endpoint"] == f"{SERVER_URL}/federation/resolve"
        print("  [1/9] entity statement de l'OP verifie (§5.1.1, §9)")

        metadata = http.get(f"{SERVER_URL}/.well-known/openid-configuration").json()
        assert metadata["federation_registration_endpoint"].endswith("/federation/register")
        assert metadata["client_registration_types_supported"] == ["automatic", "explicit"]
        print("  [2/9] discovery : registration federation + types publies (§5.1.3)")

        listed = http.get(f"{SERVER_URL}/federation/list")
        assert listed.status_code == 200, listed.text
        assert listed.headers["content-type"].startswith("application/json")
        assert listed.json() == [_FEDERATED_CLIENT_ID], listed.json()
        print("  [3/9] liste des subordonnes : seul le client federe est rendu (§8.2.2)")

        fetched = http.get(f"{SERVER_URL}/federation/fetch", params={"sub": _FEDERATED_CLIENT_ID})
        assert fetched.status_code == 200, fetched.text
        assert fetched.headers["content-type"].startswith("application/entity-statement+jwt")
        subordinate = _decode(fetched.text, claims["jwks"])
        assert subordinate["iss"] == ENTITY_IDENTIFIER, subordinate
        assert subordinate["sub"] == _FEDERATED_CLIENT_ID, subordinate
        assert subordinate["jwks"] == {"keys": [rp_jwk]}, subordinate["jwks"]
        registered = subordinate["metadata"]["openid_relying_party"]
        assert registered["redirect_uris"] == [f"{_FEDERATED_CLIENT_ID}/cb"], registered
        assert registered["jwks"] == {"keys": [rp_jwk]}, registered
        print("  [4/9] subordinate statement signe par l'OP, cles attestees (§8.1, §3.1.3)")

        missing = http.get(f"{SERVER_URL}/federation/fetch")
        assert missing.status_code == 400, missing.text
        assert missing.json()["error"] == "invalid_request", missing.json()
        as_iss = http.get(f"{SERVER_URL}/federation/fetch", params={"sub": ENTITY_IDENTIFIER})
        assert as_iss.status_code == 400, as_iss.text
        assert as_iss.json()["error"] == "invalid_request", as_iss.json()
        unknown = http.get(
            f"{SERVER_URL}/federation/fetch", params={"sub": "https://inconnu.example"}
        )
        assert unknown.status_code == 404, unknown.text
        assert unknown.json()["error"] == "not_found", unknown.json()
        print("  [5/9] fetch : contrats d'erreur (400 invalid_request, 404 not_found, §8.9)")

        resolve_missing = http.get(f"{SERVER_URL}/federation/resolve")
        assert resolve_missing.status_code == 400, resolve_missing.text
        assert resolve_missing.json()["error"] == "invalid_request", resolve_missing.json()
        print("  [6/9] resolve : parametres obligatoires manquants -> 400 (§8.3)")

        unresolvable = http.get(
            f"{SERVER_URL}/federation/resolve",
            params={"sub": _FEDERATED_CLIENT_ID, "trust_anchor": _ANCHOR},
        )
        assert unresolvable.status_code == 404, unresolvable.text
        assert unresolvable.json()["error"] == "not_found", unresolvable.json()
        print("  [7/9] resolve : ancre injoignable -> 404, aucune chaine (§10.1)")

        refused = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "client_id": _FEDERATED_CLIENT_ID,
                "response_type": "code",
                "scope": "openid",
                "state": "state-sample",
                "request": _invalid_request_object(_FEDERATED_CLIENT_ID + "/cb"),
            },
            follow_redirects=False,
        )
        assert refused.status_code == 302, refused.text
        location = refused.headers["location"]
        assert location.startswith(f"{_FEDERATED_CLIENT_ID}/cb?"), location
        refused_query = parse_qs(urlparse(location).query)
        assert refused_query["error"] == ["invalid_request_object"], refused_query
        assert refused_query["state"] == ["state-sample"], refused_query
        print("  [8/9] JAR refuse -> redirection d'erreur vers la callback du RP (issue #211)")

        outside = http.get(
            f"{SERVER_URL}/authorize",
            params={
                "client_id": _FEDERATED_CLIENT_ID,
                "response_type": "code",
                "scope": "openid",
                "state": "state-sample",
                "request": _invalid_request_object("https://evil.example/steal"),
            },
            follow_redirects=False,
        )
        assert outside.status_code == 400, outside.text
        assert "location" not in outside.headers, dict(outside.headers)
        print("  [9/9] redirect_uri du JAR hors registre -> page 400, aucune redirection")


def main() -> int:
    """Lance le serveur de test puis joue le scénario."""
    rp_jwk = _federated_client_jwk()
    clients = ({**_FEDERATED_CLIENT_BASE, "jwks": [rp_jwk]}, _PLAIN_CLIENT)
    with (
        watchdog(_DEADLINE),
        run_server(
            port=SERVER_PORT,
            clients=clients,
            extra_settings={"federation_enabled": True},
        ),
    ):
        _run_scenario(rp_jwk)
    print("\n=== SCENARIO OK ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
