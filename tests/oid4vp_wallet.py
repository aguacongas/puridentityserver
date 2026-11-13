"""Wallet OpenID4VP simule pour les tests du verifier (issue #224).

Reproduit le comportement du wallet de la suite de conformance : emission d'un
credential SD-JWT VC (JWT issu + divulgations + kb-jwt), puis chiffrement de la
reponse ``direct_post.jwt`` en JWE ``ECDH-ES`` vers la cle ephemere annoncee
dans le ``client_metadata`` du request object. Les parametres de mutation
permettent de rejouer les modules negatifs du plan HAIP (nonce, aud, sd_hash,
iat, signature, kid, vp_token).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections.abc import Iterable, Mapping
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec

from puridentityserver.domain.jwe import JWEEncryptionMethod
from puridentityserver.infrastructure.jwe import (
    b64u,
    ec_jwk,
    ec_public_key,
    encrypt_compact_ecdh_es,
)

#: Valeur de ``typ`` du credential SD-JWT (RFC 9901 Appendix B.3.4).
SD_JWT_TYP = "dc+sd-jwt"

#: Valeur de ``typ`` du key binding JWT (SD-JWT 4.3).
KEY_BINDING_TYP = "kb+jwt"

#: ``vct`` du credential PID attendu par le profil HAIP.
DEFAULT_VCT = "urn:eudi:pid:1"


def generate_key() -> ec.EllipticCurvePrivateKey:
    """Genere une cle privee EC P-256 pour le wallet simule."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """Encode la cle publique d'un wallet simule en JWK EC."""
    return dict(ec_jwk(private_key.public_key()))


def disclosure(field: str, value: object) -> str:
    """Construit une divulgation SD-JWT (RFC 9901 5.1) : salt + champ + valeur."""
    salt = b64u(secrets.token_bytes(16))
    return b64u(json.dumps([salt, field, value], separators=(",", ":")).encode("utf-8"))


def sd_hash_of(presented: str) -> str:
    """Empreinte SHA-256 (base64url) du prefixe presente jusqu'au dernier ``~``.

    Args:
        presented: chaine presente ``credential~divulgations~kb-jwt``.

    Returns:
        La valeur ``sd_hash`` attendue dans le kb-jwt.
    """
    prefix = presented.rsplit("~", 1)[0] + "~"
    return b64u(hashlib.sha256(prefix.encode("ascii")).digest())


class SimulatedWallet:
    """Wallet SD-JWT simule : emission du credential, presentation, scellage."""

    def __init__(self) -> None:
        """Prepare les cles d'emission et de detenteur du wallet."""
        self.issuer_key = generate_key()
        self.holder_key = generate_key()

    def credential(
        self,
        *,
        issuer_key: ec.EllipticCurvePrivateKey | None = None,
        vct: str = DEFAULT_VCT,
        disclosures: Iterable[tuple[str, Any]] = (("given_name", "Alice"),),
        extra_claims: Mapping[str, Any] | None = None,
        typ: str = SD_JWT_TYP,
    ) -> str:
        """Emet un credential SD-JWT signe et lie a la cle du detenteur.

        Args:
            issuer_key: cle de l'emetteur, defaut : cle de ce wallet.
            vct: type de credential a revendiquer.
            disclosures: divulgations a attacher au credential.
            extra_claims: claims supplementaires du JWT de l'emetteur.
            typ: valeur de ``typ`` de l'en-tete (permet le module negatif).

        Returns:
            La chaine ``credential~divulgations~`` (kb-jwt a ajouter).
        """
        key = issuer_key if issuer_key is not None else self.issuer_key
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "https://issuer.example",
            "sub": "alice",
            "iat": now,
            "exp": now + 3600,
            "vct": vct,
            "cnf": {"jwk": public_jwk(self.holder_key)},
        }
        if extra_claims:
            claims.update(extra_claims)
        signed = pyjwt.encode(claims, key, algorithm="ES256", headers={"typ": typ})
        parts = [signed, *(disclosure(name, value) for name, value in disclosures)]
        return "~".join(parts) + "~"

    def present(
        self,
        credential: str,
        *,
        nonce: str,
        client_id: str,
        overrides: Mapping[str, Any] | None = None,
        drop: Iterable[str] = (),
        typ: str = KEY_BINDING_TYP,
        key: ec.EllipticCurvePrivateKey | None = None,
        raw: str | None = None,
    ) -> str:
        """Assemble la chaine presentee : credential + divulgations + kb-jwt.

        Args:
            credential: chaine ``credential~divulgations~`` fournie par
                :meth:`credential`.
            nonce: nonce du request object a reprendre.
            client_id: audience du kb-jwt (``client_id`` du verifier).
            overrides: claims du kb-jwt a remplacer (modules negatifs).
            drop: claims du kb-jwt a supprimer (modules negatifs).
            typ: valeur de ``typ`` de l'en-tete du kb-jwt.
            key: cle de signature du kb-jwt, defaut : cle du detenteur.
            raw: remplace le kb-jwt par une chaine brute (malformee).

        Returns:
            La chaine SD-JWT presentee au verifier.
        """
        if raw is not None:
            return credential + raw
        binding_key = key if key is not None else self.holder_key
        claims: dict[str, Any] = {
            "iat": int(time.time()),
            "aud": client_id,
            "nonce": nonce,
            "sd_hash": sd_hash_of(credential),
        }
        if overrides:
            claims.update(overrides)
        for name in drop:
            claims.pop(name, None)
        token = pyjwt.encode(claims, binding_key, algorithm="ES256", headers={"typ": typ})
        return credential + token

    def seal(
        self,
        payload: object,
        *,
        recipient_jwk: Mapping[str, Any],
        kid: str | None = None,
    ) -> str:
        """Chiffre un payload en JWE compact ECDH-ES vers une cle du verifier.

        Args:
            payload: objet JSON a chiffrer (ou toute valeur serialisable).
            recipient_jwk: JWK public EC du ``client_metadata`` du request object.
            kid: ``kid`` de l'en-tete protege, defaut : celui du JWK cible.

        Returns:
            Le JWE compact.
        """
        effective_kid = str(recipient_jwk.get("kid", "")) if kid is None else kid
        return encrypt_compact_ecdh_es(
            method=JWEEncryptionMethod.A128GCM,
            plaintext=json.dumps(payload).encode("utf-8"),
            recipient_public_key=ec_public_key(recipient_jwk),
            kid=effective_kid,
            apu=os.urandom(12),
            apv=os.urandom(12),
        )

    def respond(
        self,
        request_object: str,
        *,
        credential: str | None = None,
        kid: str | None = None,
        payload_extra: Mapping[str, Any] | None = None,
        overrides: Mapping[str, Any] | None = None,
        drop: Iterable[str] = (),
        kb_typ: str = KEY_BINDING_TYP,
        kb_key: ec.EllipticCurvePrivateKey | None = None,
        kb_raw: str | None = None,
    ) -> str:
        """Construit la valeur ``response`` du formulaire wallet complete.

        Decode le request object pour reprendre son nonce, son ``client_id``
        et l'identifiant DCQL de la requete, puis emet le credential, le
        kb-jwt et le JWE de la reponse.

        Args:
            request_object: JWT servi au ``request_uri`` du verifier.
            credential: chaine presentee a utiliser, defaut : nouvelle emis.
            kid: ``kid`` du JWE (defaut : celui du ``client_metadata``).
            payload_extra: champs supplementaires (ou remplacements) du
                payload dechiffre, dont ``vp_token`` pour les modules negatifs.
            overrides: claims du kb-jwt a remplacer.
            drop: claims du kb-jwt a supprimer.
            kb_typ: valeur de ``typ`` du kb-jwt.
            kb_key: cle de signature du kb-jwt.
            kb_raw: kb-jwt de remplacement (chaine brute).

        Returns:
            Le JWE compact poste par le wallet.
        """
        claims = pyjwt.decode(request_object, options={"verify_signature": False})
        client_id = str(claims["client_id"])
        nonce = str(claims["nonce"])
        dcql = claims.get("dcql_query") or {}
        credentials = dcql.get("credentials") or [{}]
        credential_id = str(credentials[0].get("id", "pid"))
        presented = self.present(
            credential if credential is not None else self.credential(),
            nonce=nonce,
            client_id=client_id,
            overrides=overrides,
            drop=drop,
            typ=kb_typ,
            key=kb_key,
            raw=kb_raw,
        )
        body: dict[str, Any] = {"vp_token": {credential_id: [presented]}}
        if payload_extra:
            body.update(payload_extra)
        jwk = claims["client_metadata"]["jwks"]["keys"][0]
        return self.seal(body, recipient_jwk=jwk, kid=kid)
