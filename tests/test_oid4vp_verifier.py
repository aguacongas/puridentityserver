"""Tests du use case verifier OpenID4VP : initiation et validation (issue #224)."""

from __future__ import annotations

import time
import zlib
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import RSAAlgorithm
from oid4vp_wallet import SimulatedWallet, generate_key, public_jwk

from puridentityserver.application.oid4vp import (
    KEY_BINDING_CLAIMS,
    MAX_PENDING_REQUESTS,
    REQUEST_OBJECT_TYP,
    RESPONSE_MODE_DIRECT_POST_JWT,
    RESPONSE_TYPE_VP,
    SELF_ISSUED_AUDIENCE,
    OID4VPVerifierUseCase,
    PresentationRequestCreated,
)
from puridentityserver.infrastructure.jwe import b64u
from puridentityserver.infrastructure.oid4vp_pki import (
    InMemoryVerifierPKIRepository,
    VerifierPKIRepository,
)
from puridentityserver.infrastructure.status_list import StatusListFetcher

ISSUER = "https://id.example"


def _usecase(
    repository: VerifierPKIRepository | None = None,
    credential_jwks: tuple[dict[str, Any], ...] = (),
    status_list_fetcher: StatusListFetcher | None = None,
) -> OID4VPVerifierUseCase:
    """Construit un verifier sur un depot de PKI donne (defaut : memoire)."""
    return OID4VPVerifierUseCase(
        issuer=ISSUER,
        pki_repository=repository if repository is not None else InMemoryVerifierPKIRepository(),
        credential_jwks=credential_jwks,
        status_list_fetcher=status_list_fetcher,
    )


def _created(
    usecase: OID4VPVerifierUseCase, **kwargs: object
) -> tuple[PresentationRequestCreated, dict[str, Any]]:
    """Cree une demande et rend (demande, claims du request object)."""
    created = usecase.create_presentation_request(**kwargs)
    claims = pyjwt.decode(created.request_object, options={"verify_signature": False})
    return created, claims


def _rsa_jwk() -> dict[str, Any]:
    """Construit un JWK public RSA (algorithme refuse par le verifier)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    return dict(jwk)


#: URI de la status list referencee par les credentials de test (OTSL).
STATUS_URI = "https://status.example/statuslists/1"


class _StubStatusListFetcher:
    """Fetcher de test : memorise les uris et rend un token fourni."""

    def __init__(self, token: str | None) -> None:
        """``token`` est le corps servi a chaque fetch (``None`` = echec)."""
        self._token = token
        self.urls: list[str] = []

    def fetch(self, url: str) -> str | None:
        """Memorise ``url`` puis rend le token configure."""
        self.urls.append(url)
        return self._token


def _status_reference(index: int = 4) -> dict[str, Any]:
    """Construit le claim ``status`` d'un credential (``uri`` + ``idx``, OTSL §6.2)."""
    return {"status_list": {"uri": STATUS_URI, "idx": index}}


def _status_list_token(
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    revoked_index: int | None = None,
    sub: str | None = None,
    typ: str = "statuslist+jwt",
    bits: int = 1,
    lst: str | None = None,
) -> str:
    """Signe un Status List Token JWT au format de la suite (OTSL §5.1).

    Args:
        issuer_key: cle de l'emetteur du credential (meme cle que le JWKS).
        revoked_index: index marque INVALID (1) dans le bitstring ; les autres
            entrees restent VALID (0).
        sub: claim ``sub`` (defaut : :data:`STATUS_URI`).
        typ: valeur ``typ`` de l'en-tete.
        bits: valeur ``bits`` du claim ``status_list``.
        lst: remplace le bitstring compresse genere.

    Returns:
        Le JWT compact signe.
    """
    entries = bytearray(32)
    if revoked_index is not None:
        entries[revoked_index // 8] |= 1 << (revoked_index % 8)
    encoded = b64u(zlib.compress(bytes(entries))) if lst is None else lst
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": STATUS_URI if sub is None else sub,
        "iat": now,
        "exp": now + 300,
        "ttl": 300,
        "status_list": {"bits": bits, "lst": encoded},
    }
    return pyjwt.encode(payload, issuer_key, algorithm="ES256", headers={"typ": typ})


def test_request_object_carries_exact_oid4vp_claims() -> None:
    """Le request object porte les claims attendus du profil 1.0 Final."""
    usecase = _usecase()
    created, claims = _created(usecase)

    assert created.request_object.count(".") == 2
    assert claims["iss"] == created.client_id
    assert claims["aud"] == SELF_ISSUED_AUDIENCE
    assert claims["client_id"] == created.client_id
    assert claims["response_type"] == RESPONSE_TYPE_VP
    assert claims["response_mode"] == RESPONSE_MODE_DIRECT_POST_JWT
    assert claims["response_uri"] == f"{ISSUER}/oid4vp/vp_response/{created.request_id}"
    assert claims["nonce"] == created.nonce
    assert isinstance(claims["iat"], int)
    forbidden = {
        "request",
        "request_uri",
        "wallet_nonce",
        "request_uri_method",
        "redirect_uri",
        "scope",
        "code_challenge",
        "state",
        # client_id_scheme supprime d'OID4VP 1.0 Final (ID3) : le scheme est
        # porte par le prefixe de client_id, la suite echoue en FAILURE sinon.
        "client_id_scheme",
    }
    assert forbidden.isdisjoint(claims)


def test_request_object_header_uses_leaf_x5c_chain() -> None:
    """L'en-tete porte typ oauth-authz-req+jwt, x5c leaf et kid d'empreinte."""
    repository = InMemoryVerifierPKIRepository()
    usecase = _usecase(repository)
    created = usecase.create_presentation_request()
    pki = repository.load()
    assert pki is not None

    header = pyjwt.get_unverified_header(created.request_object)
    assert header["typ"] == REQUEST_OBJECT_TYP
    assert header["alg"] == "ES256"
    assert header["kid"] == pki.leaf_thumbprint
    assert header["x5c"] == pki.x5c

    public_key = pki.leaf_certificate.public_key()
    claims = pyjwt.decode(
        created.request_object,
        public_key,  # type: ignore[arg-type]  # cle EC hors stubs PyJWT
        algorithms=["ES256"],
        options={"verify_aud": False},
    )
    assert claims["client_id"] == pki.client_id
    assert created.client_id.startswith("x509_hash:")


def test_default_dcql_query_targets_unique_pid_sdjwt() -> None:
    """Le DCQL par defaut exige un credential PID dc+sd-jwt unique."""
    usecase = _usecase()
    _, claims = _created(usecase)
    assert claims["dcql_query"] == {
        "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
            }
        ]
    }


def test_custom_dcql_query_is_forwarded() -> None:
    """Un DCQL explicite est repris tel quel dans le request object."""
    usecase = _usecase()
    query = {"credentials": [{"id": "other", "format": "mso_mdoc"}]}
    _, claims = _created(usecase, dcql_query=query)
    assert claims["dcql_query"] == query


def test_client_metadata_advertises_encrypted_direct_post() -> None:
    """client_metadata : jwks EC ECDH-ES unique, vp_formats et enc values."""
    usecase = _usecase()
    _, claims = _created(usecase)
    metadata = claims["client_metadata"]
    assert set(metadata) == {
        "jwks",
        "vp_formats_supported",
        "encrypted_response_enc_values_supported",
    }
    assert metadata["vp_formats_supported"] == {"dc+sd-jwt": {}}
    assert metadata["encrypted_response_enc_values_supported"] == ["A128GCM", "A256GCM"]
    keys = metadata["jwks"]["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "EC"
    assert keys[0]["crv"] == "P-256"
    assert keys[0]["alg"] == "ECDH-ES"
    assert keys[0]["use"] == "enc"
    assert keys[0]["kid"]


def test_encryption_key_is_fresh_for_every_request() -> None:
    """HAIP 5-6 : aucune reutilisation de cle de chiffrement entre demandes."""
    usecase = _usecase()
    _, first = _created(usecase)
    _, second = _created(usecase)
    key_one = first["client_metadata"]["jwks"]["keys"][0]
    key_two = second["client_metadata"]["jwks"]["keys"][0]
    assert (key_one["x"], key_one["y"]) != (key_two["x"], key_two["y"])
    assert key_one["kid"] != key_two["kid"]
    assert first["nonce"] != second["nonce"]


def test_nonce_is_43_char_base64url() -> None:
    """Le nonce fait 32 octets aleatoires, encodes en 43 caracteres base64url."""
    usecase = _usecase()
    created, _ = _created(usecase)
    assert len(created.nonce) == 43
    assert set(created.nonce) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )


def test_get_request_object_is_idempotent() -> None:
    """Le GET du request_uri rend toujours le meme document signe."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    first = usecase.get_request_object(created.request_id)
    second = usecase.get_request_object(created.request_id)
    assert first == created.request_object
    assert second == created.request_object


def test_get_request_object_unknown_id_returns_none() -> None:
    """Une demande inconnue n'a pas de request object."""
    usecase = _usecase()
    assert usecase.get_request_object("missing") is None


def test_post_wallet_nonce_resigns_request_object() -> None:
    """request_uri_method=post : le wallet_nonce est ajoute et re-signé."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    resigned = usecase.get_request_object(created.request_id, wallet_nonce="wallet-value")
    assert resigned is not None
    claims = pyjwt.decode(resigned, options={"verify_signature": False})
    assert claims["wallet_nonce"] == "wallet-value"
    assert claims["nonce"] == created.nonce
    header = pyjwt.get_unverified_header(resigned)
    assert header["kid"] == pyjwt.get_unverified_header(created.request_object)["kid"]


def test_post_without_wallet_nonce_serves_original_document() -> None:
    """Un POST sans wallet_nonce sert le request object d'origine."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    document = usecase.get_request_object(created.request_id, wallet_nonce=None)
    assert document == created.request_object


def test_valid_presentation_is_accepted_with_redirect_uri() -> None:
    """Round-trip complet : la presentation valide rend 200 + redirect_uri."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object)

    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 200
    assert result.accepted
    assert result.body == {"redirect_uri": f"{ISSUER}/oid4vp/result/{created.request_id}"}
    assert result.detail == ""


def test_unknown_request_id_is_rejected_404() -> None:
    """Une response sur une demande inconnue est refusee en 404."""
    usecase = _usecase()
    result = usecase.validate_presentation_response("missing", response="whatever")
    assert result.status_code == 404
    assert result.body["error"] == "invalid_request"


def test_malformed_response_is_rejected() -> None:
    """Un document qui n'est pas un JWE compact est refuse."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    result = usecase.validate_presentation_response(created.request_id, response="not-a-jwe")
    assert result.status_code == 400
    assert result.detail == "response de presentation illisible"


def test_unknown_encryption_kid_is_rejected() -> None:
    """Un kid de chiffrement inconnu est refuse avant tout dechiffrement."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object, kid="unknown-kid")
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "kid de chiffrement inconnu"


def test_corrupted_ciphertext_is_rejected() -> None:
    """Un JWE dont le contenu a ete altere ne se dechiffre pas."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object)
    parts = response.split(".")
    ciphertext = parts[2]
    flipped = "B" if ciphertext[0] == "A" else "A"
    parts[2] = flipped + ciphertext[1:]
    result = usecase.validate_presentation_response(created.request_id, response=".".join(parts))
    assert result.status_code == 400
    assert result.detail == "response de presentation non dechiffrable"


def test_non_object_payload_is_rejected() -> None:
    """Un payload dechiffre qui n'est pas un objet JSON est refuse."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    claims = pyjwt.decode(created.request_object, options={"verify_signature": False})
    jwk = claims["client_metadata"]["jwks"]["keys"][0]
    response = wallet.seal([1, 2, 3], recipient_jwk=jwk)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "payload de response attendu comme objet JSON"


def test_vp_token_shapes_are_rejected() -> None:
    """Toute forme de vp_token autre que {id: [credential unique]} est refusee."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    invalid_payloads: tuple[dict[str, Any], ...] = (
        {"vp_token": "not-an-object"},
        {"vp_token": {}},
        {"vp_token": {"a": ["x"], "b": ["y"]}},
        {"vp_token": {"pid": "not-a-list"}},
        {"vp_token": {"pid": ["a", "b"]}},
        {"vp_token": {"pid": []}},
        {"vp_token": {"pid": [123]}},
        {"vp_token": {"pid": [""]}},
    )
    for payload in invalid_payloads:
        created = usecase.create_presentation_request()
        response = wallet.respond(created.request_object, payload_extra=payload)
        result = usecase.validate_presentation_response(created.request_id, response=response)
        assert result.status_code == 400, payload
        assert result.body["error"] == "invalid_request", payload


def test_malformed_sd_jwt_is_rejected() -> None:
    """Une chaine presentee avec un segment vide est refusee."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object, kb_raw="")
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "sd-jwt presente malforme (kb-jwt attendu)"

    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object, credential="~abc~")
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "sd-jwt presente malforme (kb-jwt attendu)"


def test_credential_typ_must_be_sd_jwt() -> None:
    """Le typ du credential doit valoir dc+sd-jwt (module negatif)."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    credential = wallet.credential(typ="jwt")
    response = wallet.respond(created.request_object, credential=credential)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "typ du credential attendu dc+sd-jwt"


def test_key_binding_typ_and_legibility_are_checked() -> None:
    """Le kb-jwt doit etre lisible et porte le typ kb+jwt."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    cases = (("garbage", "kb-jwt illisible"), ("typ", "typ du kb-jwt attendu kb+jwt"))
    for mutation, expected in cases:
        created = usecase.create_presentation_request()
        if mutation == "garbage":
            response = wallet.respond(created.request_object, kb_raw="garbage")
        else:
            response = wallet.respond(created.request_object, kb_typ="jwt")
        result = usecase.validate_presentation_response(created.request_id, response=response)
        assert result.status_code == 400, mutation
        assert result.detail == expected, mutation


def test_key_binding_claims_are_exact() -> None:
    """Le kb-jwt ne porte que iat, aud, nonce et sd_hash — ni plus, ni moins."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object, overrides={"extra": 1})
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert "claims inattendus" in result.detail

    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object, drop=("sd_hash",))
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert "claims manquants" in result.detail
    assert set(KEY_BINDING_CLAIMS) == {"iat", "aud", "nonce", "sd_hash"}


def test_key_binding_nonce_must_match_request() -> None:
    """Le nonce du kb-jwt doit valoir celui du request object."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object, overrides={"nonce": "wrong"})
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "nonce du kb-jwt invalide"


def test_key_binding_aud_must_match_client_id() -> None:
    """L'audience du kb-jwt doit valoir le client_id x509_hash du verifier."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object, overrides={"aud": "x509_hash:other"})
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "audience du kb-jwt invalide"


def test_key_binding_sd_hash_must_match_presented_prefix() -> None:
    """Le sd_hash du kb-jwt doit valoir le hash du prefixe presente."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object, overrides={"sd_hash": "AAAA"})
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "sd_hash du kb-jwt invalide"


def test_key_binding_iat_must_be_fresh_integer() -> None:
    """L'iat du kb-jwt doit etre un entier dans la fenetre de tolerance."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    now = int(time.time())
    cases: tuple[tuple[dict[str, Any], str], ...] = (
        ({"iat": now - 3600}, "iat du kb-jwt hors fenetre de tolerance"),
        ({"iat": now + 3600}, "iat du kb-jwt hors fenetre de tolerance"),
        ({"iat": "now"}, "iat du kb-jwt invalide"),
        ({"iat": True}, "iat du kb-jwt invalide"),
    )
    for overrides, expected in cases:
        created = usecase.create_presentation_request()
        response = wallet.respond(created.request_object, overrides=overrides)
        result = usecase.validate_presentation_response(created.request_id, response=response)
        assert result.status_code == 400, overrides
        assert result.detail == expected, overrides


def test_key_binding_signature_must_use_cnf_key() -> None:
    """Le kb-jwt doit etre signe par la cle de cnf.jwk du credential."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    response = wallet.respond(created.request_object, kb_key=generate_key())
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "signature du kb-jwt invalide"


def test_cnf_binding_key_is_required_and_ec() -> None:
    """Le credential doit porter un cnf.jwk EC P-256 exploitable."""
    usecase = _usecase()
    wallet = SimulatedWallet()
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"cnf": {}})
    response = wallet.respond(created.request_object, credential=credential)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "cnf.jwk absent du credential"

    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"cnf": {"jwk": _rsa_jwk()}})
    response = wallet.respond(created.request_object, credential=credential)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "cnf.jwk non exploitable (EC P-256 attendu)"


def test_witness_mode_skips_issuer_signature_check() -> None:
    """Sans JWKS de confiance, la signature de l'emetteur n'est pas controlee."""
    usecase = _usecase()
    created = usecase.create_presentation_request()
    wallet = SimulatedWallet()
    credential = wallet.credential(issuer_key=generate_key())
    response = wallet.respond(created.request_object, credential=credential)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 200


def test_trusted_jwks_accepts_matching_issuer_signature() -> None:
    """Avec un JWKS de confiance, un credential correctement signe passe."""
    wallet = SimulatedWallet()
    usecase = _usecase(credential_jwks=(public_jwk(wallet.issuer_key),))
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 200


def test_trusted_jwks_rejects_unmatched_issuer_signature() -> None:
    """Un credential signe hors JWKS de confiance est refuse (module negatif)."""
    wallet = SimulatedWallet()
    usecase = _usecase(credential_jwks=(public_jwk(wallet.issuer_key),))
    created = usecase.create_presentation_request()
    credential = wallet.credential(issuer_key=generate_key())
    response = wallet.respond(created.request_object, credential=credential)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "signature du credential non appariee au JWKS de confiance"


def test_trusted_jwks_tries_every_key_before_rejecting() -> None:
    """Chaque cle du JWKS est essayee avant de conclure a l'absence d'appariement."""
    wallet = SimulatedWallet()
    usecase = _usecase(credential_jwks=(public_jwk(generate_key()), public_jwk(wallet.issuer_key)))
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 200


def test_unreadable_trusted_key_is_reported() -> None:
    """Une cle de confiance inutilisable (type symetrique) produit un rejet motive."""
    wallet = SimulatedWallet()
    usecase = _usecase(credential_jwks=({"kty": "oct", "k": "AAAA"},))
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "credential illisible"


def test_rsa_trusted_key_cannot_verify_ec_credential() -> None:
    """Une cle RSA de confiance ne valide pas un credential ES256 : illisible."""
    wallet = SimulatedWallet()
    usecase = _usecase(credential_jwks=(_rsa_jwk(),))
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)
    result = usecase.validate_presentation_response(created.request_id, response=response)
    assert result.status_code == 400
    assert result.detail == "credential illisible"


def test_unrequested_vct_is_rejected() -> None:
    """Un credential d'un type non demande par la DCQL est refuse."""
    wallet = SimulatedWallet()
    usecase = _usecase()
    created = usecase.create_presentation_request()
    credential = wallet.credential(vct="urn:conformance-suite:unrequested:credential:1")
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "vct du credential non demande par la DCQL query"


def test_unusable_vct_is_rejected_when_the_query_requests_one() -> None:
    """Un credential sans ``vct`` exploitable est refuse."""
    wallet = SimulatedWallet()
    usecase = _usecase()
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"vct": None})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "vct du credential non demande par la DCQL query"


def test_vct_is_not_checked_when_the_query_omits_vct_values() -> None:
    """Une DCQL sans ``meta.vct_values`` n'impose aucun type au credential."""
    wallet = SimulatedWallet()
    usecase = _usecase()
    created = usecase.create_presentation_request(
        dcql_query={"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]}
    )
    credential = wallet.credential(vct="urn:autre:type:1")
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 200


def test_credential_without_status_is_accepted_without_fetch() -> None:
    """Sans claim ``status``, aucune status list n'est requise ni fetchee."""
    wallet = SimulatedWallet()
    fetcher = _StubStatusListFetcher(None)
    usecase = _usecase(status_list_fetcher=fetcher)
    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 200
    assert fetcher.urls == []


def test_valid_status_credential_is_accepted() -> None:
    """Un credential dont la status list le marque valide est accepte."""
    wallet = SimulatedWallet()
    fetcher = _StubStatusListFetcher(_status_list_token(wallet.issuer_key))
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),), status_list_fetcher=fetcher
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 200
    assert fetcher.urls == [STATUS_URI]


def test_revoked_credential_is_rejected() -> None:
    """Un index INVALID de la status list rejette la presentation."""
    wallet = SimulatedWallet()
    fetcher = _StubStatusListFetcher(_status_list_token(wallet.issuer_key, revoked_index=5))
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),), status_list_fetcher=fetcher
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference(index=5)})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "credential revoque (status list)"


def test_status_without_fetcher_is_rejected() -> None:
    """Sans fetcher configure, un credential portant ``status`` est refuse."""
    wallet = SimulatedWallet()
    usecase = _usecase()
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "status list non configuree (fetch impossible)"


def test_failed_status_fetch_is_rejected() -> None:
    """L'echec du fetch rejette le credential (le statut n'a pu etre lu)."""
    wallet = SimulatedWallet()
    fetcher = _StubStatusListFetcher(None)
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),), status_list_fetcher=fetcher
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "status list inaccessible (fetch impossible)"


def test_unreadable_status_token_is_rejected() -> None:
    """Un corps fetché qui n'est pas un JWT rejette la presentation."""
    wallet = SimulatedWallet()
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher("pas-un-jwt"),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "status list token illisible"


def test_status_token_with_wrong_typ_is_rejected() -> None:
    """Le ``typ`` du Status List Token est controle (OTSL §5.1)."""
    wallet = SimulatedWallet()
    token = _status_list_token(wallet.issuer_key, typ="jwt")
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher(token),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "typ du status list token attendu statuslist+jwt"


def test_status_token_with_wrong_sub_is_rejected() -> None:
    """Le ``sub`` du token doit etre l'uri demandee (OTSL §5.1)."""
    wallet = SimulatedWallet()
    token = _status_list_token(wallet.issuer_key, sub="https://ailleurs.example/liste")
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher(token),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "sub du status list token incoherent avec l'uri"


def test_status_token_signed_by_another_key_is_rejected() -> None:
    """Le Status List Token doit etre signe par une cle de confiance."""
    wallet = SimulatedWallet()
    token = _status_list_token(generate_key())
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher(token),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "signature du status list non appariee au JWKS de confiance"


def test_unsupported_status_list_bits_are_rejected() -> None:
    """Seul ``bits = 1`` est géré : autre valeur = rejet motive."""
    wallet = SimulatedWallet()
    token = _status_list_token(wallet.issuer_key, bits=2)
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher(token),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "bits du status list token non géré (1 attendu)"


def test_unreadable_status_list_bits_are_rejected() -> None:
    """Un ``lst`` non décompressable rejette la presentation."""
    wallet = SimulatedWallet()
    token = _status_list_token(wallet.issuer_key, lst="!!!pas-du-base64!!!")
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),),
        status_list_fetcher=_StubStatusListFetcher(token),
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference()})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "lst du status list token illisible"


def test_index_outside_status_list_is_rejected() -> None:
    """Un index hors bornes du bitstring est rejete (jamais interprete)."""
    wallet = SimulatedWallet()
    fetcher = _StubStatusListFetcher(_status_list_token(wallet.issuer_key))
    usecase = _usecase(
        credential_jwks=(public_jwk(wallet.issuer_key),), status_list_fetcher=fetcher
    )
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": _status_reference(index=10_000)})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "index hors bornes de la status list"


def test_status_reference_without_status_list_is_rejected() -> None:
    """Un claim ``status`` sans ``status_list`` exploitable est rejete."""
    wallet = SimulatedWallet()
    usecase = _usecase()
    created = usecase.create_presentation_request()
    credential = wallet.credential(extra_claims={"status": {"inconnu": True}})
    response = wallet.respond(created.request_object, credential=credential)

    result = usecase.validate_presentation_response(created.request_id, response=response)

    assert result.status_code == 400
    assert result.detail == "status.status_list absent du credential"


def test_pending_registry_is_bounded_fifo() -> None:
    """Le registre evince la plus ancienne demande au-dela de la limite."""
    usecase = _usecase()
    oldest = usecase.create_presentation_request()
    for _ in range(MAX_PENDING_REQUESTS):
        usecase.create_presentation_request()
    assert usecase.get_request_object(oldest.request_id) is None
    result = usecase.validate_presentation_response(oldest.request_id, response="x")
    assert result.status_code == 404


def test_result_page_reports_outcomes() -> None:
    """La page de resultat affiche acceptation, rejet ou attente de reponse."""
    usecase = _usecase()
    wallet = SimulatedWallet()

    created = usecase.create_presentation_request()
    pending_page = usecase.result_page(created.request_id)
    assert pending_page is not None
    assert "Presentation refusee" in pending_page
    assert "réponse non reçue" in pending_page

    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object, overrides={"nonce": "bad"})
    usecase.validate_presentation_response(created.request_id, response=response)
    rejected_page = usecase.result_page(created.request_id)
    assert rejected_page is not None
    assert "Presentation refusee" in rejected_page
    assert "nonce du kb-jwt invalide" in rejected_page
    # Un rejet n'affiche aucun claim : seul le motif est servi.
    assert "<dl>" not in rejected_page

    created = usecase.create_presentation_request()
    response = wallet.respond(created.request_object)
    usecase.validate_presentation_response(created.request_id, response=response)
    accepted_page = usecase.result_page(created.request_id)
    assert accepted_page is not None
    assert "Presentation acceptee" in accepted_page
    # Les claims du credential accepte sont rendus dans la page.
    assert "<dt>vct</dt>" in accepted_page
    assert "<dd>urn:eudi:pid:1</dd>" in accepted_page
    assert "<dt>iss</dt>" in accepted_page
    assert "<dd>https://issuer.example</dd>" in accepted_page

    assert usecase.result_page("missing") is None


def test_pki_is_generated_once_and_shared_with_repository() -> None:
    """La PKI est generee une seule fois puis rechargee depuis le depot."""
    repository = InMemoryVerifierPKIRepository()
    usecase = _usecase(repository)
    first = usecase.create_presentation_request()
    second = usecase.create_presentation_request()
    assert first.client_id == second.client_id

    reused = _usecase(repository)
    third = reused.create_presentation_request()
    assert third.client_id == first.client_id
