"""Tests d'intégration de l'émission mdoc (format ``mso_mdoc``) via OID4VCI."""

from __future__ import annotations

import asyncio
import base64
from datetime import date, datetime, timezone

import cbor2
import jwt as pyjwt
from cose.messages import Sign1Message
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from puridentityserver.application.authorization_details import (
    MDOC_CREDENTIAL_CONFIGURATION_ID,
    SUPPORTED_CREDENTIAL_CONFIGURATION_IDS,
)
from puridentityserver.application.oid4vci import (
    CREDENTIAL_CONFIGURATION_ID,
    MDOC_DOCTYPE,
    MDOC_FORMAT,
    CredentialError,
    OID4VCIIssuerUseCase,
    issuer_metadata_payload,
)
from puridentityserver.domain.authorization import Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.mdoc import (
    MDOC_ISSUING_COUNTRY,
    PERSONAL_NAME_NAMESPACE,
    _private_cose_key,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.tokens import PyJWTTokenManager

ISSUER = "https://id.example"

#: Les 11 éléments obligatoires du mDL (ISO 18013-5 §13.4.2, table 20).
MDL_MANDATORY = {
    "family_name",
    "given_name",
    "birth_date",
    "issue_date",
    "expiry_date",
    "issuing_country",
    "issuing_authority",
    "document_number",
    "portrait",
    "driving_privileges",
    "un_distinguishing_sign",
}


def _ec_proof(nonce: str, *, audience: str = ISSUER) -> str:
    """Construit une preuve JWT signée EC P-256 (device key mdoc)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    jwk = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
    jwk["alg"] = "ES256"
    now = int(datetime.now(timezone.utc).timestamp())
    return pyjwt.encode(
        {"aud": audience, "iat": now, "nonce": nonce},
        private_key,  # type: ignore[arg-type]
        algorithm="ES256",
        headers={"typ": "openid4vci-proof+jwt", "jwk": jwk},
    )


async def _ready_usecase() -> tuple[object, str]:
    """Prépare un émetteur avec une clé active et un access token valide."""
    token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
    await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)  # type: ignore[attr-defined]
    now = int(datetime.now(timezone.utc).timestamp())
    token = await token_manager.create_access_token(
        algorithm=JWTAlgorithm.RS256,
        issuer=ISSUER,
        subject="alice",
        audience="wallet-client",
        expires_at=now + 600,
        issued_at=now,
        scopes=frozenset({Scope.OID4VCI}),
    )
    from puridentityserver.application.oid4vci import OID4VCIIssuerUseCase

    usecase = OID4VCIIssuerUseCase(
        issuer=ISSUER,
        key_manager=token_manager._key_manager,
        algorithm=JWTAlgorithm.RS256,
        token_manager=token_manager,
    )
    return usecase, token


def test_metadata_publishes_mdoc_configuration() -> None:
    metadata = issuer_metadata_payload(ISSUER)
    configurations = metadata["credential_configurations_supported"]
    assert MDOC_CREDENTIAL_CONFIGURATION_ID in configurations
    assert MDOC_CREDENTIAL_CONFIGURATION_ID in SUPPORTED_CREDENTIAL_CONFIGURATION_IDS
    mdoc = configurations[MDOC_CREDENTIAL_CONFIGURATION_ID]
    assert mdoc["format"] == MDOC_FORMAT
    assert mdoc["doctype"] == MDOC_DOCTYPE
    assert mdoc["cryptographic_binding_methods_supported"] == ["cose_key"]
    assert mdoc["credential_signing_alg_values_supported"] == [-7]
    # La configuration SD-JWT reste publiée par défaut.
    assert CREDENTIAL_CONFIGURATION_ID in configurations


def test_mdoc_credential_is_verifiable_issuer_signed() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]  # type: ignore[attr-defined]
        result = await usecase.issue_credential(  # type: ignore[attr-defined]
            token,
            credential_configuration_id=MDOC_CREDENTIAL_CONFIGURATION_ID,
            proofs=(_ec_proof(nonce),),
        )
        assert isinstance(result, dict)
        credential = result["credentials"][0]["credential"]
        assert isinstance(credential, str)
        # CBOR base64url sans padding (OID4VCI 1.0 §8.5.1).
        assert "=" not in credential
        blob = base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
        outer = cbor2.loads(blob)
        assert set(outer) == {"issuerAuth", "nameSpaces"}
        assert PERSONAL_NAME_NAMESPACE in outer["nameSpaces"]
        # issuerAuth : COSE Sign1 en tableau nu (sans tag CBOR 18), vérifiable
        # par la clé du signer.
        auth = outer["issuerAuth"]
        assert isinstance(auth, list)
        assert len(auth) == 4
        usecase_pki = usecase._mdoc_pki  # type: ignore[attr-defined]
        message = Sign1Message.from_cose_obj(list(auth), True)
        message.key = _private_cose_key(usecase_pki.signer_private_key)
        assert message.verify_signature() is True
        # Le notification_id est joint (OID4VCI 1.0 §10).
        assert result["notification_id"]

    asyncio.run(_task())


def test_mdoc_emits_the_eleven_mandatory_mdl_elements() -> None:
    """Les 11 éléments obligatoires du mDL sont émis aux bons encodages.

    Régression issue #255 : la suite de conformance exige les éléments
    « M » de la table 20 (ISO 18013-5 §13.4.2) et applique à chaque
    valeur les contraintes de la colonne « Encoding format ».
    """

    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]
        result = await usecase.issue_credential(
            token,
            credential_configuration_id=MDOC_CREDENTIAL_CONFIGURATION_ID,
            proofs=(_ec_proof(nonce),),
        )
        credential = result["credentials"][0]["credential"]
        blob = base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))  # type: ignore[arg-type]
        outer = cbor2.loads(blob)
        decoded: dict[str, object] = {}
        for item in outer["nameSpaces"][PERSONAL_NAME_NAMESPACE]:
            inner = cbor2.loads(item.value)
            decoded[inner["elementIdentifier"]] = inner["elementValue"]
        assert set(decoded) == MDL_MANDATORY

        # Les dates sont des full-dates CBOR tag 1004 (date au décodage,
        # et non datetime qui correspondrait au tag 0 des tdate).
        birth_date = decoded["birth_date"]
        assert isinstance(birth_date, date) and not isinstance(birth_date, datetime)
        assert birth_date == date(1985, 6, 15)
        for element in ("issue_date", "expiry_date"):
            value = decoded[element]
            assert isinstance(value, date) and not isinstance(value, datetime)

        # portrait en bstr, issuing_country en alpha-2 aligné sur le
        # countryName du certificat document signer.
        portrait = decoded["portrait"]
        assert isinstance(portrait, bytes)
        assert portrait.startswith(b"\x89PNG")
        assert decoded["issuing_country"] == MDOC_ISSUING_COUNTRY

        # driving_privileges : tableau de maps avec vehicle_category_code
        # obligatoire, dates full-date et tableau de codes.
        privileges = decoded["driving_privileges"]
        assert isinstance(privileges, list)
        assert len(privileges) == 1
        privilege = privileges[0]
        assert privilege["vehicle_category_code"] == "B"
        for element in ("issue_date", "expiry_date"):
            value = privilege[element]
            assert isinstance(value, date) and not isinstance(value, datetime)
        assert privilege["codes"] == [{"code": "01"}]

        # Textes : latin-1 et 150 caractères au plus (table 20).
        for element in ("family_name", "given_name", "issuing_authority", "document_number"):
            value = decoded[element]
            assert isinstance(value, str)
            assert len(value) <= 150
            assert all(ord(character) <= 0xFF for character in value)

        # Les timestamps du MSO sont arrondis à l'heure (RFC 9901 §10.1)
        # et restent dans la validité du document signer (§9.3.1).
        message = Sign1Message.from_cose_obj(list(outer["issuerAuth"]), True)
        loaded = cbor2.loads(message.payload)
        mso = cbor2.loads(loaded.value) if isinstance(loaded, cbor2.CBORTag) else loaded
        validity = mso["validityInfo"]
        signed = validity["signed"]
        assert isinstance(signed, datetime)
        assert (signed.minute, signed.second, signed.microsecond) == (0, 0, 0)
        assert signed == validity["validFrom"]
        assert signed < validity["validUntil"]
        usecase_pki = usecase._mdoc_pki  # type: ignore[attr-defined]
        signer = usecase_pki.signer_certificate
        assert signer.not_valid_before_utc <= signed <= signer.not_valid_after_utc

    asyncio.run(_task())


def test_mdoc_binds_device_key_from_proof() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]  # type: ignore[attr-defined]
        proof = _ec_proof(nonce)
        proof_jwk = pyjwt.get_unverified_header(proof)["jwk"]  # type: ignore[attr-defined]
        result = await usecase.issue_credential(  # type: ignore[attr-defined]
            token,
            credential_configuration_id=MDOC_CREDENTIAL_CONFIGURATION_ID,
            proofs=(proof,),
        )
        assert isinstance(result, dict)
        credential = result["credentials"][0]["credential"]
        blob = base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))  # type: ignore[arg-type]
        outer = cbor2.loads(blob)
        usecase_pki = usecase._mdoc_pki  # type: ignore[attr-defined]
        message = Sign1Message.from_cose_obj(list(outer["issuerAuth"]), True)
        message.key = _private_cose_key(usecase_pki.signer_private_key)
        loaded = cbor2.loads(message.payload)
        mso = cbor2.loads(loaded.value) if isinstance(loaded, cbor2.CBORTag) else loaded
        device_key = mso["deviceKeyInfo"]["deviceKey"]
        # Les coordonnées COSE correspondent à la JWK de la preuve.
        expected_x = base64.urlsafe_b64decode(proof_jwk["x"] + "=" * (-len(proof_jwk["x"]) % 4))
        assert device_key[-2] == expected_x

    asyncio.run(_task())


def test_mdoc_rejects_rsa_binding_key() -> None:
    async def _task() -> None:
        usecase, token = await _ready_usecase()
        nonce = (await usecase.issue_nonce())["c_nonce"]  # type: ignore[attr-defined]
        # Une preuve RSA n'est pas un device key ISO 18013-5 valide.
        from cryptography.hazmat.primitives.asymmetric import rsa
        from jwt.algorithms import RSAAlgorithm

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)  # type: ignore[attr-defined]
        jwk["alg"] = "RS256"
        now = int(datetime.now(timezone.utc).timestamp())
        rsa_proof = pyjwt.encode(
            {"aud": ISSUER, "iat": now, "nonce": nonce},
            private_key,  # type: ignore[arg-type]
            algorithm="RS256",
            headers={"typ": "openid4vci-proof+jwt", "jwk": jwk},
        )
        result = await usecase.issue_credential(  # type: ignore[attr-defined]
            token,
            credential_configuration_id=MDOC_CREDENTIAL_CONFIGURATION_ID,
            proofs=(rsa_proof,),
        )
        assert isinstance(result, CredentialError)
        assert result.error == "invalid_proof"

    asyncio.run(_task())


def test_metadata_exposes_iaca_and_restricts_to_es256() -> None:
    """Tranche 2 HAIP : IACA publie dans les metadonnees, ES256 seul."""

    async def _task() -> None:
        usecase, _ = await _ready_usecase()
        metadata = usecase.issuer_metadata()
        mdoc = metadata["credential_configurations_supported"][MDOC_CREDENTIAL_CONFIGURATION_ID]
        assert mdoc["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] == [
            "ES256"
        ]
        # Parite avec la config SD-JWT : le proof type attestation est annonce
        # (key_attestations_required) pour que la suite OIDF joue le module de
        # validation des key attestations au lieu de le sauter.
        attestation = mdoc["proof_types_supported"]["attestation"]
        assert attestation["proof_signing_alg_values_supported"] == ["ES256"]
        assert attestation["key_attestations_required"] == {}
        certs = metadata["mdoc_iaca_certificates"]
        assert isinstance(certs, list)
        assert len(certs) == 1
        import base64

        from cryptography import x509

        der = base64.urlsafe_b64decode(certs[0] + "=" * (-len(certs[0]) % 4))
        certificate = x509.load_der_x509_certificate(der)
        assert certificate.subject is not None

    asyncio.run(_task())


def test_repository_backed_usecase_material_is_stable() -> None:
    """Tranche 3 : avec depot persistant, la PKI chargee reste stable."""

    async def _task() -> None:
        from puridentityserver.infrastructure.mdoc_storage import InMemoryMdocPKIRepository

        token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        await token_manager._key_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        now = int(datetime.now(timezone.utc).timestamp())
        token = await token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=ISSUER,
            subject="alice",
            audience="wallet-client",
            expires_at=now + 600,
            issued_at=now,
            scopes=frozenset({Scope.OID4VCI}),
        )
        repository = InMemoryMdocPKIRepository()
        usecase = OID4VCIIssuerUseCase(
            issuer=ISSUER,
            key_manager=token_manager._key_manager,
            algorithm=JWTAlgorithm.RS256,
            token_manager=token_manager,
            mdoc_pki_repository=repository,
        )
        n1 = (await usecase.issue_nonce())["c_nonce"]
        r1 = await usecase.issue_credential(
            token,
            credential_configuration_id=MDOC_CREDENTIAL_CONFIGURATION_ID,
            proofs=(_ec_proof(n1),),
        )
        assert isinstance(r1, dict)
        assert repository.load() is not None
        metadata = usecase.issuer_metadata()
        assert "mdoc_iaca_certificates" in metadata

        # persist stable across calls
        pki_loaded = repository.load()
        metadata_second = usecase.issuer_metadata()
        assert metadata_second["mdoc_iaca_certificates"] == metadata["mdoc_iaca_certificates"]
        assert pki_loaded is repository.load()

    asyncio.run(_task())
