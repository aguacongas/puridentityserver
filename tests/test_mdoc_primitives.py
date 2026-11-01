"""Tests unitaires des primitives CBOR/COSE utilisees pour mdoc/HAIP (issue #255)."""

from __future__ import annotations

import cbor2
from cose.keys import CoseKey
from cose.messages import Sign1Message
from cryptography.hazmat.primitives.asymmetric import ec


def _build_ec_key() -> CoseKey:
    """Cle EC P-256 au format COSE, comme dans le spike mdoc-pki."""
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    return CoseKey.from_dict(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: public.x.to_bytes(32, "big"),
            -3: public.y.to_bytes(32, "big"),
            -4: private.private_numbers().private_value.to_bytes(32, "big"),
        }
    )


def test_cose_sign1_tagged_roundtrip() -> None:
    """Un COSE Sign1 tague CBOR 18 peut etre produit puis relu et verifie."""
    key = _build_ec_key()
    payload = b"mdoc issuerAuth placeholder (MSO would live here)"

    message = Sign1Message(phdr={1: -7}, payload=payload)
    message.key = key
    encoded = message.encode(sign=True, tag=True)

    tagged = cbor2.loads(encoded)
    assert tagged.tag == 18

    decoded = Sign1Message.from_cose_obj(list(tagged.value), True)
    decoded.key = key
    assert decoded.payload == payload
    assert decoded.verify_signature() is True
