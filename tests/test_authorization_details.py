"""Tests pour le module de details d'autorisation OID4VCI."""

from __future__ import annotations

import pytest

from puridentityserver.application.authorization_details import (
    AuthorizationDetailsError,
    authorization_detail_keys,
    credential_configuration_for_identifier,
    encode_authorization_details,
    grant_authorization_details,
    has_authorization_details,
    parse_authorization_details,
)


def test_empty_returns_tuple() -> None:
    assert parse_authorization_details("") == ()


def test_invalid_json_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details("not-json")


def test_non_list_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details('{"type":"openid_credential"}')


def test_missing_type_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details('[{"credential_configuration_id":"puridentityserver-sdjwt-vc"}]')


def test_unknown_type_ignored() -> None:
    assert parse_authorization_details('[{"type":"unknown"}]') == ()


def test_missing_config_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details('[{"type":"openid_credential"}]')


def test_unknown_config_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details(
            '[{"type":"openid_credential","credential_configuration_id":"nope"}]'
        )


def test_claims_non_dict_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details(
            '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc","claims":42}]'
        )


def test_valid_with_claims() -> None:
    details = parse_authorization_details(
        '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc","claims":{"given_name":null},"extra":1}]'
    )
    assert details == (
        {
            "type": "openid_credential",
            "credential_configuration_id": "puridentityserver-sdjwt-vc",
            "claims": {"given_name": None},
        },
    )


def test_non_dict_item_raises() -> None:
    with pytest.raises(AuthorizationDetailsError):
        parse_authorization_details("[42]")


def test_encode_roundtrip() -> None:
    details = parse_authorization_details(
        '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc"}]'
    )
    encoded = encode_authorization_details(details)
    assert parse_authorization_details(encoded) == details


def test_detail_keys() -> None:
    details = parse_authorization_details(
        '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc"}]'
    )
    keys = authorization_detail_keys(details)
    assert len(keys) == 1


def test_grant_adds_identifiers() -> None:
    details = parse_authorization_details(
        '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc"}]'
    )
    granted = grant_authorization_details(details)
    assert granted[0]["credential_identifiers"] == ["puridentityserver-sdjwt-vc"]


def test_credential_configuration_for_identifier() -> None:
    claim = grant_authorization_details(
        parse_authorization_details(
            '[{"type":"openid_credential","credential_configuration_id":"puridentityserver-sdjwt-vc"}]'
        )
    )
    assert (
        credential_configuration_for_identifier(claim, "puridentityserver-sdjwt-vc")
        == "puridentityserver-sdjwt-vc"
    )
    assert credential_configuration_for_identifier(claim, "nope") is None
    assert credential_configuration_for_identifier("bad", "x") is None


def test_has_authorization_details() -> None:
    assert has_authorization_details([]) is False
    assert has_authorization_details(None) is False
    assert has_authorization_details([{"type": "openid_credential"}]) is True