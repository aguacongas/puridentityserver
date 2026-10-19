"""Tests de la politique de mots de passe (issue #166, CA 5-8 amendés).

Domain ``PasswordPolicy`` / ``PasswordPolicyPatch`` : validations de forme
(longueur, classes, denylist, contenance email, séquences et runs clavier),
surcharge partielle par client et configuration serveur (`Settings` :
table `[settings.password_policy]`, variable `PURIDENTITYSERVER_PASSWORD_POLICY`,
table `password_policy` d'un client seedé).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from puridentityserver.domain.password_policy import PasswordPolicy, PasswordPolicyPatch
from puridentityserver.infrastructure.settings import Settings

# Conforme au défaut : 14 caractères, toutes les classes, ni courant, ni
# email, ni suite interdite.
_COMPLIANT = "Motdepasse123!"


def test_default_policy_accepts_compliant_password() -> None:
    """Un mot de passe conforme ne remonte aucune violation."""
    assert PasswordPolicy().validate(_COMPLIANT, "carol@example.com") == ()


def test_min_length_violation_reports_requirement() -> None:
    """La longueur minimale manquante est annoncée avec la longueur actuelle."""
    violations = PasswordPolicy().validate("Mot1!", "carol@example.com")
    assert violations == ("12 caractères minimum (actuel : 5)",)


def test_max_length_violation_reports_requirement() -> None:
    """Le plafond de longueur (garde-fou DoS) est annoncé."""
    violations = PasswordPolicy().validate(f"{_COMPLIANT}{'x' * 200}", "carol@example.com")
    assert any(message.startswith("pas plus de 128 caractères") for message in violations)


def test_class_minimums_are_reported() -> None:
    """Chaque classe manquante est listée séparément."""
    violations = PasswordPolicy().validate("alllowercase123!", "carol@example.com")
    assert violations == ("1 majuscule(s) minimum (actuel : 0)",)


def test_common_password_is_rejected() -> None:
    """La denylist intégrée refuse un mot de passe courant même long."""
    violations = PasswordPolicy().validate("motdepasse123", "carol@example.com")
    assert any("trop courant" in message for message in violations)


def test_password_containing_email_is_rejected() -> None:
    """Le local-part de l'email dans le mot de passe est refusé."""
    violations = PasswordPolicy().validate("Caroline2026XY!", "carol@example.com")
    assert violations == ("mot de passe interdit : il contient l'adresse email",)


def test_short_email_local_part_is_ignored() -> None:
    """Un local-part trop court (< 3 caractères) ne déclenche pas le contrôle."""
    assert PasswordPolicy().validate("Password123ab!", "ab@example.com") == ()


def test_empty_email_skips_containment_check() -> None:
    """Sans email (hors flow), le contrôle de contenance est ignoré."""
    assert PasswordPolicy().validate(_COMPLIANT, "") == ()


@pytest.mark.parametrize(
    "password",
    (
        "Abcdefghijkl1!",  # suite ascendante alphanumérique
        "Lkjihgfedcba1!",  # suite descendante
        "Azertyuiop12!",  # run clavier AZERTY
        "Poiuytrewq12!",  # run clavier inversé
    ),
)
def test_sequences_and_keyboard_runs_are_rejected(password: str) -> None:
    """Suites alphanumériques et runs clavier (4+ consécutifs) sont refusés."""
    violations = PasswordPolicy().validate(password, "carol@example.com")
    assert violations == (
        "suite de caractères interdite (ex. 1234, abcd, azerty — 4+ consécutifs)",
    )


def test_passphrase_without_run_is_accepted() -> None:
    """Une passphrase sans suite de 4 caractères consécutifs passe."""
    assert PasswordPolicy().validate("Soleil&Lune2026", "carol@example.com") == ()


def test_disabled_checks_skip_violations() -> None:
    """Les contrôles désactivés par configuration ne produisent rien."""
    policy = PasswordPolicy(
        min_length=8,
        min_uppercase=0,
        min_lowercase=0,
        min_digits=0,
        min_special=0,
        deny_common_passwords=False,
        forbid_email_containment=False,
        forbid_sequences=False,
    )
    assert policy.validate("azerty123", "azerty@example.com") == ()


def test_describe_lists_requirements() -> None:
    """``describe`` formule les exigences pour le formulaire."""
    assert PasswordPolicy().describe() == (
        "12 caractères minimum ; "
        "dont 1 majuscule(s), 1 minuscule(s), 1 chiffre(s), 1 caractère spécial(s)"
    )


def test_patch_overrides_only_declared_keys() -> None:
    """La surcharge n'écrase que les clés renseignées."""
    base = PasswordPolicy()
    patched = PasswordPolicyPatch(min_length=16, deny_common_passwords=False).apply(base)
    assert patched.min_length == 16
    assert patched.deny_common_passwords is False
    assert patched.max_length == base.max_length
    assert patched.min_uppercase == base.min_uppercase
    assert patched.history_depth == base.history_depth


def test_from_mapping_rejects_unknown_key() -> None:
    """Une clé inconnue est rejetée (typo de configuration)."""
    with pytest.raises(ValueError, match="inconnue"):
        PasswordPolicyPatch.from_mapping({"min_lenght": 16})


@pytest.mark.parametrize(
    ("mapping", "expected"),
    (
        ({"deny_common_passwords": 1}, "bool"),
        ({"min_length": True}, "int"),
        ({"history_depth": "3"}, "int"),
    ),
)
def test_from_mapping_rejects_wrong_types(mapping: dict[str, object], expected: str) -> None:
    """Les types sont stricts : booléen ≠ entier, pas de coercion implicite."""
    with pytest.raises(ValueError, match=expected):
        PasswordPolicyPatch.from_mapping(mapping)


def test_policy_from_mapping_builds_full_policy() -> None:
    """``PasswordPolicy.from_mapping`` construit la politique complète."""
    policy = PasswordPolicy.from_mapping({"min_length": 16, "history_depth": 0})
    assert policy.min_length == 16
    assert policy.history_depth == 0
    assert policy.min_uppercase == 1
    assert policy.deny_common_passwords is True


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("min_length", 0),
        ("max_length", 0),
        ("min_uppercase", -1),
        ("min_digits", 2000),
        ("history_depth", 50),
    ),
)
def test_invalid_ranges_are_rejected(field: str, value: int) -> None:
    """Toute valeur hors plage lève ``ValueError`` au chargement."""
    with pytest.raises(ValueError):
        replace(PasswordPolicy(), **{field: value})


def test_max_length_below_min_is_rejected() -> None:
    """Un plafond inférieur au plancher est incohérent."""
    with pytest.raises(ValueError, match="max_length"):
        PasswordPolicy(min_length=20, max_length=10)


def test_settings_password_policy_accepts_mapping() -> None:
    """La table ``[settings.password_policy]`` alimente la politique par défaut."""
    settings = Settings(password_policy={"min_length": 16})
    assert settings.password_policy.min_length == 16
    assert settings.password_policy.min_uppercase == 1


def test_settings_password_policy_accepts_env_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """``PURIDENTITYSERVER_PASSWORD_POLICY`` accepte le même objet en JSON."""
    monkeypatch.setenv("PURIDENTITYSERVER_PASSWORD_POLICY", '{"min_length": 18, "min_digits": 2}')
    settings = Settings()
    assert settings.password_policy.min_length == 18
    assert settings.password_policy.min_digits == 2


def test_settings_password_policy_rejects_non_object_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un JSON non-objet en environnement est refusé."""
    monkeypatch.setenv("PURIDENTITYSERVER_PASSWORD_POLICY", "[16]")
    with pytest.raises(ValueError, match="objet JSON"):
        _ = Settings().password_policy


def test_seed_client_carries_password_policy_patch() -> None:
    """La table ``password_policy`` du client seed devient une surcharge typée."""
    settings = Settings(clients_seed=({"client_id": "app", "password_policy": {"min_length": 16}},))
    client = settings.seed_clients[0]
    assert client.password_policy.min_length == 16
    assert client.password_policy.max_length is None


def test_seed_client_without_policy_has_empty_patch() -> None:
    """Sans table ``password_policy``, la surcharge est vide (défaut pur)."""
    settings = Settings(clients_seed=({"client_id": "app"},))
    assert settings.seed_clients[0].password_policy == PasswordPolicyPatch()


def test_seed_client_rejects_unknown_policy_key() -> None:
    """Une clé inconnue dans la surcharge casse le chargement au démarrage."""
    settings = Settings(clients_seed=({"client_id": "app", "password_policy": {"nope": 1}},))
    with pytest.raises(ValueError, match="inconnue"):
        _ = settings.seed_clients


def test_seed_client_rejects_non_table_policy() -> None:
    """Une valeur non-table pour ``password_policy`` est refusée."""
    settings = Settings(
        clients_seed=({"client_id": "app", "password_policy": "min_length=16"},),
    )
    with pytest.raises(ValueError, match="table"):
        _ = settings.seed_clients
