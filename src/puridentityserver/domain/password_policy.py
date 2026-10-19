"""Politique de mots de passe des comptes de connexion de l'OP.

Une ``PasswordPolicy`` décrit les exigences appliquées aux mots de passe
soumis sur la page d'inscription ``/signup`` (``prompt=create``, issue #166)
et lors d'une réinitialisation : longueur min/max, classes de caractères
exigées, denylist de mots courants, interdiction de contenance d'adresse
email, détection de séquences (`123456`, `abcdef`) et de runs clavier
(``qwerty``, ``azerty``), profondeur d'historique de réemploi.

Configuration (hiérarchie config.toml → ``PURIDENTITYSERVER_*`` → ``.env``) :

- ``[settings.password_policy]`` : valeurs par défaut du serveur ;
- ``password_policy = { … }`` (table partielle) sur un client de
  ``[[settings.clients_seed]]`` : seules les clés présentes écrasent la
  défaut pour les flows de ce client (``PasswordPolicyPatch``) ; une clé
  inconnue ou un type erroné est rejeté au démarrage.

L'historique de réemploi (``history_depth``) est porté par
``User.password_history`` : la réinitialisation refuse un mot de passe
figurant parmi les derniers utilisés.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from itertools import pairwise
from typing import Any

#: Plafond de longueur (garde-fou DoS : hachage argon2 d'une saisie démesurée).
_MAX_LENGTH = 1024

#: Plafond d'historique conservé par compte.
_MAX_HISTORY = 20

#: Longueur minimale d'une suite interdite (1234, dcba, azerty…).
_SEQUENCE_MIN_RUN = 4

#: Rangées clavier (QWERTY + AZERTY) scrutées pour les runs interdits.
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "azertyuiop", "qsdfghjklm", "wxcvbn")

#: Mots de passe les plus courants (extraits des listes de fuites
#: populaires) : refusés quelles que soient les classes représentées.
_COMMON_PASSWORDS = frozenset(
    {
        "123456",
        "123456789",
        "12345678",
        "1234567890",
        "password",
        "passw0rd",
        "qwerty",
        "azerty",
        "azertyuiop",
        "motdepasse",
        "admin",
        "login",
        "welcome",
        "iloveyou",
        "monkey",
        "dragon",
        "letmein",
        "princess",
        "football",
        "baseball",
        "sunshine",
        "shadow",
        "superman",
        "trustno1",
        "master",
        "hello",
        "freedom",
        "whatever",
        "starwars",
        "computer",
        "secret",
        "abc123",
        "abcd1234",
        "111111",
        "000000",
        "123123",
        "654321",
        "password1",
        "password123",
        "p@ssw0rd",
        "p@ssword",
        "admin123",
        "root",
        "toor",
        "changeme",
        "default",
        "guest",
        "test",
        "test123",
        "demo",
        "demo123",
        "summer",
        "winter",
        "spring",
        "autumn",
        "january",
        "february",
        "december",
        "qwertz",
        "qsdfgh",
        "wxcvbn",
        "1q2w3e4r",
        "1qaz2wsx",
        "zaq12wsx",
        "qazwsx",
        "asdfgh",
        "zxcvbn",
        "passer",
        "bonjour",
        "coucou",
        "soleil",
        "lune",
        "chocolat",
        "france",
        "paris",
        "merde",
        "connard",
        "famille",
        "telephone",
        "internet",
        "souris",
        "clavier",
        "ordinateur",
        "marseille",
        "lyon",
        "bienvenue",
        "azerty123",
        "motdepasse123",
        "informatique",
        "developpeur",
        "administrateur",
        "connexion",
        "inscription",
    }
)

#: Champs booléens d'une surcharge (les autres sont entiers).
_BOOL_FIELDS = frozenset({"deny_common_passwords", "forbid_email_containment", "forbid_sequences"})

_CLASS_FIELDS = ("min_uppercase", "min_lowercase", "min_digits", "min_special")

#: Libellé de la classe « caractère spécial » (exigences affichées).
_SPECIAL_CLASS_LABEL = "caractère spécial"


def _require_range(name: str, value: int, minimum: int, maximum: int) -> None:
    """Lève ``ValueError`` si ``value`` sort de ``[minimum, maximum]``."""
    if not minimum <= value <= maximum:
        raise ValueError(
            f"password_policy.{name} doit être compris entre {minimum} et {maximum} "
            f"(reçu : {value})"
        )


@dataclass(frozen=True)
class PasswordPolicy:
    """Exigences de politique de mots de passe (valeurs serveur par défaut)."""

    #: Longueur minimale (caractères Unicode).
    min_length: int = 12
    #: Longueur maximale (garde-fou DoS, cf. ``_MAX_LENGTH``).
    max_length: int = 128
    #: Majuscules minimales exigées.
    min_uppercase: int = 1
    #: Minuscules minimales exigées.
    min_lowercase: int = 1
    #: Chiffres minimaux exigés.
    min_digits: int = 1
    #: Caractères spéciaux minimaux exigés (tout caractère non alphanumérique).
    min_special: int = 1
    #: Refuse les mots de passe de la denylist intégrée.
    deny_common_passwords: bool = True
    #: Refuse un mot de passe contenant l'adresse email ou son local-part.
    forbid_email_containment: bool = True
    #: Refuse les suites alphanumériques et les runs clavier.
    forbid_sequences: bool = True
    #: Nombre de derniers mots de passe dont la réutilisation est interdite
    #: (``0`` désactive l'historique).
    history_depth: int = 5

    def __post_init__(self) -> None:
        """Valide la cohérence des bornes (``ValueError`` hors plage)."""
        _require_range("min_length", self.min_length, 1, _MAX_LENGTH)
        _require_range("max_length", self.max_length, 1, _MAX_LENGTH)
        if self.max_length < self.min_length:
            raise ValueError(
                f"password_policy.max_length ({self.max_length}) "
                f"doit précéder min_length ({self.min_length})"
            )
        for name in _CLASS_FIELDS:
            _require_range(name, getattr(self, name), 0, _MAX_LENGTH)
        _require_range("history_depth", self.history_depth, 0, _MAX_HISTORY)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> PasswordPolicy:
        """Construit la politique depuis une configuration (clés partielles acceptées)."""
        return PasswordPolicyPatch.from_mapping(raw).apply(cls())

    def validate(self, password: str, email: str = "") -> tuple[str, ...]:
        """Retourne les violations du mot de passe soumis (messages FR), vide si conforme."""
        violations: list[str] = []
        if len(password) < self.min_length:
            violations.append(f"{self.min_length} caractères minimum (actuel : {len(password)})")
        if len(password) > self.max_length:
            violations.append(
                f"pas plus de {self.max_length} caractères (actuel : {len(password)})"
            )
        violations.extend(_class_violations(self, password))
        if self.deny_common_passwords and password.lower().strip() in _COMMON_PASSWORDS:
            violations.append("mot de passe trop courant (listes de fuites connues)")
        if self.forbid_email_containment and _contains_email(password, email):
            violations.append("mot de passe interdit : il contient l'adresse email")
        if self.forbid_sequences and _has_forbidden_run(password):
            violations.append(
                "suite de caractères interdite "
                f"(ex. 1234, abcd, azerty — {_SEQUENCE_MIN_RUN}+ consécutifs)"
            )
        return tuple(violations)

    def describe(self) -> str:
        """Formule les exigences pour l'affichage sur le formulaire d'inscription."""
        parts = [f"{self.min_length} caractères minimum"]
        classes = _class_requirements(self)
        if classes:
            parts.append("dont " + ", ".join(classes))
        return " ; ".join(parts)


@dataclass(frozen=True)
class PasswordPolicyPatch:
    """Surcharge partielle de politique : seules les clés renseignées écrasent la base."""

    #: Longueur minimale écrasée.
    min_length: int | None = None
    #: Longueur maximale écrasée.
    max_length: int | None = None
    #: Majuscules minimales écrasées.
    min_uppercase: int | None = None
    #: Minuscules minimales écrasées.
    min_lowercase: int | None = None
    #: Chiffres minimaux écrasés.
    min_digits: int | None = None
    #: Caractères spéciaux minimaux écrasés.
    min_special: int | None = None
    #: Traitement de la denylist écrasé.
    deny_common_passwords: bool | None = None
    #: Traitement de la contenance email écrasé.
    forbid_email_containment: bool | None = None
    #: Traitement des séquences écrasé.
    forbid_sequences: bool | None = None
    #: Profondeur d'historique écrasée.
    history_depth: int | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> PasswordPolicyPatch:
        """Valide une configuration (TOML/JSON) : clés connues et types stricts.

        Les booléens ne sont acceptés que comme vrais booléens (un entier ne
        passe pas, un ``true`` TOML non plus pour un champ entier) : une
        faute de frappe est rejetée au démarrage plutôt qu'interprétée.
        """
        known = {descriptor.name for descriptor in fields(cls)}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ValueError(
                "Clé(s) de politique de mots de passe inconnue(s) : " + ", ".join(unknown)
            )
        changes: dict[str, Any] = {}
        for name, value in raw.items():
            expected = bool if name in _BOOL_FIELDS else int
            if type(value) is not expected:
                raise ValueError(
                    f"password_policy.{name} : valeur {expected.__name__} attendue "
                    f"(reçu : {value!r})"
                )
            changes[name] = value
        return cls(**changes)

    def apply(self, base: PasswordPolicy) -> PasswordPolicy:
        """Retourne une copie de ``base`` avec les seules clés renseignées de la surcharge."""
        merged: dict[str, Any] = {
            descriptor.name: getattr(base, descriptor.name) for descriptor in fields(base)
        }
        for descriptor in fields(self):
            value = getattr(self, descriptor.name)
            if value is not None:
                merged[descriptor.name] = value
        return PasswordPolicy(**merged)


def _class_counts(password: str) -> dict[str, int]:
    """Compte les caractères de chaque classe dans ``password``."""
    return {
        "majuscule": sum(1 for character in password if character.isupper()),
        "minuscule": sum(1 for character in password if character.islower()),
        "chiffre": sum(1 for character in password if character.isdigit()),
        _SPECIAL_CLASS_LABEL: sum(1 for character in password if not character.isalnum()),
    }


def _class_requirements(policy: PasswordPolicy) -> list[str]:
    """Liste les classes exigées par ``policy`` (texte d'affichage)."""
    minimums = {
        "majuscule": policy.min_uppercase,
        "minuscule": policy.min_lowercase,
        "chiffre": policy.min_digits,
        _SPECIAL_CLASS_LABEL: policy.min_special,
    }
    return [f"{minimum} {label}(s)" for label, minimum in minimums.items() if minimum]


def _class_violations(policy: PasswordPolicy, password: str) -> list[str]:
    """Retourne les exigences de classes non satisfaites par ``password``."""
    counts = _class_counts(password)
    minimums = {
        "majuscule": policy.min_uppercase,
        "minuscule": policy.min_lowercase,
        "chiffre": policy.min_digits,
        _SPECIAL_CLASS_LABEL: policy.min_special,
    }
    return [
        f"{minimum} {label}(s) minimum (actuel : {counts[label]})"
        for label, minimum in minimums.items()
        if counts[label] < minimum
    ]


def _contains_email(password: str, email: str) -> bool:
    """Vrai si le mot de passe contient l'email ou son local-part (casse ignorée)."""
    if not email:
        return False
    lowered = password.lower()
    local_part, _, _ = email.lower().partition("@")
    candidates = {email.lower()}
    if len(local_part) >= 3:
        candidates.add(local_part)
    return any(candidate in lowered for candidate in candidates)


def _has_forbidden_run(password: str) -> bool:
    """Vrai si le mot de passe contient une suite alphanumérique ou un run clavier."""
    lowered = password.lower()
    return _has_alnum_run(lowered) or any(_has_row_run(lowered, row) for row in _KEYBOARD_ROWS)


def _has_alnum_run(value: str) -> bool:
    """Vrai si ``value`` enchaîne ``_SEQUENCE_MIN_RUN`` caractères alphanumériques (±1)."""
    ascending = descending = 0
    for previous, current in pairwise(value):
        if previous.isalnum() and current.isalnum():
            step = ord(current) - ord(previous)
            ascending = ascending + 1 if step == 1 else 0
            descending = descending + 1 if step == -1 else 0
        else:
            ascending = descending = 0
        if max(ascending, descending) >= _SEQUENCE_MIN_RUN - 1:
            return True
    return False


def _has_row_run(value: str, row: str) -> bool:
    """Vrai si ``value`` contient ``_SEQUENCE_MIN_RUN`` caractères d'une rangée clavier."""
    windows = {
        row[index : index + _SEQUENCE_MIN_RUN] for index in range(len(row) - _SEQUENCE_MIN_RUN + 1)
    }
    windows |= {window[::-1] for window in windows}
    return any(window in value for window in windows)
