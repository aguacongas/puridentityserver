"""Vérification locale : lint, format, typage strict et tests.

Usage:
    uv run python scripts/check.py            # exécute toutes les étapes
    uv run python scripts/check.py lint type  # exécute uniquement lint et type
"""

import subprocess
import sys
from collections.abc import Sequence

_STEPS: dict[str, Sequence[str]] = {
    "lint": ["uv", "run", "ruff", "check", "."],
    "format": ["uv", "run", "ruff", "format", "--check", "."],
    "type": ["uv", "run", "mypy", "src/puridentityserver"],
    "test": ["uv", "run", "pytest"],
}


def _run_steps(steps: Sequence[str]) -> int:
    failed = False
    for step in steps:
        command = _STEPS[step]
        print(f"==> {step}: {' '.join(command)}")
        result = subprocess.run(command)
        if result.returncode != 0:
            failed = True
    return 1 if failed else 0


def main() -> int:
    """Enchaîne les étapes demandées (ou toutes par défaut) et retourne le code de sortie."""
    args = sys.argv[1:]
    steps = tuple(args) if args else tuple(_STEPS)
    unknown = tuple(step for step in steps if step not in _STEPS)
    if unknown:
        print(f"Étapes inconnues : {', '.join(unknown)} — valides : {', '.join(_STEPS)}")
        return 2
    return _run_steps(steps)


if __name__ == "__main__":
    sys.exit(main())
