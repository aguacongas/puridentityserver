"""Rapport markdown du rejeu des checks de certification OIDC (marker ``conformance``).

Lit le rapport JUnit XML produit par ``pytest -m conformance`` et construit un
résumé publié directement dans la pull request (sur le modèle du Quality Gate
SonarCloud), pour voir sans ouvrir les logs du workflow quels checks passent
et lesquels échouent :

- ``--markdown <fichier>`` : écrit le rapport pour le workflow ;
- ``$GITHUB_STEP_SUMMARY`` : l'ajoute à l'onglet du workflow (si défini) ;
- sinon : affiche le rapport sur la sortie standard.

Usage:
    uv run python scripts/conformance_report.py junit-conformance.xml
    uv run python scripts/conformance_report.py junit.xml --markdown rapport.md
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_MARKER = "<!-- conformance-report -->"

# Titres des modules de la suite officielle rejoués (release-v5.2.4), indexés
# par nom de test — un test ajouté sans titre affiche simplement son nom.
_CHECK_TITLES: dict[str, str] = {
    "test_ensure_registered_redirect_uri_displays_error_page": (
        "oidcc-ensure-registered-redirect-uri"
    ),
    "test_prompt_login_forces_second_authentication": "oidcc-prompt-login",
    "test_max_age_1_reprompts_authentication": "oidcc-max-age-1",
}

_STATUS_LABELS = {"passed": "Réussi", "failed": "Échoué", "skipped": "Ignoré"}
_MAX_DETAIL = 300


@dataclass
class _CheckResult:
    """Issue d'un ``testcase`` du rapport JUnit."""

    name: str
    time: float
    status: str
    detail: str = ""


def _detail(element: ET.Element) -> str:
    """Première ligne du message d'échec (le traceback complet reste dans les logs)."""
    text = element.get("message") or element.text or ""
    lines = text.strip().splitlines()
    return (lines[0].strip() if lines else "")[:_MAX_DETAIL]


def _parse(junit_path: Path) -> list[_CheckResult]:
    """Extrait les résultats du rapport JUnit écrit par pytest."""
    if not junit_path.is_file():
        return []
    results: list[_CheckResult] = []
    for case in ET.parse(junit_path).getroot().iter("testcase"):
        name = case.get("name", "sans nom")
        duration = float(case.get("time", "0"))
        failure = case.find("failure")
        skipped = case.find("skipped")
        if failure is not None:
            results.append(_CheckResult(name, duration, "failed", _detail(failure)))
        elif skipped is not None:
            results.append(_CheckResult(name, duration, "skipped", _detail(skipped)))
        else:
            results.append(_CheckResult(name, duration, "passed"))
    return results


def _check_title(name: str) -> str:
    """Titre du check de certification (fallback : nom du test de pytest)."""
    title = _CHECK_TITLES.get(name)
    return f"`{title}`" if title is not None else f"`{name}`"


def _failures(results: Sequence[_CheckResult]) -> str:
    """Détail des échecs, replié derrière un ``<details>``."""
    failed = [result for result in results if result.status == "failed"]
    if not failed:
        return ""
    lines = ["", "<details>", f"<summary>Échecs ({len(failed)})</summary>", ""]
    lines.extend(
        f"- **{result.name}** : {result.detail or 'voir les logs du workflow'}" for result in failed
    )
    lines += ["", "</details>"]
    return "\n".join(lines)


def render(results: Sequence[_CheckResult]) -> str:
    """Construit le commentaire markdown publié dans la pull request."""
    total = len(results)
    if total == 0:
        return (
            f"{_MARKER}\n### Rejeu des checks de certification OIDC\n\n"
            "**Aucun résultat** : le rapport JUnit est absent, le rejeu n'a peut-être pas tourné."
        )
    passed = sum(result.status == "passed" for result in results)
    failed = sum(result.status == "failed" for result in results)
    skipped = sum(result.status == "skipped" for result in results)
    counts = (
        f"{passed} réussi{'' if passed == 1 else 's'}, {failed} échec{'' if failed == 1 else 's'}"
    )
    if skipped:
        counts += f", {skipped} ignoré{'' if skipped == 1 else 's'}"
    duration = sum(result.time for result in results)

    lines = [
        f"{_MARKER}",
        "### Rejeu des checks de certification OIDC",
        "",
        f"**{total} checks : {counts}** — durée totale {duration:.1f} s",
        "",
        "| Check de certification | Résultat | Durée |",
        "|:--|:-:|--:|",
    ]
    for result in results:
        label = _STATUS_LABELS[result.status]
        if result.status == "failed":
            label = f"**{label}**"
        lines.append(f"| {_check_title(result.name)} | {label} | {result.time:.1f} s |")
    lines.append(_failures(results))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Génère le rapport, l'écrit dans les sorties demandées et affiche un résumé."""
    parser = argparse.ArgumentParser(description="Rapport markdown du rejeu conformance.")
    parser.add_argument("junit", type=Path, help="Rapport JUnit XML écrit par pytest")
    parser.add_argument("--markdown", type=Path, help="Fichier markdown à écrire")
    args = parser.parse_args(argv)

    body = render(_parse(args.junit))
    if args.markdown is not None:
        args.markdown.write_text(body + "\n", encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as stream:
            stream.write("\n" + body + "\n")
    if args.markdown is None and not step_summary:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
