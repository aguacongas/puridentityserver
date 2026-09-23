"""Génère le rapport statique (GitHub Pages) de la suite de certification OIDC.

Lit les fichiers JSON exportés par ``run-test-plan.py`` (option
``--export-dir``) et produit une page ``index.html`` listant les plans joués
et leurs verdicts, avec les rapports bruts re-publiés sous ``site/results/``.
Le script reste permissif : la structure exacte de l'export étant susceptible
d'évoluer avec la version de la suite, les extractions sont défensives et
chaque rapport brut reste consultable tel quel.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path

_ALLOWED_RESULTS = frozenset({"PASSED", "FAILED", "WARNING", "REVIEW", "SKIPPED", "INTERRUPTED"})
_COLORS = {
    "PASSED": "#1b7a3d",
    "FAILED": "#b00020",
    "WARNING": "#9a6700",
    "REVIEW": "#2563eb",
    "SKIPPED": "#6b7280",
    "INTERRUPTED": "#b00020",
}


def _iter_result_entries(node: object) -> Iterable[tuple[str, str]]:
    """Énumère (libellé, résultat) portés par les entrées de test d'un rapport."""
    if isinstance(node, Mapping):
        result = node.get("result")
        if isinstance(result, str) and result in _ALLOWED_RESULTS:
            label = (
                node.get("testName")
                or node.get("testPlan")
                or node.get("condition")
                or node.get("id")
                or node.get("module")
                or "<inconnu>"
            )
            yield str(label), result
        for value in node.values():
            yield from _iter_result_entries(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_result_entries(value)


def _summarize(path: Path) -> tuple[str, str, dict[str, int], list[tuple[str, str]]]:
    """Résume un rapport brut : étiquette, horodatage, compteurs, verdicts."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    label = (
        raw.get("testPlanName")
        or raw.get("planName")
        or raw.get("testPlan")
        or raw.get("planId")
        or path.stem
    )
    timestamp = raw.get("startedAt") or raw.get("timestamp") or ""
    entries = list(_iter_result_entries(raw))
    counts = Counter(result for _, result in entries)
    ordered = sorted(_ALLOWED_RESULTS.intersection(counts), key=lambda r: -counts[r])
    counts_dict = {name: counts[name] for name in ordered}
    return str(label), str(timestamp), counts_dict, entries


def _render(
    plans: list[tuple[str, str, dict[str, int], list[tuple[str, str]]]], site: Path
) -> None:
    """Écrit la page index consolidée du rapport."""
    generated = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows: list[str] = []
    for label, timestamp, counts, entries in plans:
        badges = (
            " ".join(
                f'<span style="color:{_COLORS[name]}">{counts[name]} {name}</span>'
                for name in counts
            )
            or "<i>aucun verdict extrait</i>"
        )
        details = "".join(
            f'<li>{html.escape(lib)} - <b style="color:{_COLORS[res]}">{res}</b></li>'
            for lib, res in entries[:200]
        )
        extra = "" if len(entries) <= 200 else f"<li><i>… {len(entries) - 200} autres</i></li>"
        suffix = f" ({timestamp})" if timestamp else ""
        rows.append(
            f"<section><h2>{html.escape(label)}{html.escape(suffix)}</h2>"
            f"<p>{badges}</p><ul>{details}{extra}</ul></section>"
        )
    body = "\n".join(rows) or "<p>Aucun résultat exporté : lancer un run du workflow.</p>"
    html_content = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8"><title>PurIdentityServer - certification OIDC</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; max-width: 60rem; }}
  section {{ border-top: 1px solid #ccc; padding: 1rem 0; }}
  li {{ margin: 0.2rem 0; }}
</style>
</head>
<body>
<h1>PurIdentityServer - attestations de conformité OIDC</h1>
<p>Suite officielle OpenID Foundation (conformance-suite). Généré le {generated}.</p>
{body}
</body>
</html>
"""
    site.mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_text(html_content, encoding="utf-8")


def main() -> None:
    """Point d'entrée : rassemble les exports JSON puis écrit le site statique."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="results", help="dossier des exports JSON")
    parser.add_argument("--site", default="_site", help="dossier du site statique")
    args = parser.parse_args()

    results = Path(args.results)
    site = Path(args.site)
    site_results = site / "results"
    site_results.mkdir(parents=True, exist_ok=True)
    plans: list[tuple[str, str, dict[str, int], list[tuple[str, str]]]] = []
    for path in sorted(results.glob("*.json")):
        try:
            plans.append(_summarize(path))
        except (OSError, json.JSONDecodeError):
            continue
        (site_results / path.name).write_bytes(path.read_bytes())
    _render(plans, site)


if __name__ == "__main__":
    main()
