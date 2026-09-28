"""Génère le rapport statique (GitHub Pages) de la suite de certification OIDC.

Lit les exports produits par ``run-test-plan.py`` (option ``--export-dir``) :
des journaux JSON nus, ou les archives ``.zip`` rendues par l'API de la suite
(une archive par plan, contenant un journal JSON par module de test). Le
script produit une page ``index.html`` listant chaque module avec son verdict,
les compteurs de conditions et les contrôles en échec, puis re-publie les
journaux bruts sous ``site/results/``. Le script reste permissif : un export
illisible est simplement ignoré.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import zipfile
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

# Ordre d'affichage des verdicts (les échecs d'abord).
_VERDICTS = ("FAILED", "INTERRUPTED", "REVIEW", "WARNING", "PASSED", "SKIPPED", "INCONNU")

_COLORS = {
    "PASSED": "#1b7a3d",
    "FAILED": "#b00020",
    "INTERRUPTED": "#b00020",
    "FAILURE": "#b00020",
    "WARNING": "#9a6700",
    "REVIEW": "#2563eb",
    "SKIPPED": "#6b7280",
    "SUCCESS": "#1b7a3d",
    "INFO": "#6b7280",
    "FINISHED": "#6b7280",
    "INCONNU": "#6b7280",
}

# Résultats de conditions sans intérêt pour le rapport (trop verbeux).
_QUIET_CONDITIONS = frozenset({"SUCCESS", "INFO", "FINISHED"})

_MAX_DETAILS = 50


@dataclass(frozen=True)
class _Module:
    """Verdict d'un module de test extrait d'un journal d'export."""

    name: str
    variant: str
    verdict: str
    started: str
    counts: dict[str, int]
    checks: list[tuple[str, str]]


def _variant(info: Mapping[str, object]) -> str:
    """Formate la variante du module (paramètres du test) en texte compact."""
    variant = info.get("variant")
    if not isinstance(variant, Mapping):
        return ""
    return ", ".join(f"{key}={variant[key]}" for key in sorted(variant))


def _checks(raw: Mapping[str, object]) -> list[tuple[str, str]]:
    """Extrait les contrôles du journal sous forme de paires (libellé, résultat)."""
    results = raw.get("results")
    checks: list[tuple[str, str]] = []
    if not isinstance(results, list):
        return checks
    for entry in results:
        if not isinstance(entry, Mapping):
            continue
        result = entry.get("result")
        if not isinstance(result, str) or not result:
            continue
        label = entry.get("msg") or entry.get("src") or entry.get("condition") or "?"
        checks.append((str(label), result))
    return checks


def _load_module(name: str, payload: bytes) -> _Module | None:
    """Interprète un journal JSON ; renvoie ``None`` s'il est illisible."""
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, Mapping):
        return None
    info = raw.get("testInfo")
    typed_info = info if isinstance(info, Mapping) else {}
    checks = _checks(raw)
    return _Module(
        name=str(typed_info.get("testName") or Path(name).stem),
        variant=_variant(typed_info),
        verdict=str(typed_info.get("result") or typed_info.get("status") or "INCONNU"),
        started=str(typed_info.get("started") or raw.get("exportedAt") or ""),
        counts=dict(Counter(result for _, result in checks)),
        checks=[entry for entry in checks if entry[1] not in _QUIET_CONDITIONS],
    )


def _read_archive(path: Path) -> list[tuple[str, bytes]]:
    """Lit les journaux JSON d'une archive ; liste vide si elle est illisible."""
    try:
        with zipfile.ZipFile(path) as archive:
            return [
                (Path(member).name, archive.read(member))
                for member in sorted(archive.namelist())
                if member.endswith(".json")
            ]
    except (OSError, zipfile.BadZipFile):
        return []


def _read_report(path: Path) -> tuple[str, bytes] | None:
    """Lit un journal JSON nu ; ``None`` si le fichier est illisible."""
    try:
        return path.name, path.read_bytes()
    except OSError:
        return None


def _iter_exports(results: Path) -> Iterable[tuple[str, bytes]]:
    """Enumère les journaux JSON d'un dossier d'exports (archives ou fichiers nus)."""
    for archive_path in sorted(results.glob("*.zip")):
        yield from _read_archive(archive_path)
    for path in sorted(results.glob("*.json")):
        report = _read_report(path)
        if report is not None:
            yield report


def _badge(label: str, color: str) -> str:
    """Colorise un libellé de verdict ou de résultat de contrôle."""
    return f'<span style="color:{color}">{html.escape(label)}</span>'


def _color(result: str) -> str:
    """Renvoie la couleur associée à un verdict ou à un résultat."""
    return _COLORS.get(result, _COLORS["INCONNU"])


def _section(module: _Module) -> str:
    """Rend la section HTML consacrée à un module."""
    verdict = _badge(module.verdict, _color(module.verdict))
    counts = " ".join(
        _badge(f"{count} {result}", _color(result))
        for result, count in sorted(module.counts.items(), key=lambda item: -item[1])
    )
    title = module.name + (f" ({module.variant})" if module.variant else "")
    details = "".join(
        f"<li>{html.escape(label)} - {_badge(result, _color(result))}</li>"
        for label, result in module.checks[:_MAX_DETAILS]
    )
    extra = (
        ""
        if len(module.checks) <= _MAX_DETAILS
        else f"<li><i>+ {len(module.checks) - _MAX_DETAILS} autres contrôles</i></li>"
    )
    suffix = f" — {html.escape(module.started[:19])}" if module.started else ""
    return (
        f"<section><h2>{html.escape(title)}{suffix} {verdict}</h2>"
        f"<p>{counts}</p><ul>{details}{extra}</ul></section>"
    )


def _sort_key(module: _Module) -> tuple[int, str]:
    """Clé de tri : verdicts les plus sévères d'abord, puis ordre alphabétique."""
    rank = _VERDICTS.index(module.verdict) if module.verdict in _VERDICTS else len(_VERDICTS)
    return rank, module.name


def _summary(modules: list[_Module]) -> str:
    """Compose la ligne de synthèse (nombre de modules par verdict)."""
    totals = Counter(module.verdict for module in modules)
    return " — ".join(
        _badge(f"{totals[verdict]} {verdict}", _color(verdict))
        for verdict in _VERDICTS
        if totals[verdict]
    )


def _render(modules: list[_Module], site: Path) -> None:
    """Écrit la page index consolidée du rapport."""
    generated = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = "".join(_section(module) for module in sorted(modules, key=_sort_key))
    body = body or "<p>Aucun résultat exporté : lancer un run du workflow.</p>"
    html_content = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8"><title>PurIdentityServer - certification OIDC</title>
<style>
  body {{ font-family: sans-serif; margin: 2rem; max-width: 60rem; }}
  section {{ border-top: 1px solid #ccc; padding: 1rem 0; }}
  li {{ margin: 0.2rem 0; }}
  h2 {{ font-size: 1.05rem; }}
</style>
</head>
<body>
<h1>PurIdentityServer - attestations de conformité OIDC</h1>
<p>Suite officielle OpenID Foundation (conformance-suite). Généré le {generated}.</p>
<p><b>{len(modules)} modules</b> : {_summary(modules) or "<i>aucun verdict</i>"}</p>
{body}
</body>
</html>
"""
    site.mkdir(parents=True, exist_ok=True)
    (site / "index.html").write_text(html_content, encoding="utf-8")


def main() -> None:
    """Point d'entrée : rassemble les exports puis écrit le site statique."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", default="results", help="dossier des exports")
    parser.add_argument("--site", default="_site", help="dossier du site statique")
    args = parser.parse_args()

    results = Path(args.results)
    site = Path(args.site)
    site_results = site / "results"
    site_results.mkdir(parents=True, exist_ok=True)
    modules: list[_Module] = []
    for name, payload in _iter_exports(results):
        module = _load_module(name, payload)
        if module is None:
            continue
        modules.append(module)
        (site_results / name).write_bytes(payload)
    _render(modules, site)


if __name__ == "__main__":
    main()
