# AGENTS.md — PurIdentityServer

Instructions à respecter systématiquement (outre `CONTRIBUTING.md`, qui fait autorité pour
les règles de codage).

## Qualité (gates CI, à passer en local avant tout push)

```bash
uv run ruff check .                      # lint
uv run ruff format .                     # formatage
uv run python -m mypy src                # typage strict (pas `uv run mypy`: bug trampoline uv)
uv run python -m pytest -p no:cacheprovider -q   # tests + couverture >= 80 % (95 % attendu)
```

- CI = Python 3.13, `uv sync --extra dev --extra sql --locked`.
- SonarCloud analyse le diff de chaque PR : **aucune nouvelle issue acceptée** (DoD).
- Windows/PowerShell : pas de heredoc shell ; utiliser `--body-file` pour les loads dans gh.

## Complexité cognitive (SonarCloud S3776) — piège récurrent

Le linter SonarCompute Python `python:S3776` compte la complexité cognitive de chaque
fonction, **y compris le corps des fonctions imbriquées**. Seuil : **≤ 15**. Une PR qui
corrige un smell S3776 précédent doit rester **en dessous du seuil**.

Piège vécu : `create_app` (composition root dans `server.py`) a dépassé 17 parce que les
closures `_lifespan` et `_resolve_session_lifetime` étaient imbriquées dedans.

Règle à appliquer d'office :
- **Ne pas imbriquer de fonctions dans la composition root** (`server.py`) ni dans toute
  fonction qui a déjà du nesting. Sortir les closures/fonctions internes au niveau module.
- Extraction dans un **conteneur de dépendances** (base `_Dependencies`) ou un helper de
  module est la solution validée (cf. `server.py`).
- Après refactor, vérifier : règle S3776 sur le diff SonarCloud de la PR, pas seulement
  lint/mypy/tests.

## Conventions rapides

- Pas d'emojis, pas de commentaires superflus ; docstrings google en français sur tout
  module/classe/fonction/méthode publique.
- Pas de config de démo dans `src/` : tout s'injecte via `Settings` / composition root,
  valeurs seed dans `config.toml`.
- N'implémenter la crypto que via `PyJWT` / `cryptography` — jamais à la main.
- Commits : style français, `feat(oidc):`, `fix:`, `chore:` — ne commit/push que si demandé.