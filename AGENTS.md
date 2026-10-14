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

## Certification OIDC (suite officielle)

- **Harness local (mode courant)** : la suite `release-v5.2.4` tourne en docker
  sur le runner, OP local derrière un nginx mTLS — workflow
  `.github/workflows/certification-local.yml`, matrix des 6 plans (basic,
  implicit, hybrid, ciba, fapi1, fapi2), mode *witness* (les gaps module ne
  bloquent pas), déclenché sur chaque PR vers `main` touchant `certification/**`
  ou à la demande (`workflow_dispatch`, filtre de plan).
- **Run hébergé officiel OIDF** : `.github/workflows/certification.yml` (secret
  `CONFORMANCE_TOKEN`, publication GitHub Pages) — reste la référence finale de
  certification.
- L'ancien rejeu pytest `tests/conformance/` a été supprimé ; le mini-RP client
  (harness de parcours) vit dans `samples/oidc_harness/` et sert les smoke
  tests `samples/fapi1-client/` et `samples/fapi2-client/`.

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
- **Chaque PR référence une issue** : créer l'issue d'abord (titre + corps décrivant le
  besoin et les critères d'acceptation) avant d'ouvrir la PR ; la mentionner dans la
  description (`Closes #NN`). Pas d'issue = pas de PR.
- **Ne jamais merger une PR** : attendre la confirmation explicite de l'utilisateur avant
  `gh pr merge` (créer la branche, push, ouvrir la PR et surveiller la CI sont autorisés ;
  le merge attend toujours un feu vert de l'utilisateur).

## Échantillon de démonstration (DoD)

Chaque feature implémentée doit être testable par un utilisateur **qui ne connaît pas le
projet** : fournir un sample dans `samples/` (dossier `samples/<feature>-client/` avec README
pas-à-pas : lancement, config, résultat attendu) qui exerce le flux/endpoint de la feature,
ou documenter l'exercice dans un sample existant quand il couvre déjà le sujet (cf.
`samples/*-client/`, un par flow). Pas de sample = la PR n'est pas done.