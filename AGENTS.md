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

- **Harness local (mode courant)** : la suite de conformance OIDF tourne en docker
  sur le runner, OP local derrière un nginx mTLS — workflow
  `.github/workflows/certification-local.yml`, matrix des 11 plans (basic,
  implicit, hybrid, formpost, dynamic, ciba, fapi1, fapi2, fapi2-message-signing,
  ekyc, federation), mode *witness*
  (les gaps module ne
  bloquent pas), déclenché sur chaque PR vers `main` touchant `certification/**`
  ou à la demande (`workflow_dispatch`, filtre de plan).
  **Toujours utiliser la dernière release publiée de la suite** : la version par
  défaut vit dans `SUITE_VERSION` (`certification/local/setup.sh`) ; avant chaque
  usage/rejeu, vérifier qu'une release plus récente n'est pas publiée et bumper
  `SUITE_VERSION` + la doc (`certification/README.md`) en conséquence, puis
  rejouer les 11 plans pour valider le bump. Ne jamais fixer une version
  périmée dans la doc ou les scripts.
- **Run hébergé officiel OIDF** : `.github/workflows/certification.yml` (secret
  `CONFORMANCE_TOKEN`, publication GitHub Pages) — reste la référence finale de
  certification. Il joue les **11 plans** : les 9 du programme officiel **plus**
  `ekyc` (identité assurance) et `federation` (OpenID Federation 1.1), hors
  programme officiel — choix du
  maintainer : l'assurance conformité vaut aussi pour la spec de niche) —
  en **mode strict** (seuls les modules SUCCESS/REVIEW sont acceptés ; tout
  autre module met le job en échec) et en **deux vagues** : `dynamic` seul
  d'abord (il est seul à déclencher la rotation des clés de signature de
  l'OP partagé, qui casserait les validations des autres plans en cours),
  puis les 10 autres plans en parallèle.
- L'ancien rejeu pytest `tests/conformance/` a été supprimé ; le mini-RP client
  (harness de parcours) vit dans `samples/oidc_harness/` et sert les smoke
  tests `samples/fapi1-client/` et `samples/fapi2-client/`.

### Tests de certification en local (au cas où)

Procédure établie pour rejouer les plans sans passer par la CI — se lancer
depuis **git-bash** (jamais PowerShell) :

```bash
bash certification/local/setup.sh            # bootstrap idempotent : clone de la suite, docker, OP, nginx mTLS
bash certification/local/run-plan.sh basic   # 1 plan en sortie stricte (log + exports)
bash certification/local/down.sh             # arrêt du harness (--purge : conteneurs + clone)
```

- Plans : `basic | implicit | hybrid | formpost | dynamic | ciba | fapi1 | fapi2 | fapi2-message-signing | ekyc | federation`. `run-plan.sh` fait la
  readiness (bootstrap via `setup.sh` si le harness est absent), applique les 6 patches
  driver par `prepare-suite.sh` (idempotent), substitue les URLs locales puis joue le
  driver officiel en sortie stricte ; log : `.harness-local/last-<plan>.log`,
  exports : `.harness-local/results/<plan>` (ou `--export-dir`).
- **Bilan local = exports du run courant seulement** : le dossier d'export local accumule
  les sessions précédentes (le zip porte un id aléatoire + la date) ; `run-plan.sh`
  instantanie les archives présentes avant le driver et ne compte que les nouvelles
  (les anciennes sont conservées). Sans cette restriction, le bilan mélange les runs
  (issue #199). La CI est immunisée : dossier d'export neuf par job.
- Captures REVIEW : produire les 13 PNG avec
  `python certification/capture_screenshots.py --base-url https://localhost:9443 --out <dir>`
  (le plan `federation` n'attend plus qu'une capture :
  `invalid-client-id-in-request-object`, rejouée de façon autonome depuis l'issue #212 —
  les 12 autres modules tournent en SUCCESS depuis l'issue #211, l'erreur d'un request
  object refusé repart par redirection),
  puis `SCREENSHOTS_DIR=<dir> bash certification/local/run-plan.sh <plan>` ; sans
  `SCREENSHOTS_DIR`, le driver retombe sur le PNG de secours (mode witness) ; avec,
  toute capture absente le fait échouer (issue #161, comportement CI attendu).
- Écarts de modules connus (capacités OP absentes, module manuel) : les déclarer dans
  `certification/expected-failures/<plan>.json` (appliqué automatiquement par
  `run-plan.sh` et la CI ; seul un échec **inattendu** fait échouer). Un module que
  l'OP **saute** faute de capacité se déclare dans le pendant `<plan>-skips.json`
  (même format, `--expected-skips-file`). Purger une entrée
  dès qu'elle n'est plus consommée : le driver échec `NOT_HAPPEN` sinon.
- La CI (`certification-local.yml`) rejoue ces mêmes scripts : toute évolution de la
  procédure doit rester alignée entre local et workflow.
- **Il n'est pas interdit d'améliorer cette procédure** si un besoin se manifeste
  (script, étape, documentation) : faire évoluer les scripts locaux et tenir
  AGENTS.md + `certification/README.md` à jour en conséquence.

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