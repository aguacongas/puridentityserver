# Règles de codage — ThePurOidc

Ce guide énonce les règles de codage Python du projet. **L'arbitre machine est le
`pyproject.toml`** (config `ruff`, `mypy`, `pytest`) : en cas de doute, ce qui passe
`ruff`/`mypy` fait foi.

## Prérequis

- **Python ≥ 3.10** (cible de développement : 3.14)
- **uv** pour la gestion des dépendances (ou l'outil PyPA de ton choix)
- Outils dev : `ruff`, `mypy`, `pytest`, `pytest-cov` (voir `pyproject.toml`)

## Commandes

```bash
ruff check .                 # lint
ruff format .                # formatage
ruff check --fix .           # lint + auto-fix sûr
mypy src                     # typage strict
pytest                       # tests + couverture (min 80 %)
```

## Style et syntaxe

- **Typage explicite obligatoire** : signatures de fonctions annotées (params + retour),
  y compris les closures et les variables de module. Pas d'`Any` sauf justification
  (`# type: ignore` motivé).
- **Syntaxe moderne** :
  - unions : `str | None` (jamais `Optional[str]`)
  - génériques : `list[T]`, `dict[str, T]` (jamais `typing.List`)
  - f-strings pour toute interpolation
  - `dataclasses` pour les structs, `Pydantic` pour les modèles d'entrée/sortie
- **Nommage PEP 8** : `snake_case` fonctions/variables, `UPPER_CASE` constantes,
  `PascalCase` classes, `_privé` pour membres internes.
- **Docstrings obligatoires** (convention *google*, règle `D` de ruff) : tout module,
  classe et fonction/méthode publique doit avoir un docstring; le contenu doit décrire
  le *quoi* (le pourquoi va en commentaire), en français.
- **Formatage** (automatisé par `ruff format`) : double quotes, 4 espaces,
  100 caractères max, imports triés (`isort`).

## Configuration

- **Pas de configuration par défaut en dur dans le code** : les valeurs de démonstration
  (adresses, ports, clients seed, profils utilisateurs du `ClaimsProvider`, …) se déclarent
  dans le **`config.toml`** de la racine (table `[settings]`), pas dans `src/`. Le code ne
  déclare qu'un défaut *neutre* — l'option absente — et reçoit la configuration par injection
  (`Settings`, composition root).
- Tout nouveau paramètre (`THEPUROIDC_*`) est exposé dans `Settings`
  (`infrastructure/settings.py`), documenté dans `docs/configuration.md` et, si ses défauts
  de démonstration comptent pour l'exécution locale, déclaré dans `config.toml`.

## Sécurité

- **Jamais de secret en dur** ni de token dans les logs (utiliser `SecretStr`).
- **Pas de `print`** dans le code de production (logging via `logging` standard).
- Ceinture dédiée à la sécurité (`bandit`/`S`) : pas d'`eval`, pas de crypto maison,
  pas d'algorithmes faibles.

## Tests

- Un test par régression/bug.
- Les tests vivent dans `tests/`, nommés `test_<module>.py`.
- Couverture ≥ 80 % (défaut `fail_under` dans `pyproject.toml`).

## Processus

1. Prendre une **branch** par feature (`feat/`, `fix/`, `chore/`).
2. `ruff check . && ruff format . && mypy src && pytest` doivent passer **en local**.
3. Ouvrir une PR vers `main` — les mêmes checks tournent en CI.

## Definition of Done

Chaque feature n'est **done** que si elle respecte l'ensemble :

- [ ] **Qualité** — `scripts/check.py` vert (ruff lint+format, mypy strict, pytest ≥ 80 %)
- [ ] **Tests** — les endpoints/usecases ajoutés couvrent le nouveau code (100 % sur la
      feature de préférence)
- [ ] **SonarCloud** — aucune nouvelle issue sur le diff de la PR
- [ ] **Documentation à jour dans la même PR** :
  - [ ] `README.md` — table des endpoints, plan d'implémentation, mention de la feature
  - [ ] `docs/configuration.md` — nouveaux paramètres `THEPUROIDC_*` (par feature)
  - [ ] `docs/installation.md` — si le déploiement/lancement change
  - [ ] Disposer/vérifier les liens `#spec` de la feature

> Règle pragmatique : un PR qui modifie `src/` ou `pyproject.toml` implique au minimum une
> mise à jour du README (endpoints/plan) ou d'un doc `docs/` — la documentation n'est pas
> un « à part », elle est livrée avec la feature.

## Architecture

Le code respecte **Clean Architecture** en 4 cercles concentriques, avec la règle de
dépendance **« points always inward »** : un cercle ne dépends jamais d'un cercle
extérieur.

- **Domain** (`domain/`) — entités OIDC (`Client`, `Grant`, `Scope`, `Claims`), les règles
  métier. **Zéro dépendance** (ni FastAPI, ni PyJWT, ni framework).
- **Application** (`application/`) — cas d'utilisation : émission de code/token, validation,
  consentement, logout. Dépend du domaine seul.
- **Interface Adapters** (`interfaces/`) — ports et adaptateurs : routes FastAPI, schémas
  Pydantic (requests/réponses), abstractions de persistance (`repositories`).
- **Frameworks & Drivers** (`infrastructure/`) — PyJWT, storage concret (in-memory d'abord,
  puis SQL/Mongo), Uvicorn, TLS/proxy.

Concrètement :

- `src/thepuroidc/` — code de l'application (FastAPI).
- `tests/` — tests unitaires et d'intégration (TestClient httpx).
- **Composition root** unique (`server.py`) : c'est le seul endroit qui assemble
  infrastructure + adaptateurs + usecases (injection de dépendances).
- On n'implémente **pas** la crypto : `PyJWT` (JWT/JWS/JWA/JWK), `cryptography`
  (primitives), `FastAPI` (HTTP/TLS géré par l'infra).
