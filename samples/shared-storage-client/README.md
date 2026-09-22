# Sample — stockage SQL partagé entre protocole et administration

Ce sample démontre un **déploiement séparé** (deux processus) dont les serveurs
`protocol` et `admin` partagent le **même stockage SQL** (`storage_type = "sql"`)
: aucune ressource n'est dupliquée, chaque instance lit et écrit dans la même
base. Le serveur `admin` ne connaît pas les clés du `protocol` : il valide les
jetons de gestion **à distance** via le JWKS publié par le protocole.

Aucune connaissance préalable du projet n'est nécessaire : suivez les étapes.

## Ce que fait le sample

- `client.py` : démo CLI — obtient un jeton `client_credentials` `scope=admin`
  sur le protocole, lit les ApiResources via l'administration, crée une
  IdentityResource et une ApiResource, puis vérifie que le **discovery du
  protocole** (autre processus, sans redémarrage) les publie aussitôt, avant
  de les retirer.
- `smoke_test.py` : scénario automatique de bout en bout avec **deux serveurs
  sur un même fichier SQLite** (chemin temporaire) :
  - serveur A (`role = protocol`, port 8111) : émet les jetons, publie
    discovery/JWKS, seede les resources, n'expose **pas** les CRUD ;
  - serveur B (`role = admin`, port 8112) : applique les CRUD sur la **même
    base**, valide les jetons de A **à distance** (JWKS distant).

## Prérequis

- Python 3.13 et [uv](https://docs.astral.sh/uv/) installés ;
- les dépendances avec le support SQL : `uv sync --extra dev --extra sql`
  (à la racine du dépôt).

## 1. Démo manuelle (deux serveurs, un fichier SQLite)

Créez d'abord une base vide (chemin libre, ex. `C:\tmp\shared.db`) :

```sh
New-Item -ItemType Directory -Force C:\tmp | Out-Null
```

**Terminal 1 — serveur protocole** (port 8111) :

```powershell
$env:PURIDENTITYSERVER_ROLE = "protocol"
$env:PURIDENTITYSERVER_PORT = "8111"
$env:PURIDENTITYSERVER_ISSUER = "http://127.0.0.1:8111"
$env:PURIDENTITYSERVER_STORAGE_TYPE = "sql"
$env:PURIDENTITYSERVER_STORAGE_DSN = "sqlite:///C:/tmp/shared.db"
uv run python -m puridentityserver
```

**Terminal 2 — serveur administration** (port 8112, même base) :

```powershell
$env:PURIDENTITYSERVER_ROLE = "admin"
$env:PURIDENTITYSERVER_PORT = "8112"
$env:PURIDENTITYSERVER_ISSUER = "http://127.0.0.1:8112"
$env:PURIDENTITYSERVER_STORAGE_TYPE = "sql"
$env:PURIDENTITYSERVER_STORAGE_DSN = "sqlite:///C:/tmp/shared.db"
$env:PURIDENTITYSERVER_MANAGEMENT_JWT_ISSUER = "http://127.0.0.1:8111"
$env:PURIDENTITYSERVER_MANAGEMENT_JWT_JWKS_URL = "http://127.0.0.1:8111/.well-known/jwks.json"
uv run python -m puridentityserver
```

> La configuration par défaut (`config.toml`) seede déjà le client
> `sample-admin-client` (scope `admin`) et l'ApiResource `management` : le
> jeton d'administration du client CLI fonctionne sans paramètre
> supplémentaire.

**Terminal 3 — client de démonstration** :

```sh
uv run python samples/shared-storage-client/client.py
```

Résultat attendu (ordre des scopes : liste triée) :

```text
Discovery http://127.0.0.1:8111 : scopes_supported = [... 'admin' 'billing.read' ...]
POST http://127.0.0.1:8111/token -> HTTP 200
GET http://127.0.0.1:8112/api-resources -> HTTP 401
GET http://127.0.0.1:8112/api-resources -> HTTP 200
  ApiResources lues côté administration : ['management', 'sample-api']
POST http://127.0.0.1:8112/identity-resources -> HTTP 201
POST http://127.0.0.1:8112/api-resources -> HTTP 201
Discovery http://127.0.0.1:8111 : scopes_supported = [... 'cli.read' 'cli-shared-identity' ...]
  Nouveaux scopes apparus côté protocole (état partagé) : ['cli-shared-identity', 'cli.read']
DELETE http://127.0.0.1:8112/identity-resources/cli-shared-identity -> HTTP 204
DELETE http://127.0.0.1:8112/api-resources/cli-shared-api -> HTTP 204
  Resources retirées côté administration.
```

Le scope `cli.read` (porté par l'ApiResource créée sur le port 8112) apparaît
dans le discovery du **port 8111** : les deux processus partagent le même état.

## 2. Scénario automatique

```sh
uv run python samples/shared-storage-client/smoke_test.py
```

Le test démarre les deux serveurs sur un fichier SQLite temporaire et vérifie
créations/suppressions visibles des deux côtés sans redémarrage :

```text
  [1/10] serveur A (role=protocol, stockage SQL partagé) : discovery + JWKS ; billing.read seedé -> [...]
  [2/10] A : GET /api-resources -> 404 (pas de CRUD en mode protocol)
  [3/10] A : émission du jeton scope=admin (client_credentials)
  [4/10] B : GET /api-resources sans jeton -> 401 (WWW-Authenticate: Bearer)
  [5/10] B : lit la resource seedée par A via la base partagée -> ['billing', 'management']
  [6/10] B : jeton non admin (billing.read) -> 401
  [7/10] serveur B (role=admin, même SQL) : ni discovery ni /token sur http://127.0.0.1:8112
  [8/10] B : création shared-identity (201) et shared-api (201)
  [9/10] A : discovery mis à jour sans redémarrage -> shared-identity + shared.read/shared.write présents
  [10/10] A : suppression visible côté protocole -> [...]
=== SCÉNARIO OK en ...s ===
```

## 3. Configuration équivalente (fichier `config.toml` commun)

Les deux serveurs partagent la base via `storage_dsn`, le protocole seul publie
les key/métadonnées, et l'administration valide les jetons à distance :

```toml
[settings]
role = "admin"
storage_type = "sql"
storage_dsn = "sqlite:///C:/tmp/shared.db"
management_jwt_issuer = "http://127.0.0.1:8111"
management_jwt_jwks_url = "http://127.0.0.1:8111/.well-known/jwks.json"
admin_required_claim = "scope"
admin_required_claim_values = ["admin"]
```

Notez qu'avec `storage_type = "memory"` (défaut), chaque processus possède son
propre état en mémoire : cette démonstration **exige** `storage_type = "sql"`.

## Références

- `role`, `management_jwt_*`, `admin_required_claim*` :
  [docs/configuration.md](../../docs/configuration.md).
- Entrée en matière sur les trois rôles (`full`, `protocol`, `admin`) :
  [docs/installation.md](../../docs/installation.md).