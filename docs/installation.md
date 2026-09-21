# Installation

## Prérequis

- **Python ≥ 3.10** (testé sur 3.13)
- **uv** — gestionnaire de dépendances Python : <https://docs.astral.sh/uv/getting-started/installation/>
- **Git**

## 1. Récupérer le code

```sh
git clone git@github.com:aguacongas/puridentityserver.git
cd PurIdentityServer
```

## 2. Installer les dépendances

```sh
uv sync          # dépendances de production
uv sync --extra dev   # + outils de qualité (ruff, mypy, pytest…) pour le développement
```

## 3. Lancer le serveur

```sh
uv run python -m puridentityserver
```

Le serveur écoute sur `http://127.0.0.1:8000` (surchargeable via `PURIDENTITYSERVER_HOST` / `PURIDENTITYSERVER_PORT`).

Vérification :

```sh
curl http://127.0.0.1:8000/.well-known/openid-configuration
```

Un document JSON contenant l'`issuer` et les endpoints doit être retourné.

## 4. Installer sans source (wheel)

Construire et installer la distribution :

```sh
uv build                     # génère dist/puridentityserver-*.whl et -*.tar.gz
uv pip install dist/puridentityserver-*.whl
```

Démarrage :

```sh
uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

Le point d'entrée ci-dessus est une **façade** : il délègue la composition au
serveur sélectionné par le réglage `role` (défaut `full`, voir
`docs/configuration.md`). Chaque rôle est aussi déployable indépendamment via
son propre point d'entrée :

- `role = "full"` (défaut) → `puridentityfull.server:app` : protocole OIDC/OAuth
  **et** administration par-dessus les mêmes stores (mémoire seule ou SQL partagé,
  mono-processus) ;
- `role = "protocol"` → `puridentityprotocol.server:app` : endpoints OIDC/OAuth
  et identité, accès en **lecture seule** aux resources administrées ;
- `role = "admin"` → `puridentityadmin.server:app` : CRUD des
  IdentityResources/ApiResources, sans aucun endpoint OIDC/OAuth.

En production, deux processus séparés (`protocol` + `admin`) partagent le même
état via `storage_type = "sql"` ; on monte alors chaque point d'entrée explicite :

```sh
uv run uvicorn puridentityprotocol.server:app --host 127.0.0.1 --port 8001
uv run uvicorn puridentityadmin.server:app  --host 127.0.0.1 --port 8002
```

## 5. Déployer en production

Le projet **ne gère pas TLS lui-même** (choix d'architecture : la crypto de transport est
confiée à l'infrastructure). Le déploiement recommandé est donc derrière un reverse proxy
(nginx, Caddy, Traefik) qui termine le TLS :

```text
Client ──HTTPS──> Reverse proxy (TLS) ──HTTP──> PurIdentityServer (127.0.0.1:8000)
```

Points clés :

- Définir `PURIDENTITYSERVER_ISSUER` sur **l'URL publique HTTPS** du serveur (l'un des identifiants
  que la spec exige de publier). Il servira de base aux URL des endpoints.
- L'issuer doit être stable dans le temps : changer d'URL publique invalide les
  `id_token` et access tokens émis précédemment.
- Le stockage est **en mémoire** par défaut (`storage_type = "memory"`) : l'état
  (clés de signature, clients, codes, jetons…) est perdu au redémarrage et
  local à chaque processus. Pour la production, passer à un **backend SQL**
  partagé (voir ci-dessous) afin de supporter plusieurs workers / instances
  loadbalancées et de reprendre après un redémarrage.

### 5.b Persistance SQL (production multi-instance)

Installer les dépendances SQL puis choisir le backend :

```sh
uv sync --extra sql
```

```sh
# SQLite (fichier local, simple / monoprocess)
export PURIDENTITYSERVER_STORAGE_TYPE=sql
export PURIDENTITYSERVER_STORAGE_DSN=sqlite:///puridentityserver.db

# PostgreSQL (recommandé pour le multi-instance)
export PURIDENTITYSERVER_STORAGE_TYPE=sql
export PURIDENTITYSERVER_STORAGE_DSN=postgresql://puridentityserver:secret@db-host/puridentityserver

# MySQL
export PURIDENTITYSERVER_STORAGE_TYPE=sql
export PURIDENTITYSERVER_STORAGE_DSN=mysql://puridentityserver:secret@db-host/puridentityserver
```

Le DSN est réécrit automatiquement vers le dialecte **asynchrone**
(`sqlite`→`aiosqlite`, `postgresql`→`asyncpg`, `mysql`→`aiomysql`) ;
attendre le driver correspondant (fourni par `--extra sql` pour SQLite et
PostgreSQL). Le schéma est créé au démarrage (`create_all`) ; les colonnes
ajoutées par une version plus récente sont migrées par `ALTER TABLE ADD
COLUMN` sans toucher aux données.

Exemple minimal derrière nginx :

```sh
export PURIDENTITYSERVER_ISSUER=https://id.example.com
uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

```nginx
server {
    listen 443 ssl;
    server_name id.example.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Dépannage

| Symptôme | Cause probable |
| --- | --- |
| `No module named puridentityserver` | commande lancée hors du répertoire du projet, ou `uv sync` non exécuté |
| Le CI Sonar échoue | secret `SONAR_SECRET` non défini sur le dépôt GitHub (voir `docs/configuration.md`) |
