# Configuration du serveur

La configuration se fait par **variables d'environnement** (préfixe `THEPUROIDC_`), par
fichier **`.env`** placé à la racine du projet (chargé automatiquement au démarrage),
ou par le fichier **`config.toml`** du dépôt qui fournit des **défauts de démonstration**
(l'environnement reste prioritaire sur le fichier).
Elle est lue au démarrage par [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)

## Paramètres actuels

| Variable | Défaut | Description |
| --- | --- | --- |
| `THEPUROIDC_ISSUER` | `http://localhost:8000` | Identifiant public de l'émetteur : l'URL où le serveur est joignable. Doit être stable et, en production, en **HTTPS**. |
| `THEPUROIDC_BASE_URL` | *(issuer)* | Base utilisée pour construire les URL des endpoints publiées dans le document de discovery (`/authorize`, `/token`, `/userinfo`, `/.well-known/jwks.json`, …). Par défaut : l'issuer. |
| `THEPUROIDC_HOST` | `127.0.0.1` | Interface réseau sur laquelle écoute le serveur Uvicorn. |
| `THEPUROIDC_PORT` | `8000` | Port d'écoute. |
| `THEPUROIDC_KEY_STORE_TYPE` | `memory` | Type de stockage des clés de signature (`memory` pour le développement local, `sql` pour la production). |
| `THEPUROIDC_KEY_STORE_DSN` | `sqlite:///thepuroidc_keys.db` | Chaîne de connexion SQLAlchemy du magasin de clés (utilisée lorsque `KEY_STORE_TYPE=sql`). |
| `THEPUROIDC_JWKS_KEY_SIZE` | `4096` | Taille des clés RSA générées (bits) pour la signature des jetons. |
| `THEPUROIDC_JWKS_ALGORITHMS` | *(tous)* | Liste (séparée par des virgules) des algorithmes de signature fournis. Supporte `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. |
| `THEPUROIDC_JWKS_ROTATION_DAYS` | `90` | Âge à partir duquel une clé de signature est retirée du JWKS et remplacée. |
| `THEPUROIDC_JWKS_GRACE_PERIOD_DAYS` | `7` | Délai après la rotation avant suppression définitive de l'ancienne clé. |
| `THEPUROIDC_AUTHORIZATION_CODE_TTL_SECONDS` | `600` | Durée de vie du code d'autorisation (secondes). |
| `THEPUROIDC_ACCESS_TOKEN_TTL_SECONDS` | `3600` | Durée de vie de l'access token émis (secondes). |
| `THEPUROIDC_SETTINGS_FILE` | `config.toml` | Chemin du fichier TOML des défauts du projet (table `[settings]`), notamment les clients seed. |
| `THEPUROIDC_CLIENTS_SEED` | *(config.toml)* | Liste JSON de clients seed au démarrage (format `[{"client_id":"...","client_secret":"...","redirect_uris":["..."],"scopes":"openid","client_type":"public"}]`). Par défaut, `config.toml` fournit le client de démo `sample-pkce-client`. |
| `THEPUROIDC_USERINFO_PROFILES` | *(config.toml)* | Annuaire des profils utilisateurs servis par `/userinfo` : objet JSON mappant un `subject` (`sub`) à ses claims (format `{"web-app": {"name": "...", "email": "..."}}`). Par défaut, `config.toml` fournit les profils de démo des clients `sample-pkce-client` et `web-app`. |

### `issuer` vs `base_url`

- **`issuer`** est l'identifiant porté par les jetons émis (claim `iss`) et publié dans le
  document de discovery. C'est une valeur qui doit rester **stable dans le temps**.
- **`base_url`** est uniquement la racine de construction des URL des endpoints exposées
  dans `/.well-known/openid-configuration`. Par défaut les deux sont identiques.

### Stockage des clés et multi-instance

La variable `KEY_STORE_TYPE` définit comment les clés de signature sont persistées.
C'est le paramètre qui permet de **loadbalancer** plusieurs instances du serveur
et de reprendre après un redémarrage.

| `KEY_STORE_TYPE` | Comportement | Usage |
| --- | --- | --- |
| `memory` | Stockage en mémoire (Process-local, sans persistance) | Développement local, tests unitaires |
| `sql` | Stockage SQL via SQLAlchemy (SQLite, PostgreSQL, MySQL) | Production, load balancing multi-instance |

**Chargement de la DSN** : quand le type est `sql`, le DSN `KEY_STORE_DSN` est
réécrit automatiquement vers le dialecte asynchrone (ex. `sqlite:///keys.db` →
`sqlite+aiosqlite:///keys.db`).

### Clés RSA et ECDSA (JWKS)

- Au démarrage, une clé est générée **par algorithme configuré** et exposée sur
  `/.well-known/jwks.json` (format JWK, champs `kty`, `kid`, `use`, `alg`, plus `n`/`e`
  pour RSA, `crv`/`x`/`y` pour EC).
- `THEPUROIDC_JWKS_ALGORITHMS` permet de choisir les algorithmes fournis.
- La rotation est déclenchée à chaque lecture du JWKS : les clés plus vieilles que
  `rotation_days` sont retirées, les clés hors `grace_period_days` sont supprimées,
  et une nouvelle clé est générée si nécessaire.

## Fichier de configuration par défaut (`config.toml`)

Le dépôt embarque un `config.toml` (racine du projet) qui déclare les **défauts
de démonstration**. Sa table `[settings]` est chargée automatiquement sous les
défauts, avec la hiérarchie de priorité suivante :

```text
arguments d'init > variables d'environnement (THEPUROIDC_*) > config.toml > défauts du code
```

Le fichier ne contient actuellement :

- le **client de démo du flow Authorization Code + PKCE** (`sample-pkce-client`, client
  *public*, callback `http://127.0.0.1:5173/callback`, scopes `openid profile email`) ;
- les **profils utilisateurs de démonstration** servis par `/userinfo` (clés
  `sample-pkce-client` et `web-app`, claims `name`, `email`, `address`, … filtrés selon les
  scopes accordés au token, voir OIDC Core 1.0 §5.4).

- Pour personnaliser ou ajouter des clients sans toucher au code, deux options :

  - surcharger le chemin via `THEPUROIDC_SETTINGS_FILE` (ex. copier
    `config.toml` vers `config.local.toml`, l'éditer, puis
    `THEPUROIDC_SETTINGS_FILE=config.local.toml uv run python -m thepuroidc`) ;
  - passer la liste complète par l'environnement :
    `THEPUROIDC_CLIENTS_SEED='[{"client_id": "my-app", ...}]'` (remplace `config.toml`).

> Note : `THEPUROIDC_CLIENTS_SEED` et `THEPUROIDC_USERINFO_PROFILES` **remplacent**
> les valeurs par défaut, ils ne les fusionnent pas. Déclarez l'ensemble complet.

## Exemples

### Lancement local simple (en mémoire)

```sh
THEPUROIDC_ISSUER=http://localhost:8000 uv run python -m thepuroidc
```

### Stockage SQL pour la production

```sh
THEPUROIDC_ISSUER=https://id.example.com
THEPUROIDC_KEY_STORE_TYPE=sql
THEPUROIDC_KEY_STORE_DSN=postgresql+asyncpg://thepuroidc:secret@db-host/thepuroidc
```

### Derrière un reverse proxy TLS

```sh
THEPUROIDC_ISSUER=https://id.example.com uv run uvicorn thepuroidc.server:app --host 127.0.0.1 --port 8000
```

## Notes d'implémentation

- Les clés privées sont stockées en texte PEM ; le repository SQL utilise une table
  `key_pairs` avec une colonne `kid` (identifiant unique, clé primaire) et une colonne
  `is_active` (booléen) pour gérer la rotation.
- Les contrats (ports) de gestion des clés (`KeyManager`), de persistance
  (`KeyPairRepository`), des clients (`ClientRepository`) et des codes
  d'autorisation (`AuthorizationCodeRepository`) sont des Protocol vivant
  dans `thepuroidc/interfaces/` ; seules les implémentations `memory` et `sql`
  sont livrées dans cette version.
  Des implémentations Redis et MongoDB peuvent être ajoutées comme extras optionnels.
- Les endpoints `/authorize` et `/token` supportent le flux Authorization Code
  avec PKCE (S256), conformes aux RFC 6749 et 7636. Les clients publics
  doivent utiliser PKCE. Les secrets sont hashés SHA-256 (jamais stockés en clair).
- L'endpoint `/userinfo` valide l'access token Bearer (signature JWKS, `iss`,
  `exp`) puis renvoie les claims filtrés par les scopes accordés au jeton
  (OIDC Core 1.0 §5.4). Les claims sont résolus par un `ClaimsProvider`
  (`interfaces/domain/userinfo.py`) dont l'implémentation livrée est un
  annuaire **en mémoire** (`infrastructure/claims.py`), alimenté par les
  profils déclarés dans la configuration (`THEPUROIDC_USERINFO_PROFILES`) —
  prête à être remplacée par un vrai user store.
- Toutes les opérations sont asynchrones (`async/await`), compatibles avec l'event loop
  de FastAPI.
