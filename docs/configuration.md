# Configuration du serveur

La configuration se fait par **variables d'environnement** (préfixe `PURIDENTITYSERVER_`), par
fichier **`.env`** placé à la racine du projet (chargé automatiquement au démarrage),
ou par le fichier **`config.toml`** du dépôt qui fournit des **défauts de démonstration**
(l'environnement reste prioritaire sur le fichier).
Elle est lue au démarrage par [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)

## Paramètres actuels

| Variable | Défaut | Description |
| --- | --- | --- |
| `PURIDENTITYSERVER_ISSUER` | `http://127.0.0.1:8000` | Identifiant public de l'émetteur : l'URL où le serveur est joignable. Doit être stable et, en production, en **HTTPS**. |
| `PURIDENTITYSERVER_BASE_URL` | *(issuer)* | Base utilisée pour construire les URL des endpoints publiées dans le document de discovery (`/authorize`, `/token`, `/userinfo`, `/.well-known/jwks.json`, …). Par défaut : l'issuer. |
| `PURIDENTITYSERVER_HOST` | `127.0.0.1` | Interface réseau sur laquelle écoute le serveur Uvicorn. |
| `PURIDENTITYSERVER_PORT` | `8000` | Port d'écoute. |
| `PURIDENTITYSERVER_KEY_STORE_TYPE` | `memory` | Type de stockage des clés de signature et du user store (`memory` pour le développement local, `sql` pour la production). |
| `PURIDENTITYSERVER_KEY_STORE_DSN` | `sqlite:///puridentityserver_keys.db` | Chaîne de connexion SQLAlchemy du stockage persistant (clés, codes, clients, utilisateurs — utilisée lorsque `KEY_STORE_TYPE=sql`). |
| `PURIDENTITYSERVER_JWKS_KEY_SIZE` | `4096` | Taille des clés RSA générées (bits) pour la signature des jetons. |
| `PURIDENTITYSERVER_JWKS_ALGORITHMS` | *(tous)* | Liste (séparée par des virgules) des algorithmes de signature fournis. Supporte `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. |
| `PURIDENTITYSERVER_JWKS_ROTATION_DAYS` | `90` | Âge à partir duquel une clé de signature est retirée du JWKS et remplacée. |
| `PURIDENTITYSERVER_JWKS_GRACE_PERIOD_DAYS` | `7` | Délai après la rotation avant suppression définitive de l'ancienne clé. |
| `PURIDENTITYSERVER_AUTHORIZATION_CODE_TTL_SECONDS` | `600` | Durée de vie du code d'autorisation (secondes) — défaut serveur, surchargée par client via `authorization_code_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). |
| `PURIDENTITYSERVER_ACCESS_TOKEN_TTL_SECONDS` | `3600` | Durée de vie de l'access token émis (secondes) — défaut serveur, surchargée par client via `access_token_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). L'`id_token` partage la même durée. |
| `PURIDENTITYSERVER_SETTINGS_FILE` | `config.toml` | Chemin du fichier TOML des défauts du projet (table `[settings]`), notamment les clients seed et les profils utilisateurs. |
| `PURIDENTITYSERVER_CLIENTS_SEED` | *(config.toml)* | Liste JSON de clients seed au démarrage (format `[{"client_id":"...","client_secret":"...","redirect_uris":["..."],"scopes":"openid","client_type":"public","session_lifetime_seconds":1800,"access_token_lifetime_seconds":120,"authorization_code_lifetime_seconds":30}]`). Champs de durée **facultatifs**, le défaut serveur s'applique si absents : `session_lifetime_seconds` (cookie de session, défaut `identity_jwt_lifetime_seconds`), `access_token_lifetime_seconds` (id_token + access_token, défaut `access_token_ttl_seconds`) et `authorization_code_lifetime_seconds` (code d'autorisation, défaut `authorization_code_ttl_seconds`). |
| `PURIDENTITYSERVER_USERS_SEED` | *(config.toml)* | Seed du user store servi par `/userinfo` (déversé dans le store au démarrage, comme `clients_seed`) : objet JSON mappant un `subject` (`sub`) à ses claims (format `{"alice": {"name": "...", "email": "...", "roles": ["admin"]}}`). Les clés `alice` / `bob` sont des sujets utilisateurs que le pont identité recopie sous l'UUID FastAPI Users correspondant (même email que `PURIDENTITYSERVER_IDENTITY_SEED_USERS`). Par défaut, `config.toml` fournit les profils démo `alice` (admin) et `bob` (user). |
| `PURIDENTITYSERVER_IDENTITY_SEED_USERS` | *(config.toml)* | Comptes de connexion du login navigateur (FastAPI Users) : objet JSON mappant un `subject` à ses identifiants (format `{"alice": {"email": "alice@example.com", "password": "..."}}`). Le serveur les crée (mot de passe haché) au démarrage via `seed_users`. Par défaut `config.toml` fournit `alice` et `bob`. |
| `PURIDENTITYSERVER_IDENTITY_JWT_LIFETIME_SECONDS` | `3600` | Durée de vie par défaut du cookie de session (surchargée par `session_lifetime_seconds` du client du flow, voir `PURIDENTITYSERVER_CLIENTS_SEED`). |

Cookie de session : signé RS256 avec une clé dédiée (`KeyUse.SESSION`,
stockée au même endroit que les clés de signature, mais **jamais publiée**
dans le JWKS). Sa rotation est calée sur `PURIDENTITYSERVER_JWKS_ROTATION_DAYS` et
`PURIDENTITYSERVER_JWKS_GRACE_PERIOD_DAYS` : une session reste valide tant que sa
clé n'a pas dépassé la période de grâce, puis force un nouveau login.

Tokens de gestion de compte (réinitialisation de mot de passe, vérification
de compte) : signés RS256 de la même façon par une clé dédiée et rotative
(`KeyUse.RESET` / `KeyUse.VERIFY`), jamais publiée dans le JWKS et sans
aucun secret statique en configuration.

Aucun secret statique n'est requis pour signer le cookie ni les jetons de
gestion de compte : plus de `identity_jwt_secret`, de
`identity_reset_password_secret` ou de `identity_verification_secret`.

### `issuer` vs `base_url`

- **`issuer`** est l'identifiant porté par les jetons émis (claim `iss`) et publié dans le
  document de discovery. C'est une valeur qui doit rester **stable dans le temps**.
- **`base_url`** est uniquement la racine de construction des URL des endpoints exposées
  dans `/.well-known/openid-configuration`. Par défaut les deux sont identiques.

### Stockage des clés et multi-instance

La variable `KEY_STORE_TYPE` définit comment l'état persistant du serveur est stocké :
clés de signature, codes d'autorisation, clients seed et **profils utilisateurs**
(user store servis par `/userinfo`). C'est le paramètre qui permet de
**loadbalancer** plusieurs instances du serveur et de reprendre après un redémarrage.

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
- `PURIDENTITYSERVER_JWKS_ALGORITHMS` permet de choisir les algorithmes fournis.
- La rotation est déclenchée à chaque lecture du JWKS : les clés plus vieilles que
  `rotation_days` sont retirées, les clés hors `grace_period_days` sont supprimées,
  et une nouvelle clé est générée si nécessaire.

## Fichier de configuration par défaut (`config.toml`)

Le dépôt embarque un `config.toml` (racine du projet) qui déclare les **défauts
de démonstration**. Sa table `[settings]` est chargée automatiquement sous les
défauts, avec la hiérarchie de priorité suivante :

```text
arguments d'init > variables d'environnement (PURIDENTITYSERVER_*) > config.toml > défauts du code
```

Le fichier contient actuellement :

- les **durées de vie par défaut** des codes d'autorisation et des jetons émis
  (`authorization_code_ttl_seconds`, `access_token_ttl_seconds`) ;
- le **client de démo du flow Authorization Code + PKCE** (`sample-pkce-client`, client
  *public*, callback `http://127.0.0.1:5173/callback`, scopes `openid profile email`) ;
- le **seed utilisateurs de démonstration** servi par `/userinfo` (clés
  `sample-pkce-client` et `web-app`, claims `name`, `email`, `address`, … filtrés selon les
  scopes accordés au token, voir OIDC Core 1.0 §5.4).

- Pour personnaliser ou ajouter des clients sans toucher au code, deux options :

  - surcharger le chemin via `PURIDENTITYSERVER_SETTINGS_FILE` (ex. copier
    `config.toml` vers `config.local.toml`, l'éditer, puis
    `PURIDENTITYSERVER_SETTINGS_FILE=config.local.toml uv run python -m puridentityserver`) ;
  - passer la liste complète par l'environnement :
    `PURIDENTITYSERVER_CLIENTS_SEED='[{"client_id": "my-app", ...}]'` (remplace `config.toml`).

> Note : `PURIDENTITYSERVER_CLIENTS_SEED` et `PURIDENTITYSERVER_USERS_SEED` **remplacent**
> les valeurs par défaut, ils ne les fusionnent pas. Déclarez l'ensemble complet.

## Exemples

### Lancement local simple (en mémoire)

```sh
PURIDENTITYSERVER_ISSUER=http://127.0.0.1:8000 uv run python -m puridentityserver
```

### Stockage SQL pour la production

```sh
PURIDENTITYSERVER_ISSUER=https://id.example.com
PURIDENTITYSERVER_KEY_STORE_TYPE=sql
PURIDENTITYSERVER_KEY_STORE_DSN=postgresql+asyncpg://puridentityserver:secret@db-host/puridentityserver
```

### Derrière un reverse proxy TLS

```sh
PURIDENTITYSERVER_ISSUER=https://id.example.com uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

## Notes d'implémentation

- Les clés privées sont stockées en texte PEM ; le repository SQL utilise une table
  `key_pairs` avec une colonne `kid` (identifiant unique, clé primaire) et une colonne
  `is_active` (booléen) pour gérer la rotation.
- Les contrats (ports) de gestion des clés (`KeyManager`), de persistance
  (`KeyPairRepository`, `ClientRepository`, `AuthorizationCodeRepository`,
  `UserRepository`) sont des Protocol vivant dans `puridentityserver/interfaces/` ; chaque
  store est décliné en deux implémentations — `memory` (dictionnaire process-local)
  et `sql` (SQLAlchemy 2.0 asynchrone) — choisies via `KEY_STORE_TYPE`.
  Des implémentations Redis et MongoDB peuvent être ajoutées comme extras optionnels.
- Les endpoints `/authorize` et `/token` supportent le flux Authorization Code
  avec PKCE (S256), conformes aux RFC 6749 et 7636. Les clients publics
  doivent utiliser PKCE. Les secrets sont hashés SHA-256 (jamais stockés en clair).
- L'endpoint `/userinfo` valide l'access token Bearer (signature JWKS, `iss`,
  `exp`) puis renvoie les claims filtrés par les scopes accordés au jeton
  (OIDC Core 1.0 §5.4). Les claims sont résolus par un `ClaimsProvider`
  (`interfaces/domain/userinfo.py`) dont l'implémentation livrée
  (`infrastructure/claims.py`) délègue au **user store** (`UserRepository`),
  alimenté au démarrage depuis le seed déclaré dans la configuration
  (`PURIDENTITYSERVER_USERS_SEED`).
- Toutes les opérations sont asynchrones (`async/await`), compatibles avec l'event loop
  de FastAPI.
