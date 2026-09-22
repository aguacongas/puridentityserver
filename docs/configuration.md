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
| `PURIDENTITYSERVER_STORAGE_TYPE` | `memory` | Type de stockage de l'état persistant du serveur (clés de signature, clients, codes d'autorisation, utilisateurs). `memory` pour le développement local, `sql` pour la production. |
| `PURIDENTITYSERVER_STORAGE_DSN` | `sqlite:///puridentityserver.db` | Chaîne de connexion SQLAlchemy du stockage persistant — utilisée lorsque `STORAGE_TYPE=sql`. |
| `PURIDENTITYSERVER_JWKS_KEY_SIZE` | `4096` | Taille des clés RSA générées (bits) pour la signature des jetons. |
| `PURIDENTITYSERVER_JWKS_ALGORITHMS` | *(tous)* | Liste (séparée par des virgules) des algorithmes de signature fournis. Supporte `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`. |
| `PURIDENTITYSERVER_JWKS_ROTATION_DAYS` | `90` | Âge à partir duquel une clé de signature est retirée du JWKS et remplacée. |
| `PURIDENTITYSERVER_JWKS_GRACE_PERIOD_DAYS` | `7` | Délai après la rotation avant suppression définitive de l'ancienne clé. |
| `PURIDENTITYSERVER_JWKS_ENCRYPTION_ALGORITHMS` | *(tous)* | Algorithmes de gestion de clé JWE annoncés au discovery (`id_token_encryption_alg_values_supported`). Supporte `RSA-OAEP`, `RSA-OAEP-256`, `A128KW`, `A256KW`, `dir`. Les clients choisissent via `id_token_encrypted_response_alg` (voir `PURIDENTITYSERVER_CLIENTS_SEED` et `/register`). |
| `PURIDENTITYSERVER_JWKS_ENCRYPTION_METHODS` | *(tous)* | Méthodes de chiffrement du contenu JWE annoncées au discovery (`id_token_encryption_enc_values_supported`). Supporte `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`. Les clients choisissent via `id_token_encrypted_response_enc` ; une méthode absente retombe sur `A128CBC-HS256`. |
| `PURIDENTITYSERVER_AUTHORIZATION_CODE_TTL_SECONDS` | `600` | Durée de vie du code d'autorisation (secondes) — défaut serveur, surchargée par client via `authorization_code_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). |
| `PURIDENTITYSERVER_ACCESS_TOKEN_TTL_SECONDS` | `3600` | Durée de vie de l'access token émis (secondes) — défaut serveur, surchargée par client via `access_token_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). L'`id_token` partage la même durée. |
| `PURIDENTITYSERVER_REFRESH_TOKEN_TTL_SECONDS` | `2592000` | Durée de vie du refresh token émis (30 jours, en secondes) — défaut serveur, surchargée par client via `refresh_token_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). Un refresh token n'est émis que si le scop `offline_access` a été accordé ; chaque usage le consomme (rotation). |
| `PURIDENTITYSERVER_DEVICE_CODE_TTL_SECONDS` | `900` | Durée de vie du device code (secondes) — la fenêtre pendant laquelle l'utilisateur peut autoriser l'appareil sur la page de vérification avant expiration. Défaut serveur, surchargée par client via `device_code_lifetime_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). |
| `PURIDENTITYSERVER_DEVICE_CODE_INTERVAL_SECONDS` | `5` | Intervalle minimal conseillé (secondes) entre deux polls du client sur `/token` avec le grant `urn:ietf:params:oauth:grant-type:device_code`. Le serveur retourne `slow_down` si le client interroge plus vite, et augmente cet intervalle de 5 secondes à chaque fois. Défaut serveur, surchargée par client via `device_code_interval_seconds` (voir `PURIDENTITYSERVER_CLIENTS_SEED`). |
| `PURIDENTITYSERVER_SETTINGS_FILE` | `config.toml` | Chemin du fichier TOML des défauts du projet (table `[settings]`), notamment les clients seed et les profils utilisateurs. |
| `PURIDENTITYSERVER_CLIENTS_SEED` | *(config.toml)* | Liste JSON de clients seed au démarrage (format `[{"client_id":"...","client_secret":"...","redirect_uris":["..."],"post_logout_redirect_uris":["..."],"web_origins":["..."],"scopes":"openid offline_access","client_type":"public","session_lifetime_seconds":1800,"access_token_lifetime_seconds":120,"authorization_code_lifetime_seconds":30,"refresh_token_lifetime_seconds":3600,"device_code_lifetime_seconds":300,"device_code_interval_seconds":2,"par_required":true,"require_consent":true}]`). `post_logout_redirect_uris` limite les URI de retour acceptées sur `/end_session` (RP-Initiated Logout) — absent = aucune redirection de sortie possible. `web_origins` déclare des origines supplémentaires autorisées en CORS au-delà de celles déduites des `redirect_uris` (OAuth 2.0 for Browser-Based Apps) — facultatif. Champs de durée **facultatifs**, le défaut serveur s'applique si absents : `session_lifetime_seconds` (cookie de session, défaut `identity_jwt_lifetime_seconds`), `access_token_lifetime_seconds` (id_token + access_token, défaut `access_token_ttl_seconds`), `authorization_code_lifetime_seconds` (code d'autorisation, défaut `authorization_code_ttl_seconds`), `refresh_token_lifetime_seconds` (refresh token, défaut `refresh_token_ttl_seconds`), `device_code_lifetime_seconds` (device code, défaut `device_code_ttl_seconds`) et `device_code_interval_seconds` (intervalle de poll device, défaut `device_code_interval_seconds`). `par_required` (facultatif, `false` par défaut) force le client à utiliser la Pushed Authorization Request (RFC 9126 §6.1) : toute demande directe à `/authorize` sans `request_uri` est rejetée en `invalid_request`. `require_consent` (facultatif, `false` par défaut) soumet chaque demande d'autorisation à la confirmation de l'utilisateur connecté sur la page `/consent` (OIDC Core 1.0 §3.1.2.2) avant d'émettre le moindre code ou jeton ; les scopes déjà consentis pour ce client sont ré-utilisés automatiquement (auto-approbation), un scope supplémentaire déclenche un nouvel écran. Authentification JWT / TLS (issues #46, RFC 7523 §2.2 / RFC 8705) : `token_endpoint_auth_method` (facultatif — `client_secret_basic` par défaut) choisit la méthode : `client_secret_basic`/`client_secret_post` (secret partagé), `client_secret_jwt` (secret HMAC prouvé par `client_assertion`, stocké **chiffré** au repos via `client_secret_encrypted` — cf. chiffrement automatique `KeyUse.SECRET`, § dédié), `private_key_jwt` (clé privée : `jwks` — liste de clés JWKS embarquée — ou `jwks_uri` distante), `tls_client_auth`/`self_signed_tls_client_auth` (mTLS : `tls_client_certificate_hash` — SHA-256 de la dérivation de la partie utilisateur du nom de sujet X.500 (RFC 4514) — et/ou `tls_client_auth_subject_dn`). Ces champs alimentent `token_endpoint_auth_methods_supported` du discovery ; un client seed peut se passer de `client_secret` (le secret JWT est chiffré au repos). Algorithmes d'`id_token` (issue #47, OIDC Core 1.0 §3.1.3.6) : `id_token_signed_response_alg` (facultatif — `RS256` par défaut) choisit la **signature** : les algorithmes serveur (`RS*`/`PS*`/`ES*`, clé publiée au JWKS) ou un **HS*** (`HS256`/`HS384`/`HS512`, signature du jeton avec le secret partagé du client, jamais publié au JWKS) ; `id_token_encrypted_response_alg` (facultatif — vide = pas de chiffrement) active le **chiffrement JWE** de l'`id_token` (`RSA-OAEP`/`RSA-OAEP-256` avec une clé publique RSA ≥ 2048 bits du `jwks` enregistré, `A128KW`/`A256KW`/`dir` avec la clé dérivée du secret partagé) ; `id_token_encrypted_response_enc` (facultatif — `A128CBC-HS256` si absente) choisit la méthode de chiffrement du contenu. Ces champs alimentent `id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported` et `id_token_encryption_enc_values_supported` du discovery et sont acceptés par `/register` (RFC 7591). |
| `PURIDENTITYSERVER_USERS_SEED` | *(config.toml)* | Seed du user store servi par `/userinfo` (déversé dans le store au démarrage, comme `clients_seed`) : objet JSON mappant un `subject` (`sub`) à ses claims (format `{"alice": {"name": "...", "email": "...", "roles": ["admin"]}}`). Les clés `alice` / `bob` sont des sujets utilisateurs que le pont identité recopie sous l'UUID FastAPI Users correspondant (même email que `PURIDENTITYSERVER_IDENTITY_SEED_USERS`). Par défaut, `config.toml` fournit les profils démo `alice` (admin) et `bob` (user). |
| `PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED` | *(config.toml)* | IdentityResources supplémentaires (scopes identité, OIDC Core 1.0 §5.4) : liste JSON (format `[{"name":"custom","display_name":"Claims métier","user_claims":["employee_id"],"show_in_discovery_document":true}]`). **Dérogation** : les resources standard (openid, profile, email, address, phone, offline_access) sont seedées **quoi qu'il arrive**, même sans configuration ; cette liste **ajoute** des resources en plus (un nom égal à un standard le surcharge — configurer `profile` remplace ses claims). Chaque resource déclare un scope et les claims exposés quand ce scope est accordé au jeton ; `show_in_discovery_document` (facultatif, défaut `true`) contrôle sa présence dans `scopes_supported`. Elles alimentent `scopes_supported` / `claims_supported` du discovery et le filtrage des claims de `/userinfo` par scope accordé. Gestion en cours de vie via l'API CRUD `GET/POST /identity-resources` et `GET/PUT/DELETE /identity-resources/{name}`. |
| `PURIDENTITYSERVER_API_RESOURCES_SEED` | *(config.toml)* | ApiResources (ressources protégées) : registre des audiences API et de leurs scopes d'API, liste JSON (format `[{"name":"sample-api","display_name":"API de démonstration","scopes":["api.read","api.write"],"allowed_access_token_signing_algos":["ES256"]}]`). Champs d'une entrée : `name` (nom court de la resource, c'est l'`aud` de l'access token quand des scopes lui sont accordés), `display_name` (libellé humain, facultatif), `scopes` (liste des scopes d'API exposés, caractères alphanumériques + `.`/`-`/`_`), `allowed_access_token_signing_algos` (facultatif : restriction des algorithmes de signature acceptables pour cette resource ; vide = algorithmes configurés du serveur). Les scopes d'API complètent `scopes_supported` du discovery ; tout scope non enregistré (standard ou API) est refusé en `invalid_scope` à l'émission (`/authorize`, `/par`, `/token`, `/device_authorization`) et à la registration dynamique (`scope` de RFC 7591). L'`aud` d'un access token porte le nom unique ou la liste triée des resources dont des scopes ont été accordés, sinon le `client_id` émetteur. Gestion en cours de vie via l'API CRUD `GET/POST /api-resources` et `GET/PUT/DELETE /api-resources/{name}`. |
| `PURIDENTITYSERVER_IDENTITY_SEED_USERS` | *(config.toml)* | Comptes de connexion du login navigateur (FastAPI Users) : objet JSON mappant un `subject` à ses identifiants (format `{"alice": {"email": "alice@example.com", "password": "..."}}`). Le serveur les crée (mot de passe haché) au démarrage via `seed_users`. Par défaut `config.toml` fournit `alice` et `bob`. |
| `PURIDENTITYSERVER_IDENTITY_JWT_LIFETIME_SECONDS` | `3600` | Durée de vie par défaut du cookie de session (surchargée par `session_lifetime_seconds` du client du flow, voir `PURIDENTITYSERVER_CLIENTS_SEED`). |
| `PURIDENTITYSERVER_REGISTRATION_ENABLED` | `false` | Active la Dynamic Client Registration (RFC 7591 + 7592) : endpoint `POST /register` (création de client) et `GET/PUT/DELETE /register/{client_id}` (gestion via le registration access token, RFC 7592). Active aussi la publication de `registration_endpoint` dans le document de discovery. |
| `PURIDENTITYSERVER_REGISTRATION_REQUIRES_INITIAL_ACCESS_TOKEN` | `true` | Quand vrai, la création d'un client (`POST /register`) exige un initial access token dans l'en-tête `Authorization: Bearer <token>` ; le jeton doit figurer dans `PURIDENTITYSERVER_REGISTRATION_INITIAL_ACCESS_TOKENS` (comparaison par hash SHA-256, jamais en clair). Mettre à `false` pour un mode ouvert — réservé au développement. |
| `PURIDENTITYSERVER_REGISTRATION_INITIAL_ACCESS_TOKENS` | *(config.toml)* | Liste (séparée par des virgules en environnement) des initial access tokens autorisés à créer des clients. Chaque jeton est stocké uniquement sous forme d'empreinte SHA-256. Exemple : `PURIDENTITYSERVER_REGISTRATION_INITIAL_ACCESS_TOKENS="dev-registrar-token,staging-registrar"`. |
| `PURIDENTITYSERVER_PAR_ENABLED` | `true` | Active la Pushed Authorization Request (RFC 9126) : endpoint `POST /par` et publication de `pushed_authorization_request_endpoint` dans le document de discovery. |
| `PURIDENTITYSERVER_PAR_TTL_SECONDS` | `90` | Durée de vie du `request_uri` retourné par `/par` (secondes, entre 5 et 600). Le `request_uri` est à usage unique : il expire après ce délai et est détruit dès son utilisation à l'endpoint d'autorisation. |
| `PURIDENTITYSERVER_ROLE` | `full` | Rôle de déploiement : `full` expose protocole OIDC/OAuth **et** administration ; `protocol` n'expose que le protocole (aucun CRUD) ; `admin` n'expose que la gestion des resources (`/identity-resources`, `/api-resources`), **sans** générer de clés de signature ni seeder clients/utilisateurs. Deux processus séparés partagent le même état via `STORAGE_TYPE=sql` ; un serveur `admin` peut valider les jetons émis par le serveur `protocol` via `MANAGEMENT_JWT_ISSUER` / `MANAGEMENT_JWT_JWKS_URL`. |
| `PURIDENTITYSERVER_MANAGEMENT_JWT_ISSUER` | *(issuer)* | Issuer de confiance des jetons protégeant les CRUD d'administration. Vide = l'`issuer` du serveur (validation locale, sans réseau). Une valeur différente active la validation **distante** : la signature est vérifiée via le JWKS publié par cet issuer (déploiement séparé). |
| `PURIDENTITYSERVER_MANAGEMENT_JWT_JWKS_URL` | *(découverte)* | URL explicite du JWKS de l'issuer de gestion (sinon découverte via `<issuer>/.well-known/openid-configuration`). Utile quand le serveur d'administration n'a pas accès au discovery. |
| `PURIDENTITYSERVER_MANAGEMENT_JWT_AUDIENCE` | *(aucune)* | Audience exigée dans les jetons de gestion (vide = non contrôlée). |
| `PURIDENTITYSERVER_ADMIN_REQUIRED_CLAIM` | `scope` | Nom du claim exigé sur les CRUD d'administration. Le claim `scope` (chaîne séparée par des espaces) est interprété comme une **appartenance** ; les autres claims sont comparés par **égalité** (valeur unique ou liste). |
| `PURIDENTITYSERVER_ADMIN_REQUIRED_CLAIM_VALUES` | `admin` | Liste (séparée par des virgules) des valeurs autorisées du claim d'administration. **Une liste vide désactive la protection** des CRUD (dérogation à réserver aux tests / usages mono-utilisateur). |
| `PURIDENTITYSERVER_REGISTRATION_INITIAL_ACCESS_TOKEN_MODE` | `static` | Mode d'autorisation de `POST /register` : `static` (initial access tokens hachés de `REGISTRATION_INITIAL_ACCESS_TOKENS`), `jwt` (Bearer JWT validé contre l'issuer de gestion + `REGISTRATION_REQUIRED_CLAIM` / `REGISTRATION_REQUIRED_CLAIM_VALUES`) ou `disabled` (aucune autorisation — déconseillé hors développement). |
| `PURIDENTITYSERVER_REGISTRATION_REQUIRED_CLAIM` | `scope` | Claim exigé en mode `jwt` (mêmes règles que `ADMIN_REQUIRED_CLAIM`). |
| `PURIDENTITYSERVER_REGISTRATION_REQUIRED_CLAIM_VALUES` | `register` | Valeurs autorisées du claim de registration en mode `jwt` (liste séparée par des virgules). |
| `PURIDENTITYSERVER_CLIENT_SECRET_SEAL_KEY_PEM` | *(config.toml)* | **Seed facultatif** de la clé de scellement au repos des secrets clients (issue #46) : clé privée RSA PEM enregistrée dans le store `key_pair` (`KeyUse.SECRET`) au démarrage si aucune clé de scellement n'existe encore. Sert aux mondes **déterministes** (serveurs en mémoire) : le `kid` dérive de la clé publique, le seed est stable d'un redémarrage à l'autre. En production, **aucune clé n'est à fournir** : la clé de scellement est générée automatiquement puis tourne suivant `jwks_rotation_days`. |

**Chiffrement au repos des secrets clients** (méthodes HMAC `client_secret_jwt` et grant `jwt-bearer` signé) : RSA-OAEP (SHA-256) avec la clé publique **la plus récente** de la famille `KeyUse.SECRET`, clé privée détenue uniquement par le serveur (store `key_pair`). Chaque jeton chiffré est préfixé du `kid` de sa clé (SHA-256 de la clé publique tronqué 9 octets, base64url) : le déchiffrement résout la source immédiatement, sans table de correspondance, et replie sur toutes les clés encore présentes (y compris jetons sans préfixe). Les clés de scellement sont mises en rotation **automatiquement** comme les clés de signature mais ne sont **jamais purgées** par la rotation : un secret est chiffré à vie dans le registre.

**Rotation de la clé de scellement** (transparente pour le client : le secret en clair n'est émis qu'une fois, à `POST /register` puis à chaque `PUT` avec un nouveau `client_secret`) :

1. La rotation ajoute une clé quand la plus récente dépasse `jwks_rotation_days` ; tout ciphertext existant reste déchiffrable (l'ancienne clé est toujours présente) et les nouveaux secrets sont scellés sous la clé récente.
2. **Drainer** : `PUT /register/{client_id}` — un `PUT` sans secret sur un client à jour **re-scellé** le ciphertext existant sous la clé récente, sans ré-émettre le secret. Idem pour les clients en mémoire au prochain démarrage.
3. Retirer **manuellement** l'ancienne clé une fois le drain terminé (table `key_pairs`) : un ciphertext orphelin devient illisible et l'authentification est rejetée (`invalid_client`).

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

### Stockage et multi-instance

La variable `STORAGE_TYPE` définit comment l'état persistant du serveur est stocké :
clés de signature, clients, codes d'autorisation, device codes, requêtes PAR
poussées, refresh tokens, jetons révoqués et profils utilisateurs (user store
servis par `/userinfo`). C'est le paramètre qui permet de **loadbalancer**
plusieurs instances du serveur et de reprendre après un redémarrage.

| `STORAGE_TYPE` | Comportement | Usage |
| --- | --- | --- |
| `memory` | Stockage en mémoire (Process-local, sans persistance) | Développement local, tests unitaires |
| `sql` | Stockage SQL via SQLAlchemy (SQLite, PostgreSQL, MySQL) | Production, load balancing multi-instance |

**CORS (SPA)** : un client public JavaScript (Authorization Code + PKCE,
ex. `samples/spa-client`) peut appeler `/token`, `/par`,
`/device_authorization`, `/introspect`, `/revoke` et `/userinfo` depuis le
navigateur dès lors que son **origine est déduite de ses URIs enregistrées** :
toute origine d'une `redirect_uri` d'un client actif, complétée par ses
`web_origins` (OAuth 2.0 for Browser-Based Apps), est autorisée en CORS — y
compris pour un client créé dynamiquement via `/register` (RFC 7591), sans
reconfiguration ni redémarrage. Aucune liste statique n'est à maintenir. Les
cookies de session navigateur ne sont **pas** partagés (cross-origin,
`allow_credentials=false`), conformément au modèle public sans secret.

**Chargement de la DSN** : quand le type est `sql`, le DSN `STORAGE_DSN` est
réécrit automatiquement vers le dialecte asynchrone
(`sqlite:///puridentityserver.db` → `sqlite+aiosqlite:///puridentityserver.db`,
`postgresql://…` → `postgresql+asyncpg://…`, `mysql://…` → `mysql+aiomysql://…`) ;
le driver correspondant doit être installé (`uv sync --extra sql` fournit
`aiosqlite` et `asyncpg`). Le schéma est créé automatiquement au démarrage
(`create_all`, 8 tables : `key_pairs`, `clients`, `authorization_codes`,
`device_authorizations`, `pushed_authorizations`, `refresh_tokens`,
`revoked_tokens`, `users`) et les colonnes ajoutées par une version plus
récente du serveur sont migrées en place (`ALTER TABLE ADD COLUMN`, sans perte
de données).

### Persistance SQL — exemple de démarrage

```sh
uv sync --extra sql
PURIDENTITYSERVER_STORAGE_TYPE=sql \
PURIDENTITYSERVER_STORAGE_DSN=postgresql://puridentityserver:secret@db-host/puridentityserver \
uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

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

- le **backend de stockage** (`storage_type` / `storage_dsn`) ainsi que les
  réglages serveur (`issuer`, `host`, `port`) et JWKS (`jwks_key_size`,
  `jwks_algorithms` — y compris HS* —, `jwks_rotation_days`,
  `jwks_grace_period_days`) et le **chiffrement JWE des id_token**
  (`jwks_encryption_algorithms`, `jwks_encryption_methods`) ;
- les **durées de vie par défaut** des codes d'autorisation et des jetons émis
  (`authorization_code_ttl_seconds`, `access_token_ttl_seconds`,
  `refresh_token_ttl_seconds`) et du **device flow** (`device_code_ttl_seconds`,
  `device_code_interval_seconds`) ;
- la **Dynamic Client Registration** (`registration_enabled`,
  `registration_requires_initial_access_token`,
  `registration_initial_access_tokens`, `registration_initial_access_token_mode`,
  `registration_required_claim`, `registration_required_claim_values` — RFC 7591
  + 7592, endpoint `/register`) ;
- la **séparation administration / protocole** (`role`) et la **protection des
  CRUD** (`management_jwt_issuer`, `management_jwt_jwks_url`,
  `management_jwt_audience`, `admin_required_claim`,
  `admin_required_claim_values`) — les CRUD sont protégés par défaut ; le client
  de démo `sample-admin-client` (scope `admin`) permet d'obtenir un jeton.
  `role` sélectionne le serveur monté : `protocol` →
  `puridentityprotocol.server:app` (OIDC/OAuth, lecture seule des resources),
  `admin` → `puridentityadmin.server:app` (CRUD seuls), `full` →
  `puridentityfull.server:app` (les deux par-dessus les mêmes stores) ; la
  façade historique `puridentityserver.server:app` dispatche sur `role`.
- la **Pushed Authorization Request** (`par_enabled`, `par_ttl_seconds` —
  RFC 9126, endpoint `/par`) ;
- le **client de démo du flow Authorization Code + PKCE** (`sample-pkce-client`, client
  *public*, callback `http://127.0.0.1:5173/callback`, scopes `openid profile email`) ;
- le **client de démo de la SPA statique** (`sample-spa-client`, client
  *public*, callback `http://127.0.0.1:5177/`, scopes `openid profile email
  offline_access` — voir `samples/spa-client/`) ;
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
PURIDENTITYSERVER_STORAGE_TYPE=sql
PURIDENTITYSERVER_STORAGE_DSN=postgresql+asyncpg://puridentityserver:secret@db-host/puridentityserver
```

### Derrière un reverse proxy TLS

```sh
PURIDENTITYSERVER_ISSUER=https://id.example.com uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

### Séparer protocole et administration (déploiement multi-processus)

Chaque rôle expose son propre point d'entrée ; les deux processus partagent le
même état via `storage_type = "sql"`, mais l'administration peut valider les
jetons de gestion contre l'issuer **distant** du protocole
(`management_jwt_issuer`/`management_jwt_jwks_url`) :

```sh
# serveur protocole (endpoints OIDC/OAuth) — port 8001
PURIDENTITYSERVER_ROLE=protocol \
PURIDENTITYSERVER_ISSUER=https://id.example.com \
PURIDENTITYSERVER_STORAGE_TYPE=sql \
uv run uvicorn puridentityprotocol.server:app --host 127.0.0.1 --port 8001

# serveur administration (CRUD des resources) — port 8002
PURIDENTITYSERVER_ROLE=admin \
PURIDENTITYSERVER_MANAGEMENT_JWT_ISSUER=https://id.example.com \
PURIDENTITYSERVER_STORAGE_TYPE=sql \
uv run uvicorn puridentityadmin.server:app --host 127.0.0.1 --port 8002
```

Le mode **mémoire seule / mono-processus** correspond à `role = "full"`
(comportement par défaut) : `puridentityfull.server:app` compose le protocole
et l'administration par-dessus les mêmes stores.

## Notes d'implémentation

- Les clés privées sont stockées en texte PEM ; le repository SQL utilise une table
  `key_pairs` avec une colonne `kid` (identifiant unique, clé primaire) et une colonne
  `is_active` (booléen) pour gérer la rotation.
- Les contrats (ports) de gestion des clés (`KeyManager`), de persistance
  (`KeyPairRepository`, `ClientRepository`, `AuthorizationCodeRepository`,
  `UserRepository`) sont des Protocol vivant dans `puridentityserver/interfaces/` ; chaque
  store est décliné en deux implémentations — `memory` (dictionnaire process-local)
  et `sql` (SQLAlchemy 2.0 asynchrone) — choisies via `STORAGE_TYPE`.
  Des implémentations Redis et MongoDB peuvent être ajoutées comme extras optionnels.
- Les endpoints `/authorize` et `/token` supportent le flux Authorization Code
  avec PKCE (S256), conformes aux RFC 6749 et 7636. Les clients publics
  doivent utiliser PKCE. Le grand `client_credentials` (RFC 6749 §4.4) est
  supporté par `/token` pour les clients **confidentiels** : le client
  s'authentifie avec son `client_secret`, l'access token est émis au nom du
  client (le `sub` du jeton est son `client_id` — pas d'utilisateur final,
  donc aucun `id_token` ni `refresh_token`), et son scope est limité aux
  scopes enregistrés pour ce client. Les secrets sont hashés SHA-256 (jamais
  stockés en clair).
- L'**authentification client JWT** (RFC 7523 §2.2) est dispatchée selon la
  `token_endpoint_auth_method` du client : `client_secret_jwt` (secret HMAC
  prouvé par une `client_assertion`, chiffré au repos par la clé de
  scellement RSA-OAEP automatique — `KeyUse.SECRET`, cf. § dédié), `private_key_jwt`
  (clé privée via JWKS embarqué — `kid` obligatoire — ou `jwks_uri`), et les
  méthodes mTLS `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705,
  `extract_client_certificate`). Le grand **jwt-bearer** (RFC 7523 §2.1,
  `urn:ietf:params:oauth:grant-type:jwt-bearer`) échange une assertion
  (`iss` = client, `sub` = utilisateur délégué, `aud` = token endpoint, `exp`)
  contre un access token émis au nom du `sub`. Le grant et les méthodes
  disponibles sont annoncés au discovery (`grant_types_supported`,
  `token_endpoint_auth_methods_supported`) — la clé de scellement étant
  générée automatiquement, `client_secret_jwt` est toujours disponible.
- L'`id_token` est **signé** par l'algorithme du client (OIDC Core 1.0
  §3.1.3.1) : `RS*`/`PS*`/`ES*` (clé serveur publiée au JWKS) ou **HS*** —
  `HS256`/`HS384`/`HS512` — qui signe avec le secret partagé du client (jamais
  publié au JWKS). Sur demande (`id_token_encrypted_response_alg`), il est
  ensuite **chiffré en JWE compact** (RFC 7516, `cty: JWT`) pour le client
  destinataire : `RSA-OAEP`/`RSA-OAEP-256` (première clé publique RSA ≥ 2048
  bits du `jwks` enregistré, RFC 7518 §4.3), `A128KW`/`A256KW` (RFC 3394) ou
  `dir` (clé dérivée utilisée directement), méthode de contenu
  `A128CBC-HS256` par défaut. Les clés symétriques sont dérivées par
  HKDF-SHA256 du secret partagé du client — **déterministe** : le client
  connaît son secret, rejoue la dérivation et déchiffre (OIDC symétrique).
  Les clés JWKS embarquées sont **validées** à la registration (kty RSA/EC
  uniquement, membres `n`/`e` ou `crv`/`x`/`y` intacts en base64url, module
  RSA ≥ 2048 bits, `use`/`alg` cohérents) puis **re-vérifiées à l'émission**
  (défense en profondeur) ; un matérial de chiffrement indisponible ou
  non conforme est rejeté en `invalid_client`/`invalid_client_metadata`.
- L'endpoint `/userinfo` valide l'access token Bearer (signature JWKS, `iss`,
  `exp`) puis renvoie les claims filtrés par les scopes accordés au jeton
  (OIDC Core 1.0 §5.4). Les claims sont résolus par un `ClaimsProvider`
  (`interfaces/domain/userinfo.py`) dont l'implémentation livrée
  (`infrastructure/claims.py`) délègue au **user store** (`UserRepository`),
  alimenté au démarrage depuis le seed déclaré dans la configuration
  (`PURIDENTITYSERVER_USERS_SEED`).
- Toutes les opérations sont asynchrones (`async/await`), compatibles avec l'event loop
  de FastAPI.
