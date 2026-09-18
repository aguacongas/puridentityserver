# Client démo : Hybrid flow (OIDC Core 1.0 §3.3)

Application FastAPI de démonstration : une *relying party* qui se connecte à
un serveur PurIdentityServer via le flow **Hybrid**
(`response_type=code id_token token`, OIDC Core 1.0 §3.3, RFC 6749 §4.2).

Le flow Hybrid combine l'Authorization Code flow et l'Implicit flow :
l'endpoint d'autorisation remet **dans le fragment** de l'URL de
redirection un `code` d'autorisation **ainsi que** des jetons
(`id_token` + `access_token`) — puis le `code` est échangé au `/token`
avec PKCE pour obtenir les jetons finaux. Le `nonce` est obligatoire
(OIDC Core §3.3.2.1).

Le client effectue :

1. une **redirection du navigateur** vers la page de login du serveur
   (`/login?next=<authorize>`), avec `response_type=code id_token token`,
   un `state`, un `nonce` et un `code_challenge` PKCE S256 ;
2. l'**authentification sur le serveur** : l'utilisateur saisit ses
   identifiants sur la page de login PurIdentityServer et obtient un cookie de
   session ;
3. la **redirection vers `/authorize`** (émis avec le cookie) : le serveur
   redirige vers `http://127.0.0.1:5176/callback` en plaçant `code`,
   `id_token`, `access_token`, `token_type`, `expires_in` et `scope` dans le
   **fragment** de l'URL. L'`id_token` porte `at_hash` (lien avec l'access
   token) et `c_hash` (lien avec le code, OIDC Core §3.3.2.11) ;
4. la **collecte du fragment côté navigateur** : la page de callback lit
   `window.location.hash` (JavaScript) et transmet les jetons au client
   (`POST /collect`) — jamais par la query string ;
5. la **vérification de l'`id_token` d'authorize** : signature via les JWKS
   du serveur, `aud` = notre `client_id`, `iss` du discovery, `nonce`
   correspondant, liens `at_hash` et `c_hash` ;
6. l'**échange du code au `/token`** avec le `code_verifier` PKCE
   (`grant_type=authorization_code`) : le client obtient un second
   `id_token` et l'`access_token` final, eux-mêmes vérifiés ;
7. l'**appel à `/userinfo`** avec l'access token final (RFC 6750) et
   l'affichage des claims de l'utilisateur (filtrés selon les scopes
   `openid profile email` accordés au token).

Comptes de démonstration fournis par le serveur (créés automatiquement au
démarrage) :

- `alice@example.com` / `password` — rôle `admin`
- `bob@example.com` / `password` — rôle `user`

Les rôles sont portés par le claim `roles` du profil seed (scope `profile`)
et restitués dans la réponse de `/userinfo`.

## Lancement

Prérequis : `uv` et une version récente de Python.

1. Démarrer le serveur PurIdentityServer (depuis la racine du dépôt) :

   ```bash
   uv run python -m puridentityserver
   ```

   Le serveur enregistre par défaut le client de démo
   `sample-hybrid-client` (URL de callback `http://127.0.0.1:5176/callback`),
   déclaré dans [`config.toml`](../../config.toml).

2. Démarrer le client de démonstration :

   ```bash
   uv sync --extra dev
   uv run python samples/hybrid-client/app.py
   ```

3. Ouvrir <http://127.0.0.1:5176> et cliquer sur **Se connecter**.

## Smoke test

Un test de bout en bout lance le serveur + ce client, joue le flow complet
et vérifie chaque étape (redirection, remise du code + des jetons dans le
*fragment*, vérification de l'`id_token` avec `at_hash`/`c_hash`, échange du
code au `/token` avec PKCE, rejet du rejeu). Les sous-processus sont
nettoyés à la fin, avec un garde-fou temporel de 30 s.

```bash
uv run python samples/hybrid-client/smoke_test.py
```

## Configuration

Le client se configure de trois façons complémentaires (du plus prioritaire
au moins prioritaire) :

1. **Arguments** passés à `Settings(...)` dans le code ;
2. **Variables d'environnement** `OIDC_*` ;
3. **Fichier [`config.toml`](config.toml)** du sample (table `[settings]`),
   chargé automatiquement depuis le répertoire du script ;
4. **Défauts** déclarés dans le code.

Fichier surchargeable via `OIDC_SETTINGS_FILE=config.local.toml`.