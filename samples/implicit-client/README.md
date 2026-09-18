# Client démo : Implicit flow (OIDC Core 1.0 §3.2)

Application FastAPI de démonstration : une *relying party* qui se connecte à
un serveur PurIdentityServer via le flow **Implicit**
(`response_type=id_token token`, OIDC Core 1.0 §3.2, RFC 6749 §4.2).

Particularité du flow Implicit : les jetons sont remis **directement par
l'endpoint d'autorisation**, dans le **fragment** de l'URL de redirection
(jamais dans la query string, RFC 6749 §4.2.2). Aucun échange au `/token`
n'a lieu. Le `nonce` est obligatoire (OIDC Core §3.2.2.1).

Le client effectue :

1. une **redirection du navigateur** vers la page de login du serveur
   (`/login?next=<authorize>`), avec `response_type=id_token token`, un
   `state` et un `nonce` ; aucun `code_challenge` : pas de code à échanger ;
2. l'**authentification sur le serveur** : l'utilisateur saisit ses
   identifiants sur la page de login PurIdentityServer et obtient un cookie de
   session ;
3. la **redirection vers `/authorize`** (émis avec le cookie) : le serveur
   redirige vers `http://127.0.0.1:5175/callback` en plaçant `id_token`,
   `access_token`, `token_type`, `expires_in` et `scope` dans le **fragment**
   de l'URL ;
4. la **collecte du fragment côté navigateur** : la page de callback lit
   `window.location.hash` (JavaScript) et transmet les jetons au client
   (`POST /collect`) — jamais par la query string ;
5. la **vérification de l'`id_token`** : signature via les JWKS du serveur,
   `aud` = notre `client_id`, `iss` du discovery, `nonce` correspondant,
   **et** le lien `at_hash` avec l'access token reçu dans le même fragment
   (OIDC Core §3.2.2.11) ;
6. l'**appel à `/userinfo`** avec l'access token Bearer (RFC 6750) et
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
   `sample-implicit-client` (URL de callback `http://127.0.0.1:5175/callback`),
   déclaré dans [`config.toml`](../../config.toml).

2. Démarrer le client de démonstration :

   ```bash
   uv sync --extra dev
   uv run python samples/implicit-client/app.py
   ```

3. Ouvrir <http://127.0.0.1:5175> et cliquer sur **Se connecter**.

## Smoke test

Un test de bout en bout lance le serveur + ce client, joue le flow complet
et vérifie chaque étape (redirection, remise des jetons dans le *fragment*,
réémission des jetons du fragment vers `/collect`, vérification de l'`id_token`
et du lien `at_hash`, interrogation de `/userinfo`). Les sous-processus sont
nettoyés à la fin, avec un garde-fou temporel de 30 s.

```bash
uv run python samples/implicit-client/smoke_test.py
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