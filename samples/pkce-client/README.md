# Client démo : Authorization Code + PKCE

Application FastAPI de démonstration : une *relying party* qui se connecte à
un serveur ThePurOidc via le flow **Authorization Code** (RFC 6749) avec
**PKCE** (RFC 7636).

Le client effectue :

1. une **redirection du navigateur** vers la page de login du serveur
   (`/login?next=<authorize>`), en ayant préparé un `code_challenge` S256
   (et un `state` + `nonce`) ;
2. l'**authentification sur le serveur** : l'utilisateur saisit ses
   identifiants sur la page de login ThePurOidc et obtient un cookie de
   session ;
3. la **redirection vers `/authorize`** (émis avec le cookie de session) ;
   le serveur délivre le `code` d'autorisation au `sub` de l'utilisateur
   connecté, reçu sur `http://127.0.0.1:5173/callback` ;
4. l'**échange du code** au `/token` en présentant le `code_verifier` PKCE ;
5. la **vérification de l'`id_token`** : signature via les JWKS du serveur,
   `aud` = notre `client_id`, `iss` du discovery et `nonce` correspondant ;
6. l'**appel à `/userinfo`** avec l'access token Bearer (RFC 6750) et
   l'affichage des claims de l'utilisateur renvoyés par le serveur
   (filtrés selon les scopes `openid profile email` accordés au token).

Comptes de démonstration fournis par le serveur (créés automatiquement au
démarrage) :

- `alice@example.com` / `password` — rôle `admin`
- `bob@example.com` / `password` — rôle `user`

Les rôles sont portés par le claim `roles` du profil seed (scope `profile`)
et restitués dans la réponse de `/userinfo`.

## Lancement

Prérequis : `uv` et une version récente de Python.

1. Démarrer le serveur ThePurOidc (depuis la racine du dépôt) :

   ```bash
   uv run python -m thepuroidc
   ```

   Le serveur enregistre par défaut le client de démo
   `sample-pkce-client` (URL de callback `http://127.0.0.1:5173/callback`),
   déclaré dans [`config.toml`](../../config.toml).

2. Démarrer le client de démonstration :

   ```bash
   uv sync --extra dev
   uv run python samples/pkce-client/app.py
   ```

3. Ouvrir <http://127.0.0.1:5173> et cliquer sur **Se connecter**.

## Smoke test

Un test de bout en bout lance le serveur + ce client, joue le flow complet
et vérifie chaque étape (redirection, émission du code, échange, vérification
de l'`id_token`, rejet du rejeu). Les sous-processus sont nettoyés à la fin,
avec un garde-fou temporel de 30 s.

```bash
uv run python samples/pkce-client/smoke_test.py
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

| Clé (env `OIDC_*` si précisée) | Défaut                           | Rôle                           |
| ------------------------------ | -------------------------------- | ------------------------------ |
| `OIDC_ISSUER`                  | `http://127.0.0.1:8000`          | Emetteur (issuer) côté serveur |
| `OIDC_CLIENT_ID`               | `sample-pkce-client`             | Identifiant du client          |
| `OIDC_REDIRECT_URI`            | `http://127.0.0.1:5173/callback` | URI de callback enregistrée    |
| `OIDC_HOST` / `OIDC_PORT`      | `127.0.0.1` / `5173`             | Hôte / port d'écoute du client |

Le client lit le document de discovery `/.well-known/openid-configuration`
du serveur pour résoudre les endpoints (`authorization_endpoint`,
`token_endpoint`, `jwks_uri`, `issuer`).
