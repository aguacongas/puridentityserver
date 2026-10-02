# Sample — authentification OIDC dans Swagger UI (bouton Authorize)

Ce sample montre l'**authentification OIDC de Swagger UI** : le bouton
**Authorize** de `/docs` déclenche un vrai flow *authorization code + PKCE*
contre PurIdentityServer, puis les CRUD d'administration s'appellent avec le
jeton obtenu (claim `scope=admin` exigé par les CRUD).

Aucune connaissance préalable du projet n'est nécessaire : suivez les étapes.

## Ce que fait le sample

- **Démo navigateur** : le serveur par défaut expose `/docs` avec le bouton
  Authorize déjà configuré (client public `sample-swagger-client`, PKCE —
  voir `config.toml`).
- `smoke_test.py` : scénario automatique qui rejoue à la main le flow du
  bouton : schéma dans `openapi.json` → page `/docs` → page de retour OAuth2 →
  `/authorize` (PKCE S256) → `/token` → CRUD 401 puis 200.

## Prérequis

- Python 3.13 et [uv](https://docs.astral.sh/uv/) installés ;
- les dépendances : `uv sync --extra dev` (à la racine du dépôt).

## 1. Démo manuelle (navigateur)

Depuis la **racine du dépôt**, lancez le serveur par défaut (port 8000) :

```sh
uv run python -m puridentityserver
```

Ouvrez <http://127.0.0.1:8000/docs> puis :

1. le bouton **Authorize** apparaît en haut à droite : les CRUD portent le
   schéma OAuth2 `oidc` (vérifiable dans `GET /openapi.json` →
   `components.securitySchemes.oidc`) ;
2. cliquez **Authorize** : la fenêtre pré-remplit
   `Client ID = sample-swagger-client` avec les scopes `openid` et `admin` —
   validez (**Authorize**) ;
3. le navigateur passe par `/docs/oauth2-redirect` puis revient sur `/docs` :
   le jeton est mémorisé (séries de points en haut de la fenêtre) ;
4. dépliez `GET /identity-resources` → **Try it out** → **Execute** :

```text
GET /identity-resources sans jeton -> HTTP 401
GET /identity-resources avec le jeton OIDC -> HTTP 200
```

(« Logout » en haut de `/docs` efface le jeton mémorisé pour revoir le 401.)

### Variante avec page de login

Par défaut `require_login = false` : le flow est auto-approuvé (subject vide).
Pour un **vrai** login OIDC :

```sh
PURIDENTITYSERVER_REQUIRE_LOGIN=true uv run python -m puridentityserver
```

Lors du flow, la page `/login` s'affiche : connectez-vous avec
`alice@example.com` / `password` (comptes de démo de `config.toml`).

### Désactiver la fonctionnalité

```sh
PURIDENTITYSERVER_SWAGGER_UI_OAUTH2_ENABLED=false uv run python -m puridentityserver
```

Le schéma OAuth2 n'est plus déclaré : aucun bouton Authorize OIDC.

## 2. Scénario automatique

```sh
uv run python samples/swagger-docs-client/smoke_test.py
```

Le test démarre un serveur dédié (port 8109, configuration générée) et
vérifie :

```text
  [1/6] /openapi.json : schéma oauth2 « oidc » déclaré sur les CRUD
  [2/6] /docs : initOAuth(clientId=sample-swagger-client) + oauth2RedirectUrl
  [3/6] /docs/oauth2-redirect : page de retour OAuth2 servie (200)
  [4/6] /authorize : 302 vers /docs/oauth2-redirect avec code + state
  [5/6] /token : authorization_code + PKCE échangé contre l'access token
  [6/6] /api-resources : 401 sans jeton puis 200 avec le jeton (['management'])
=== SCÉNARIO OK en ...s ===
```

## 3. Configuration équivalente

Extrait de la configuration de démonstration (`config.toml`) :

```toml
[settings]
swagger_ui_oauth2_enabled = true
swagger_ui_oauth2_redirect_url = "/docs/oauth2-redirect"
swagger_ui_init_oauth = { clientId = "sample-swagger-client", scopes = ["openid", "admin"], usePkceWithAuthorizationCodeGrant = true }

[[settings.clients_seed]]
client_id = "sample-swagger-client"
redirect_uris = ["http://127.0.0.1:8000/docs/oauth2-redirect"]
scopes = "openid admin"
client_type = "public"
```

Trois points importants :

- l'**ApiResource `management`** (scope `admin`) doit être déclarée : c'est
  elle qui rend le scope `admin` émissible, donc présent dans le claim
  `scope` exigé par les CRUD (`admin_required_claim_values`) ;
- le client est **public** : le PKCE est obligatoire côté serveur, d'où
  `usePkceWithAuthorizationCodeGrant = true` côté Swagger ;
- `swagger_ui_oauth2_redirect_url` doit figurer dans les `redirect_uris` du
  client (le navigateur l'utilise comme `window.location.origin` + chemin).

## Références

- `swagger_ui_oauth2_enabled`, `swagger_ui_oauth2_redirect_url`,
  `swagger_ui_init_oauth`, `docs_enabled` :
  [docs/configuration.md](../../docs/configuration.md).
- Protection des CRUD : `admin_required_claim` / `admin_required_claim_values`
  et échantillon [admin-api-client](../admin-api-client/README.md).
