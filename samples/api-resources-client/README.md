# Test manuel : ApiResources & API protégée

Échantillon complet de la feature **ApiResources** de PurIdentityServer :
les scopes d'API, l'audience `aud` des access tokens, et une **API
protégée** qui valide le token avant de servir des données.

Il se compose de trois éléments :

- **une ApiResource** (une audience/API déclarée côté serveur, ici
  `sample-api` avec les scopes `api.read` / `api.write`) ;
- **une API protégée échantillon** (`api_server.py`) : un resource server
  qui reçoit le token en `Authorization: Bearer`, **vérifie sa signature
  contre les JWKS de l'issuer** (RFC 7517), contrôle `iss` (exact),
  l'expiration `exp`, l'audience `aud` (= nom de la ApiResource) puis que
  le claim `scope` contient le scope requis (`api.read`) — avant de servir
  les données protégées ;
- **des clients** qui obtiennent un token avec un scope d'API et appellent
  cette API : un client machine-à-machine (`client.py`) et un bouton de la
  [démo SPA](../spa-client/README.md).

L'authentification est déclarée en **dépendance FastAPI** (`HTTPBearer`),
pas dans le corps du handler : la route protégée reçoit directement les
claims validés. La sélection de la clé de signature (par `kid`) et la
rotation du JWKS sont déléguées à `PyJWT.PyJWKClient`, qui met les clés en
cache — le resource server n'a donc aucun code de gestion des clés.

## Smoke test

Le test de bout en bout lance le serveur avec une configuration dédiée
(port `8106`, ApiResources `sample-api`/`sample-admin`, client confidentiel
`sample-api-client`), démarre l'API protégée (port `8120`) et vérifie :

1. le discovery annonce `scopes_supported` incluant `api.read`, `api.write`
   et `api.admin` ;
2. `GET /api-resources` liste les resources protégées et leurs scopes (appel
   authentifié : les CRUD d'administration sont protégés par un Bearer au
   scope `api.admin`) ;
3. `/token` (client_credentials, `api.read`) → access token dont l'`aud`
   vaut `sample-api` et le `sub` le `client_id` émetteur ;
4. `/token` (client_credentials, `api.read api.admin`) → `aud` en liste
   triée `["sample-admin", "sample-api"]` ;
5. `/token` (client_credentials, scope inconnu `nope`) → `400
   invalid_scope` (tout scope non enregistré est refusé) ;
6. `/introspect` sur le token API → `active: true`, audience API conservée
   et attribuée comme `client_id` (une audience unique, RFC 7662) ;
7. `/token` (client_credentials, `openid profile`, aucun scope d'API) →
   `aud` = `client_id` (comportement historique sans audience API) ;
8. CRUD (Bearer `api.admin`) : `PUT /api-resources/sample-api` remplace ses
   scopes, `DELETE /api-resources/sample-admin` la retire, `GET` après
   suppression → `404` ;
9. `GET /api/data` de l'API protégée avec un jeton invalide → `401
   invalid_token` ;
10. `GET /api/data` avec le jeton `api.read` → `200` et les claims du jeton
    (la signature JWKS, `iss`, `exp`, `aud` et le scope ont été vérifiés
    par le resource server) ;
11. `GET /api/data` avec un jeton adressé à l'API mais **sans le scope
    requis** (`api.write`) → `403 insufficient_scope`.

```bash
uv run python samples/api-resources-client/smoke_test.py
```

Sortie attendue (extraits) :

```text
  [3/11] client_credentials api.read -> aud='sample-api' OK (sub='sample-api-client')
  [4/11] client_credentials api.read api.admin -> aud=['sample-admin', 'sample-api'] OK
  [5/11] scope inconnu (nope) -> 400 invalid_scope OK
  [9/11] API protégée, jeton invalide -> 401 invalid_token OK
  [10/11] API protégée, jeton api.read -> 200 OK (sub='sample-api-client', aud='sample-api', scope='api.read', JWKS/iss/exp vérifiés par l'API)
  [11/11] API protégée, jeton sans scope requis -> 403 insufficient_scope OK

=== SCÉNARIO OK en X.Xs ===
```

## Lancer l'API protégée seule

L'API est autonome : c'est un simple resource server. Elle a besoin de
l'issuer PurIdentityServer pour récupérer les JWKS (au premier appel) et
n'a besoin d'aucun client.

```bash
# terminal 1 — serveur PurIdentityServer (port par défaut 8000)
uv run python -m puridentityserver

# terminal 2 — API protégée échantillon (port 8120)
uv run python samples/api-resources-client/api_server.py
```

Au démarrage, l'API journalise sa configuration puis chaque requête. Sans
jeton, elle répond `401` :

```text
14:03:12 INFO     puridentityserver.sample.api-resources | API protégée prête sur http://127.0.0.1:8120/api/data (issuer=http://127.0.0.1:8000, aud=sample-api, scope requis=api.read)
14:03:12 INFO     uvicorn.error | Uvicorn running on http://127.0.0.1:8120 (Press CTRL+C to quit)
14:03:20 INFO     uvicorn.access | 127.0.0.1:52134 - "GET /api/data HTTP/1.1" 401 Unauthorized
14:03:20 WARNING  puridentityserver.sample.api-resources | Token rejeté : Not enough segments
```

Avec un jeton valide (voir le client ci-dessous), le log de succès détaille
les claims vérifiés :

```text
14:04:02 INFO     puridentityserver.sample.api-resources | 200 token accepté : sub=sample-api-client aud=sample-api scope=api.read (signature JWKS, iss, exp vérifiés)
14:04:02 INFO     uvicorn.access | 127.0.0.1:52140 - "GET /api/data HTTP/1.1" 200 OK
```

Un jeton adressé à l'API mais sans le scope requis journalise un `403` :

```text
14:04:10 WARNING  puridentityserver.sample.api-resources | 403 insufficient_scope : sub=sample-api-client aud=sample-api scope=api.write (requis api.read)
```

Variables : `API_RES_ISSUER` (défaut `http://127.0.0.1:8000`), `API_RES_PORT`
(défaut `8120`), `API_RES_API` (audience attendue, défaut `sample-api`),
`API_RES_SCOPE` (scope requis, défaut `api.read`). Pour écrire dans un
fichier : `uv run python samples/api-resources-client/api_server.py 2> api.log`.

## Lancer le client seul

`client.py` enchaîne tout automatiquement : discovery de l'issuer, jeton
`client_credentials` avec le scope d'API, puis appel de l'API protégée. Il
suffit que le serveur **et** l'API soient démarrés (voir ci-dessus).

```bash
# terminal 3 — client machine à machine : jeton api.read puis appel de l'API
uv run python samples/api-resources-client/client.py
```

Sortie attendue :

```text
Grant client_credentials contre http://127.0.0.1:8000
  client_id : sample-api-client
  scope     : api.read
  expires_in: 3600 s
  claims (décodés sans vérification — la vérification est le rôle de l'API protégée) : sub='sample-api-client' aud='sample-api' scope='api.read'

GET http://127.0.0.1:8120/api/data (Bearer) :
{
  "resource": "sample-api",
  "message": "Données protégées : token valide (signature JWKS, iss, exp, aud) et scope 'api.read' présent",
  "sub": "sample-api-client",
  "aud": "sample-api",
  "scope": "api.read"
}
```

Le client se pilote par variables d'environnement pour viser un autre
serveur ou une autre API : `API_RES_ISSUER`, `API_RES_CLIENT_ID`,
`API_RES_CLIENT_SECRET`, `API_RES_SCOPE`, `API_RES_API_URL`. Par exemple
pour demander un scope insuffisant et observer le `403` de l'API :

```bash
$env:API_RES_SCOPE = "api.write"
uv run python samples/api-resources-client/client.py
```

## Dans la démo SPA

L'API protégée est aussi exercée depuis la [SPA statique](../spa-client/README.md)
avec le bouton **API protégée** : le navigateur lance un flow Authorization
Code + PKCE demandant les scopes `openid api.read`, reçoit un token dont
l'`aud` est `sample-api`, puis appelle `GET /api/data`.

## Configuration

Le smoke test génère sa configuration (port dédié `8106`, clés de signature
limitées à `RS256` pour un démarrage rapide, clients et ApiResources
spécifiques) via [`smoke_common.py`](../smoke_common.py). Aucun fichier de
configuration n'est committé par sample. La ApiResource `sample-api` et les
clients de démo utilisés par `client.py` et la SPA sont **déjà enregistrés
dans la configuration par défaut du serveur**
([`config.toml`](../../config.toml) à la racine) :

| Élément        | Valeur                                            |
| -------------- | ------------------------------------------------- |
| ApiResource    | `sample-api` (`display_name` « API de démonstration », `scopes = ["api.read", "api.write"]`) |
| `client_id`    | `sample-api-client` (machine à machine)           |
| `client_secret`| `api-demo-secret`                                 |
| `client_type`  | `confidential` (obligatoire)                      |
| `scope`        | `api.read`                                        |
| API protégée   | `http://127.0.0.1:8120/api/data` (port `8120`)    |

Les variables d'environnement de l'API et du client sont détaillées dans
les sections « Lancer l'API protégée seule » et « Lancer le client seul ».

> Le client confidentiel de démo est servi **en clair** (secret dans
> `config.toml`) : c'est un échantillon ; en production le `client_secret`
> se gère comme un secret applicatif, et le resource server valide le token
> de la même façon présentée ici (JWKS du discovery, jamais un secret
> partagé). La vérification d'audience est le point clé : n'acceptez jamais
> un token dont l'`aud` ne mentionne pas votre API.