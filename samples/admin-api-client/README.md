# Sample — administration protégée par JWT

Ce sample montre comment **séparer l'administration du protocole** et
**protéger les CRUD** (`/identity-resources`, `/api-resources`) par un JWT
Bearer portant un claim configurable. C'est une démonstration complète du
réglage `role` et de la validation locale **et** distante (JWKS).

Aucune connaissance préalable du projet n'est nécessaire : suivez les étapes.

## Ce que fait le sample

- `client.py` : démo CLI — obtient un jeton `client_credentials` avec le scope
  `admin`, puis appelle `/api-resources` **sans** puis **avec** le jeton (401
  puis 200).
- `smoke_test.py` : scénario automatique de bout en bout avec **deux serveurs** :
  - serveur A (`role = full`, port 8107) : émet les jetons et expose les CRUD ;
  - serveur B (`role = admin`, port 8108) : n'expose **que** la gestion des
    resources, ne connaît pas les clés de A et valide les jetons **à distance**
    via le JWKS publié par A.

## Prérequis

- Python 3.13 et [uv](https://docs.astral.sh/uv/) installés ;
- les dépendances : `uv sync --extra dev` (à la racine du dépôt).

## 1. Démo manuelle (un seul serveur)

Depuis la **racine du dépôt**, lancez le serveur par défaut (port 8000) :

```sh
uv run python -m puridentityserver
```

Dans un second terminal, lancez le client d'administration :

```sh
uv run python samples/admin-api-client/client.py
```

Résultat attendu :

```text
GET http://127.0.0.1:8000/api-resources sans jeton -> HTTP 401
Grant client_credentials contre http://127.0.0.1:8000 (scope=admin)
GET http://127.0.0.1:8000/api-resources avec jeton -> HTTP 200
[
  {
    "name": "sample-api",
    ...
  },
  {
    "name": "management",
    "display_name": "API de gestion",
    "scopes": ["admin"]
  }
]
```

Le serveur par défaut (`config.toml`) déclare :

- l'ApiResource `management` (scope `admin`) — le scope `admin` alimente le
  claim `scope` du jeton ;
- le client `sample-admin-client` (confidentiel, secret `admin-demo-secret`,
  scopes `openid admin`) ;
- `admin_required_claim = "scope"` et `admin_required_claim_values = ["admin"]` :
  les CRUD exigent un jeton dont le scope contient `admin`.

Essayez sans le scope admin pour observer le refus :

```sh
# avec un jeton sans scope admin (client api-resources)
ADMIN_API_CLIENT_ID=sample-api-client ADMIN_API_CLIENT_SECRET=api-demo-secret \
ADMIN_API_SCOPE=api.read uv run python samples/admin-api-client/client.py
# -> GET ... avec jeton -> HTTP 401
```

## 2. Scénario automatique (séparation de déploiement)

```sh
uv run python samples/admin-api-client/smoke_test.py
```

Le test démarre les deux serveurs et vérifie :

```text
  [1/9] serveur A (role=full) : discovery + JWKS publiés sur http://127.0.0.1:8107
  [2/9] A : GET /api-resources sans jeton -> 401 (WWW-Authenticate: Bearer)
  [3/9] A : jeton sans claim admin -> 401
  [4/9] A : jeton scope=admin -> 200 (resources ['management', 'sample-api'])
  [5/9] A : CRUD /identity-resources avec le jeton admin -> 201 puis 204
  [6/9] serveur B (role=admin) : ni discovery ni /token sur http://127.0.0.1:8108
  [7/9] B : GET /api-resources sans jeton -> 401
  [8/9] B : jeton émis par A accepté (signature validée via JWKS distant)
  [9/9] B : jeton non admin -> 401
=== SCÉNARIO OK en ...s ===
```

## 3. Configuration équivalente (serveur B)

Le serveur B valide les jetons de A sans partager ses clés :

```toml
[settings]
role = "admin"
management_jwt_issuer = "http://127.0.0.1:8107"
management_jwt_jwks_url = "http://127.0.0.1:8107/.well-known/jwks.json"
admin_required_claim = "scope"
admin_required_claim_values = ["admin"]
```

Pour un déploiement réel avec deux instances partageant les données, ajoutez
`storage_type = "sql"` et un `storage_dsn` commun.

## Références

- `role`, `management_jwt_*`, `admin_required_claim*` :
  [docs/configuration.md](../../docs/configuration.md).
- Le claim peut aussi être un claim d'égalité (ex. `role = "operator"` ou
  `roles = ["operator"]`) : voir les tests `tests/test_admin_security.py`.
