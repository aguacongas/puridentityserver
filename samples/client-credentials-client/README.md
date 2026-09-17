# Test manuel : grand client_credentials (RFC 6749 §4.4)

Script de démonstration/test manuel du **grant type `client_credentials`**
de PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8102`, client confidentiel `sample-cc-client`, scopes
`openid profile`) puis joue le scénario complet.

Ce flow est purement *machine à machine* : le client s'authentifie avec
son `client_secret`, le `sub` de l'access token est le `client_id`
lui-même (aucun utilisateur final, aucun `id_token`, aucun refresh token).

Le scénario vérifie :

1. le discovery annonce `grant_types_supported` incluant `client_credentials` ;
2. `/token` (client_credentials + secret) → access_token seul, scope
   `openid profile`, aucun `id_token` ;
3. scop restreint (`openid`) → access_token au scop `openid` ;
4. scop non enregistré pour le client (`email`) → `400 invalid_scope` ;
5. secret erroné → `400 invalid_client` ;
6. secret absent → `400 invalid_client` ;
7. client inconnu → `400 invalid_client`.

## Lancement

```bash
uv run python samples/client-credentials-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...
  [1/7] discovery OK ...
  [2/7] client_credentials -> access_token seul ...
  [3/7] scope restreint (openid) OK
  [4/7] scope non enregistré -> 400 invalid_scope OK
  [5/7] secret erroné -> 400 invalid_client OK
  [6/7] secret absent -> 400 invalid_client OK
  [7/7] client inconnu -> 400 invalid_client OK

=== SCÉNARIO OK en X.Xs ===
```

## Client de démonstration

```bash
# terminal 1 — serveur PurIdentityServer (port par défaut 8000)
uv run python -m puridentityserver

# terminal 2 — requête machine à machine
uv run python samples/client-credentials-client/client.py
```

`client.py` demande un access token avec le grand client_credentials puis
affiche ses claims (décodés, non vérifiés — simple démonstration) :
`sub` = `client_id`, `scope` = `openid profile`, et l'absence d'`id_token`.

## Configuration

Le smoke test génère sa configuration (port dédié `8102`, clés de signature
limitées à `RS256` pour un démarrage rapide, client confidentiel unique)
via [`smoke_common.py`](../smoke_common.py). Aucun fichier de configuration
n'est committé par sample — le client `sample-cc-client` est **déjà
enregistré dans la configuration par défaut du serveur**
([`config.toml`](../../config.toml) à la racine).

| Clé           | Valeur                                   |
| ------------- | ---------------------------------------- |
| `client_id`   | `sample-cc-client`                       |
| `client_secret` | `cc-demo-secret`                       |
| `client_type` | `confidential` (obligatoire)             |
| `scope`       | `openid profile`                         |

`client.py` cible par défaut `http://127.0.0.1:8000` ; pour tester contre un
autre serveur, surchargez `CC_ISSUER` (et `CC_CLIENT_ID`/
`CC_CLIENT_SECRET`/`CC_SCOPE` si besoin).