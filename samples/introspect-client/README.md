# Test manuel : introspection et révocation de jeton (RFC 7662 / RFC 7009)

Script de démonstration/test manuel des endpoints **`POST /introspect`** et
**`POST /revoke`** de PurIdentityServer. Il lance un serveur en
sous-processus avec une configuration **spécifique à ce test** (générée par
`sample_common.py` : port `8100`, client confidentiel
`sample-introspect-client`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `introspection_endpoint` et `revocation_endpoint` ;
2. `/authorize` émet un code d'autorisation (appel anonyme) ;
3. `/token` l'échange contre un access_token (présentation du secret
   client, aucun PKCE nécessaire pour un client confidentiel) ;
4. `/introspect` sur le token valide → `active: true` + métadonnées
   (`scope`, `client_id`, `username`, `token_type`, `iss`/`sub`/`aud`/`iat`/`exp`) ;
5. `/introspect` sur un token inconnu → `active: false` (HTTP 200,
   jamais d'erreur serveur sur un token invalide) ;
6. `/introspect` avec un secret client erroné → `401 invalid_client` ;
7. `/introspect` avec un token vide → `400 invalid_request` ;
8. `/revoke` sur le token valide → HTTP 200, corps vide ;
9. `/introspect` sur le token révoqué → `active: false` (le denylist
   est consulté par l'introspection) ;
10. `/revoke` sur un token inconnu → HTTP 200, corps vide (RFC 7009 §2.2) ;
11. `/revoke` avec un secret client erroné → `401 invalid_client`.

## Lancement

```bash
uv run python samples/introspect-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...
  [1/11] discovery OK ...
  [2/11] code d'autorisation émis (...)
  [3/11] échange code → access_token OK
  [4/11] introspection token valide OK ...
  [5/11] introspection token inconnu → active=false OK
  [6/11] secret client erroné → 401 invalid_client OK
  [7/11] token vide → 400 invalid_request OK
  [8/11] révocation du token valide → HTTP 200 corps vide OK
  [9/11] introspection token révoqué → active=false OK
  [10/11] révocation token inconnu → HTTP 200 corps vide OK
  [11/11] secret client erroné → 401 invalid_client OK

=== SCÉNARIO OK en X.Xs ===
```

## Configuration

Le smoke test génère sa configuration (port dédié `8100`, clés de signature
limitées à `RS256` pour un démarrage rapide, client confidentiel unique)
via [`smoke_common.py`](../smoke_common.py). Aucun fichier de
configuration n'est committé par sample — le client `sample-introspect-client`
est **déjà enregistré dans la configuration par défaut du serveur**
([`config.toml`](../../config.toml) à la racine).

| Clé             | Valeur                                 |
| --------------- | -------------------------------------- |
| `client_id`     | `sample-introspect-client`             |
| `client_secret` | `introspect-demo-secret`               |
| `client_type`   | `confidential`                         |
| `scope`         | `openid profile`                       |

Pour tester manuellement sur le serveur par défaut (port `8000`) :

```bash
# terminal 1 — serveur de développement, tous les clients des samples enregistrés
uv run python -m puridentityserver

# terminal 2 — appels d'introspection / révocation (exemples)
curl -s -d "token=<ACCESS_TOKEN>" \
  -d "client_id=sample-introspect-client" \
  -d "client_secret=introspect-demo-secret" \
  http://127.0.0.1:8000/introspect
curl -s -d "token=<ACCESS_TOKEN>" \
  -d "client_id=sample-introspect-client" \
  -d "client_secret=introspect-demo-secret" \
  http://127.0.0.1:8000/revoke
```

(`<ACCESS_TOKEN>` : un jeton émis sur le port `8000`, par exemple via le flow
du sample `pkce-client`.)