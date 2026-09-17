# Test manuel : introspection de jeton (RFC 7662)

Script de démonstration/test manuel de l'endpoint **`POST /introspect`**
de PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration dédiée (port `8100`, client confidentiel
`sample-introspect-client`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `introspection_endpoint` ;
2. `/authorize` émet un code d'autorisation (appel anonyme) ;
3. `/token` l'échange contre un access_token (présentation du secret
   client, aucun PKCE nécessaire pour un client confidentiel) ;
4. `/introspect` sur le token valide → `active: true` + métadonnées
   (`scope`, `client_id`, `username`, `token_type`, `iss`/`sub`/`aud`/`iat`/`exp`) ;
5. `/introspect` sur un token inconnu → `active: false` (HTTP 200,
   jamais d'erreur serveur sur un token invalide) ;
6. `/introspect` avec un secret client erroné → `401 invalid_client` ;
7. `/introspect` avec un token vide → `400 invalid_request`.

## Lancement

```bash
uv run python samples/introspect-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config config.toml)...
  [1/7] discovery OK ...
  [2/7] code d'autorisation émis (...)
  [3/7] échange code → access_token OK
  [4/7] introspection token valide OK ...
  [5/7] introspection token inconnu → active=false OK
  [6/7] secret client erroné → 401 invalid_client OK
  [7/7] token vide → 400 invalid_request OK

=== SCÉNARIO OK en X.Xs ===
```

## Configuration

Le serveur de test lit [`config.toml`](config.toml) (via
`PURIDENTITYSERVER_SETTINGS_FILE`) : port dédié `8100`, clés de signature
limitées à `RS256` (démarrage rapide) et un client confidentiel unique :

| Clé                    | Valeur                                |
| ---------------------- | ------------------------------------- |
| `issuer`               | `http://127.0.0.1:8100`               |
| `client_id`            | `sample-introspect-client`            |
| `client_secret`        | `introspect-demo-secret`              |
| `scope`                | `openid profile`                      |

Pour tester **manuellement contre un serveur par défaut** déjà lancé sur le port
`8000` (issuer `http://127.0.0.1:8000`), le root `config.toml` seed le même client
confidentiel `sample-introspect-client` (`introspect-demo-secret`) : il suffit de
pointer `SERVER_URL` de `smoke_test.py` vers `http://127.0.0.1:8000`.