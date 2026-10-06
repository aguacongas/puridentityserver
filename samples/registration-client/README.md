# Test manuel : registration dynamique de clients (RFC 7591 / RFC 7592)

Script de démonstration de la **Dynamic Client Registration** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8104`, registration activée avec un initial access token de démo —
aucun client seed : le client est créé dynamiquement) puis joue le
scénario complet.

Le scénario vérifie :

1. le discovery annonce `registration_endpoint` (`/register`) ;
2. `POST /register` sans initial access token → `401 invalid_client` ;
3. `POST /register` avec une redirect_uri invalide → `400 invalid_redirect_uri` ;
4. `POST /register` profil CIBA (`grant_types` sans flow de redirection) sans
   `redirect_uris` → `201` (RFC 7591 §2 : `redirect_uris` omissible) ;
5. `POST /register` avec l'initial access token → `201` + `Location`,
   `client_id` + `client_secret` + `registration_access_token` émis une seule fois ;
6. `GET /register/{client_id}` avec le registration access token → `200`
   (métadonnées, ni secret ni registration token dans la réponse) ;
7. flow OIDC complet avec le client **dynamique** : `/authorize` puis
   `/token` avec le secret émis à la registration → `200` access_token ;
8. `PUT /register/{client_id}` avec un nouveau `client_secret` (rotation) →
   `200` + nouveau secret, émis une seule fois ;
9. `/token` avec l'ancien secret → `400 invalid_client` (rotation) ;
10. `/token` avec le nouveau secret → `200` access_token ;
11. `DELETE /register/{client_id}` → `204` ;
12. `GET /register/{client_id}` → `404` (suppression effective).

## Lancement

```bash
uv run python samples/registration-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...
  [1/12] discovery OK (registration_endpoint=http://127.0.0.1:8104/register)
  [2/12] POST /register sans initial access token -> 401 invalid_client OK
  [3/12] redirect_uri invalide -> 400 invalid_redirect_uri OK
  [4/12] DCR sans redirect_uris (grant CIBA, RFC 7591 §2) -> 201 OK
  [5/12] POST /register -> 201 (client_id=UytQvM_1..., secret + registration_access_token émis une seule fois)
  [6/12] GET /register/{client_id} -> 200 (ni secret ni token réémis) OK
  [7/12] flow OIDC complet via le client dynamique (secret de registration) OK
  [8/12] PUT /register/{client_id} (rotation du secret) -> 200 OK
  [9/12] ancien secret après rotation -> 400 invalid_client OK
  [10/12] nouveau secret (après rotation) -> 200 access_token OK
  [11/12] DELETE /register/{client_id} -> 204 corps vide OK
  [12/12] GET /register/{client_id} après suppression -> 404 OK

=== SCÉNARIO OK en X.Xs ===
```

## Configuration

Le smoke test génère sa configuration (port dédié `8104`, clés de signature
limitées à `RS256` pour un démarrage rapide) via
[`smoke_common.py`](../smoke_common.py) : aucun client seed — le client est
créé dynamiquement au cours du scénario. La seule donnée d'administration
fournie est l'**initial access token** de démonstration :

| Clé                        | Valeur                          |
| -------------------------- | ------------------------------- |
| `registration_enabled`     | `true`                          |
| `initial_access_token`     | `dev-registrar-token`           |

C'est la même valeur que dans la configuration **par défaut** du serveur
([`config.toml`](../../config.toml) à la racine) : tester manuellement sur
le port `8000` fonctionne donc tel quel.

## Test manuel sur le serveur par défaut (port 8000)

```bash
# terminal 1 — serveur de développement (registration activée par défaut)
uv run python -m puridentityserver

# terminal 2 — enregistrement d'un client (RFC 7591)
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Authorization: Bearer dev-registrar-token" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["http://127.0.0.1:5173/callback"],
       "scope": "openid profile email"}'
# → 201 { "client_id": ..., "client_secret": ..., "registration_access_token": ...,
#         "registration_client_uri": "http://127.0.0.1:8000/register/<client_id>", ... }
```

Le `client_secret`, le `registration_access_token` et le
`registration_client_uri` ne sont retournés qu'à la création (RFC 7592 §2.2) :
stockez-les côté client.

```bash
# gestion du client (RFC 7592) — lecture
curl -s http://127.0.0.1:8000/register/<client_id> \
  -H "Authorization: Bearer <registration_access_token>"

# rotation du secret — remplacement de la configuration (PUT)
curl -s -X PUT http://127.0.0.1:8000/register/<client_id> \
  -H "Authorization: Bearer <registration_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["http://127.0.0.1:5173/callback"],
       "client_secret": "un-nouveau-secret",
       "scope": "openid profile"}'

# suppression du client (DELETE)
curl -s -X DELETE http://127.0.0.1:8000/register/<client_id> \
  -H "Authorization: Bearer <registration_access_token>"
# → 204
```

Le client ainsi enregistré est un client **confidentiel** utilisable
immédiatement dans les autres samples (Authorization Code, secret client,
sans PKCE obligatoire) : le secret prouvé à l'étape 7 du smoke test.