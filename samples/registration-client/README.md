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
12. `GET /register/{client_id}` → `404` (suppression effective) ;
13. le discovery annonce `subject_types_supported` =
    `["public", "pairwise", "ephemeral"]` ;
14. deux clients `pairwise` (secteurs distincts) → `sub` différentes pour le
    même utilisateur, non corrélables entre elles (OIDC Core 1.0 §8.1) ;
15. un même client `pairwise` → `sub` stable entre deux sessions ;
16. `/userinfo` expose la même `sub` que l'id_token (profil résolu sur le
    sujet réel) ;
17. un client `ephemeral` → `sub` constante dans la session, jamais réutilisée
    après une nouvelle connexion (ESID 1.0 §4) ;
18. un client `public` (défaut) → `sub` réelle, non dérivée ;
19. `POST /register` avec un `sector_identifier_uri` inaccessible ou
    incohérent → `400 invalid_client_metadata` ;
20. le discovery annonce `userinfo_signing_alg_values_supported` =
    `["PS256", "ES256", "RS256"]` ;
21. `POST /register` avec `userinfo_signed_response_alg: "RS256"` → `201` +
    métadonnée échoée (OIDC Core 1.0 §5.3.1) ;
22. `userinfo_signed_response_alg: "HS256"` (non publié par l'OP) →
    `400 invalid_client_metadata` ;
23. `/userinfo` de ce client → `application/jwt`, signature RS256 vérifiée
    contre le JWKS, avec les claims `iss` / `aud` / `sub` (OIDC Core 1.0 §5.3.2) ;
24. un client sans la métadonnée → `/userinfo` reste `application/json` non signé.

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
  [1/7] discovery subject_types_supported = public, pairwise, ephemeral OK
  [2/7] deux clients pairwise -> sub distinctes (secteurs différents) OK
  [3/7] même client pairwise -> sub stable entre deux sessions OK
  [4/7] /userinfo expose la sub de l'id_token OK
  [5/7] client ephemeral -> sub constante en session, nouvelle jamais réutilisée OK
  [6/7] client public (défaut) -> sub réelle non dérivée OK
  [7/7] sector_identifier_uri incohérent -> 400 invalid_client_metadata OK
  [1/5] discovery userinfo_signing_alg_values_supported = [PS256, ES256, RS256] OK
  [2/5] POST /register userinfo_signed_response_alg=RS256 -> 201 + écho OK
  [3/5] userinfo_signed_response_alg=HS256 (non publié) -> 400 OK
  [4/5] /userinfo -> application/jwt RS256 vérifiée au JWKS (iss/aud/sub) OK
  [5/5] client sans métadonnée -> /userinfo reste application/json OK

=== SCÉNARIO OK en X.Xs ===
```

## Configuration

Le smoke test génère sa configuration (port dédié `8104`, clés de signature
limitées à `RS256` pour un démarrage rapide) via
[`smoke_common.py`](../smoke_common.py) : aucun client seed — le client est
créé dynamiquement au cours du scénario. Les données d'administration
fournies sont l'**initial access token** de démonstration et le **seed de
dérivation des subjects** :

| Clé                        | Valeur                          |
| -------------------------- | ------------------------------- |
| `registration_enabled`     | `true`                          |
| `initial_access_token`     | `dev-registrar-token`           |
| `subject_pairwise_seed`    | `smoke-subject-seed-8104`       |

Le seed est requis pour tout client `pairwise`/`ephemeral` : sans lui, la
registration de tel client est refusée (`invalid_client_metadata`). Le smoke
test seed aussi un compte `alice@example.com` (connexion au formulaire
`/login`, nécessaire pour que le flow porte un sujet réel).

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

## Réponses UserInfo signées (OIDC Core 1.0 §5.3.1 / §5.3.2)

```bash
# enregistrement d'un client exigeant une réponse /userinfo signée RS256
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Authorization: Bearer dev-registrar-token" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["http://127.0.0.1:5173/callback"],
       "scope": "openid profile",
       "userinfo_signed_response_alg": "RS256"}'
# → 201 avec "userinfo_signed_response_alg": "RS256" échoé dans la réponse
# (PS256 / ES256 / RS256 admis ; toute autre valeur -> 400 invalid_client_metadata)
```

Après un flow Authorization Code classique avec ce client, `GET /userinfo`
avec l'access token renvoie un **JWT RS256** servi en `application/jwt` au
lieu du JSON, vérifiable contre `/.well-known/jwks.json` :

```python
header = jwt.get_unverified_header(userinfo_jwt)  # {"alg": "RS256", "kid": ...}
claims = jwt.decode(  # clé du JWKS portant le même kid
    userinfo_jwt,
    jwk_public_key,
    algorithms=["RS256"],
    audience="<client_id>",
    issuer="http://127.0.0.1:8000",
)
# claims = {"iss": ..., "sub": ..., "aud": "<client_id>", "iat": ..., profil...}
```

Sans la métadonnée à l'enregistrement, la réponse reste le JSON non signé
historique : la signature n'est imposée que si le client la demande.

## Grants étendus et profils FAPI via DCR (#176)

Avec `PURIDENTITYSERVER_DCR_ALLOW_FULL_GRANTS=true` (défaut strict : `false`),
l'enregistrement dynamique accepte les grants supplémentaires et les profils
FAPI, sous réserve d'une authentification client forte.

```bash
# Activation côté serveur (pour cet exemple uniquement)
PURIDENTITYSERVER_DCR_ALLOW_FULL_GRANTS=true \
  uv run python -m puridentityserver
```

Grants étendus (client_credentials, device_code, jwt-bearer) :

```bash
curl -s -X POST http://127.0.0.1:8000/register   -H "Authorization: Bearer dev-registrar-token"   -H "Content-Type: application/json"   -d '{"redirect_uris": ["http://127.0.0.1:5173/callback"],
       "scope": "openid",
       "token_endpoint_auth_method": "private_key_jwt",
       "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
       "jwks": {"keys": [{"kty":"RSA","n":"...","e":"AQAB","kid":"k1","use":"sig","alg":"RS256"}]}}'
# -> 201 si l'authentification est forte ; 400 invalid_client_metadata sinon
```

Profil FAPI 2.0 via DCR (authentification forte requise) :

```bash
curl -s -X POST http://127.0.0.1:8000/register   -H "Authorization: Bearer dev-registrar-token"   -H "Content-Type: application/json"   -d '{"redirect_uris": ["http://127.0.0.1:5173/callback"],
       "scope": "openid",
       "token_endpoint_auth_method": "private_key_jwt",
       "fapi2_enabled": true,
       "jwks": {"keys": [{"kty":"RSA","n":"...","e":"AQAB","kid":"k1","use":"sig","alg":"RS256"}]}}'
# -> 201 avec "fapi2_enabled": true dans la reponse
# (fapi_enabled et fapi2_enabled sont mutuellement exclusifs)
```

Note : la même configuration fonctionne tel quel avec le serveur par défaut,
pourvu que `PURIDENTITYSERVER_DCR_ALLOW_FULL_GRANTS=true` soit positionné.
