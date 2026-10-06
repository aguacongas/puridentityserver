# Test manuel : Resource Indicators (RFC 8707) + resource server intégré

Script de démonstration des **Resource Indicators** de PurIdentityServer :
le client désigne la (ou les) ressource(s) cible(s) de son access token par
le paramètre `resource` (URI absolue, RFC 8707 §2.1), le serveur en contrôle
l'enregistrement (`invalid_target` hors registre) et en déduit le claim `aud`
du jeton (RFC 8707 §3). La démonstration se termine par l'appel du
**resource server intégré** `GET /protected-resource` (FAPI-R-6.2.1), qui
valide le jeton présenté avant de servir un corps JSON minimal.

## Principes

1. `resource` est accepté sur `GET/POST /authorize`, `POST /par`,
   `POST /bc-authorize` et `POST /token` (une ou plusieurs occurrences,
   repliées en tableau JSON compact quand le dictionnaire de paramètres
   n'en garde qu'une) ;
2. chaque URI doit correspondre à l'`indicator` déclaré d'une
   `ApiResource` seedée, sinon la demande est refusée
   `invalid_target` (redirectable sur `/authorize`) ;
3. les resources sont **liées au support** : persistées sur le code
   d'autorisation, le refresh token et la demande CIBA ; l'`/token` n'accepte
   qu'un sous-ensemble de ce périmètre (RFC 8707 §4) et l'`aud` de l'access
   token en découle (chaîne pour une URI, liste pour plusieurs) ;
4. le resource server intégré `GET /protected-resource` exige l'en-tête
   `Authorization: Bearer <token>` (le transport en query string est refusé,
   RFC 6750 §2.3), répond `401` + challenge `WWW-Authenticate` pour tout
   jeton absent/invalide/révoqué, échoie l'en-tête `x-fapi-interaction-id`
   (ou en génère un `uuid4`) et laisse le `Date` HTTP posé par uvicorn.

## Prérequis

- serveur PurIdentityServer démarré avec la configuration `config.toml`
  racine (port 8000) :

```sh
uv run python -m puridentityserver
```

- la configuration par défaut fournit déjà :
  - l'ApiResource `sample-api` avec
    `indicator = "http://127.0.0.1:8000/protected-resource"` (scopes
    `api.read` / `api.write`) ;
  - `protected_resource_enabled = true` (le endpoint `GET /protected-resource`
    est monté ; sans ce flag : `404`) ;
  - le client confidentiel `sample-resource-client`
    (`redirect_uris = ["http://127.0.0.1:8000/callback"]`,
    scopes `openid profile offline_access`).

## Exécution du client

```sh
uv run python samples/resource-indicators-client/client.py
```

Le client affiche, étape par étape :

1. `/authorize` + `resource` enregistré → code échangé en `200`, puis les
   claims du jeton dont `aud = "http://127.0.0.1:8000/protected-resource"` ;
2. `/authorize` + `resource` inconnue → redirection
   `error=invalid_target&state=ri-state-1` ;
3. `GET /protected-resource` avec le jeton → `200`, corps JSON
   (`message`, `sub`, `scope`), en-tête `x-fapi-interaction-id` échoyé et
   `Date` présent ;
4. `GET /protected-resource` sans jeton → `401` avec
   `WWW-Authenticate: Bearer error="invalid_request"`.

> Variables d'environnement (défauts montrés) : `RI_ISSUER`
> `http://127.0.0.1:8000`, `RI_CLIENT_ID` `sample-resource-client`,
> `RI_CLIENT_SECRET` `resource-demo-secret`, `RI_REDIRECT_URI`
> `http://127.0.0.1:8000/callback`, `RI_RESOURCE`
> `http://127.0.0.1:8000/protected-resource`, `RI_SCOPE`
> `openid profile offline_access`.

## Smoke test (serveur autonome)

Le test de bout en bout lance un serveur dédié (port `8119`, config générée
par `samples/smoke_common.py` : ApiResources `sample-api` / `sample-other`
avec `indicator`, client `sample-ri-client`,
`protected_resource_enabled = true`) et vérifie en 10 étapes :

1. discovery OK ;
2. `resource` enregistrée → code échangé, `aud` = l'URI ciblée (chaîne) ;
3. sans `resource` → `aud` = `client_id` (comportement historique) ;
4. `resource` inconnue → `302 error=invalid_target` ;
5. `resource` malformée → `302 error=invalid_target` ;
6. deux `resource` répétées → `aud` en liste `[uri1, uri2]` ;
7. refresh avec `resource` hors périmètre → `400 invalid_target`, puis sans
   `resource` → `aud` conservé ;
8. `GET /protected-resource` + Bearer → `200` JSON, `x-fapi-interaction-id`
   échoyée, `Date` présent ;
9. sans jeton / jeton invalide / transport en query → `401` + challenge
   `WWW-Authenticate` ;
10. `x-fapi-interaction-id` absente → `uuid4` généré en réponse.

```sh
uv run python samples/resource-indicators-client/smoke_test.py
```

Sortie attendue : dix lignes `[n/10] ... OK` suivies de
`=== SCÉNARIO OK en <durée>s ===`.

## Configuration

- `protected_resource_enabled` (dans `[settings]`, env
  `PURIDENTITYSERVER_PROTECTED_RESOURCE_ENABLED`) : monte
  `GET /protected-resource` (défaut `false`) ;
- `indicator` d'une entrée `[[settings.api_resources_seed]]` (env
  `PURIDENTITYSERVER_API_RESOURCES_SEED`, JSON) : URI absolue sans fragment
  acceptée en paramètre `resource` ; toute valeur hors registre vaut
  `invalid_target` (RFC 8707 §2.2) ;
- les resources ciblées sont accessibles en lecture côté gestion via les
  colonnes `resource_uris` des codes / refresh tokens / demandes CIBA.

Voir aussi : `docs/configuration.md` (seeds et flags) et
`tests/test_resource_indicators.py` (couverture unitaire/intégration).
