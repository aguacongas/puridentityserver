# Test manuel : request objects RS256 des clients standards (OIDC Core 1.0 §10.1)

Script de démonstration des **request objects signés RS256** d'un client
**non-FAPI** (issue #188). Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8112`, client seed `sample-request-object-client` *public* avec une
paire RSA embarquée dans `jwks`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery publie `RS256` dans
   `request_object_signing_alg_values_supported` ;
2. `/authorize?request=<JAR RS256>` → `302` code d'autorisation — le
   client est résolu par le claim `iss` du jeton, sans `client_id` en
   query ;
3. `/token` échange du code (PKCE) → `200` access_token + `id_token` ;
4. même demande, JAR signé par une **clé étrangère** → `302`
   `error=invalid_request_object` redirigé au client (OIDC Core 1.0
   §10.3 : la signature doit être vérifiable aux `jwks` du client) ;
5. `/authorize?request=<JAR alg=none>` → `302` code : le request object
   non signé reste admis pour les clients standards.

## Lancement

```bash
uv run python samples/request-object-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/5] discovery OK (request_object_signing_alg_values_supported=[... RS256 ...])
  [2/5] /authorize?request=JAR RS256 -> 302 (code émis, client résolu par le claim iss) OK
  [3/5] échange du code (PKCE) -> 200 access_token + id_token OK
  [4/5] JAR signé par une clé étrangère -> 302 error=invalid_request_object OK
  [5/5] JAR alg=none -> 302 (request object non signé toujours admis) OK
=== SCÉNARIO OK en X.Xs ===
```

## Comment ça marche ?

RFC 9101 (JAR) permet de porter les paramètres d'autorisation dans un JWT
à la place (ou en plus) de la query string. PurIdentityServer accepte, pour
un client **standard** (non-FAPI), deux formes de `request` :

- **`alg=none`** : lecture sans vérification de signature (aucun segment de
  signature admis) — c'est le comportement historique (`REQUEST_OBJECT_SIGNING_ALGORITHMS`) ;
- **`RS256`** : signature vérifiée aux `jwks` enregistrés du client
  (embarqués ou `jwks_uri` distante), claims `iss` (= `client_id`) et
  `aud` (= issuer) exigés, `exp`/`nbf` contrôlés s'ils sont présents
  (RFC 9101 §6.1) — `STANDARD_SIGNED_REQUEST_OBJECT_ALGORITHMS` et
  port `SignedRequestObjectVerifier`.

Les clients `fapi_enabled` suivent toujours le profil strict
`PS256`/`ES256` avec les bornes 60 minutes (FAPI1-ADV-5.2.2) : un JAR
RS256 présenté par un client FAPI reste refusé. Voir aussi
`samples/fapi1-client/` (request objects FAPI) et
`docs/configuration.md` (paragraphe `PURIDENTITYSERVER_CLIENTS_SEED`).
