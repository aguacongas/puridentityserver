# Test manuel : request objects des clients standards (OIDC Core 1.0 §10.1)

Script de démonstration des **request objects** d'un client **non-FAPI**
(issues #188 — signés RS256, et #204 — chiffrés JWE). Il lance un serveur
en sous-processus avec une configuration **spécifique à ce test** (générée
par `smoke_common.py` : port `8112`, client seed
`sample-request-object-client` *public* avec une paire RSA embarquée dans
`jwks`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery publie `RS256` dans
   `request_object_signing_alg_values_supported` et les familles
   `request_object_encryption_alg_values_supported` /
   `request_object_encryption_enc_values_supported` (OIDC Core 1.0 §10.1) ;
2. `/authorize?request=<JAR RS256>` → `302` code d'autorisation — le
   client est résolu par le claim `iss` du jeton, sans `client_id` en
   query ;
3. `/token` échange du code (PKCE) → `200` access_token + `id_token` ;
4. même demande, JAR signé par une **clé étrangère** → `302`
   `error=invalid_request_object` redirigé au client (OIDC Core 1.0
   §10.3 : la signature doit être vérifiable aux `jwks` du client) ;
5. `/authorize?request=<JAR alg=none>` → `302` code : le request object
   non signé reste admis pour les clients standards ;
6. le même JAR RS256 **chiffré** en JWE (RSA-OAEP-256 + A256GCM) avec la
   clé publique `use=enc` de l'OP lue au `jwks_uri` → `302` code, puis
   échange du code (PKCE) : l'OP déchiffre avec sa clé privée `enc`, puis
   suit la chaîne habituelle (OIDC Core 1.0 §10.1) ;
7. JAR chiffré à une clé publique **étrangère** → `400`
   `invalid_request_object` (l'OP ne peut déchiffrer le JWE, donc pas de
   `redirect_uri` à cible : page d'erreur HTML, OIDC Core 1.0 §10.1).

## Lancement

```bash
uv run python samples/request-object-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/7] discovery OK (signing=[... RS256 ...], encryption alg=[... RSA-OAEP-256 ...] enc=[... A256GCM ...])
  [2/7] /authorize?request=JAR RS256 -> 302 (code émis, client résolu par le claim iss) OK
  [3/7] échange du code (PKCE) -> 200 access_token + id_token OK
  [4/7] JAR signé par une clé étrangère -> 302 error=invalid_request_object OK
  [5/7] JAR alg=none -> 302 (request object non signé toujours admis) OK
  [6/7] JAR RS256 chiffré (RSA-OAEP-256 + A256GCM, clé use=enc de l'OP) -> 302 code + échange PKCE OK
  [7/7] JAR chiffré à une clé étrangère -> 400 error=invalid_request_object (déchiffrement impossible) OK
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

Un `request` peut en outre être **chiffré** (OIDC Core 1.0 §10.1) : un
document à cinq segments (JWE compact) est déchiffré avec la clé RSA
`use=enc` de l'OP — générée au démarrage, publiée au
`/.well-known/jwks.json` et dans le `jwks` de l'entity statement fédéré —
puis le JWT obtenu suit la chaîne ci-dessus. Les familles `alg`/`enc` sont
publiées au discovery (`RSA-OAEP`, `RSA-OAEP-256` /
`A128CBC-HS256`, `A256CBC-HS512`, `A128GCM`, `A256GCM`, réglables via
`PURIDENTITYSERVER_REQUEST_OBJECT_ENCRYPTION_ALGORITHMS` /
`PURIDENTITYSERVER_REQUEST_OBJECT_ENCRYPTION_METHODS`) ; un `alg`/`enc`
non publié ou un déchiffrement impossible rend
`error=invalid_request_object`.

Les clients `fapi_enabled` suivent toujours le profil strict
`PS256`/`ES256` avec les bornes 60 minutes (FAPI1-ADV-5.2.2) : un JAR
RS256 présenté par un client FAPI reste refusé. Voir aussi
`samples/fapi1-client/` (request objects FAPI),
`samples/federation-client/` (request objects fédérés, dont le module
certifié `…-with-jar-and-encrypted-request-object`) et
`docs/configuration.md` (paragraphe `PURIDENTITYSERVER_CLIENTS_SEED`).
