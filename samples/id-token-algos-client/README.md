# Algorithmes d'`id_token` — HS* + JWE (issue #47)

Scénario de démonstration des algorithmes d'`id_token` de PurIdentityServer
(OIDC Core 1.0 §3.1.3.1 et §3.1.3.6) : un client est enregistré **dynamiquement**
(RFC 7591) avec sa **signature** `id_token_signed_response_alg` et son
**chiffrement** `id_token_encrypted_response_alg` / `_enc`, puis un flow
Authorization Code + PKCE complet (login inclus) est joué pour observer
l'`id_token` produit.

Deux familles de chiffrement JWE (RFC 7516) sont exercées :

1. **Asymétrique — `RSA-OAEP-256` / `A256GCM`** : l'`id_token` signé (HS256,
   avec le **secret partagé** du client — jamais publié au JWKS serveur) est
   chiffré pour le client avec sa **clé publique RSA** (JWK `use: enc` ≥ 2048
   bits enregistré dans le `jwks`, RFC 7518 §4.3). Le script le déchiffre avec
   la clé privée correspondante.
2. **Symétrique — `dir` / `A256CBC-HS512`** : la clé de contenu est **dérivée
   du secret partagé** (HKDF-SHA256, déterministe : le client la rejoue pour
   déchiffrer). Bascule jouée en cours de vie via `PUT /register` (RFC 7592).

Le scénario complet (registration incluse) est aussi joué en auto par
`smoke_test.py`, qui vérifie les **défenses** du serveur : clé RSA courte
(`invalid_client_metadata`), JWK `use: sig` pour un `RSA-OAEP*`, `id_token`
altéré (intégrité), et l'émission d'un `id_token` HS256 **seul** (sans
chiffrement).

## 1. Lancement du serveur

La configuration **par défaut** du dépôt fournit déjà les signatures HS* et
tous les algorithmes/méthodes de chiffrement (réglages
`PURIDENTITYSERVER_JWKS_ENCRYPTION_ALGORITHMS` / `_METHODS`), la registration
dynamique et le compte de connexion `alice@example.com` / `password` :

```bash
# terminal 1 - serveur de développement (port 8000 par défaut)
uv run python -m puridentityserver
```

## 2. Le client de démonstration

```bash
# terminal 2 - enregistrement + flow Authorization Code + PKCE
uv run python samples/id-token-algos-client/client.py
```

Étapes exécutées :

1. `GET /.well-known/openid-configuration` : vérifie que `HS256` est annoncé
   dans `id_token_signing_alg_values_supported`, `RSA-OAEP-256` dans
   `id_token_encryption_alg_values_supported` et `A256GCM` dans
   `id_token_encryption_enc_values_supported` ;
2. `POST /register` (RFC 7591) : client
   `id_token_signed_response_alg: HS256` +
   `id_token_encrypted_response_alg: RSA-OAEP-256` +
   `id_token_encrypted_response_enc: A256GCM`, avec un JWK RSA
   (`use: enc`, 2048 bits) dans `jwks` → `client_id` + `client_secret` ;
3. **flow Authorization Code + PKCE** : `/authorize` → login `alice` →
   code → `/token` → l'`id_token` est un **JWE compact** (5 segments) ;
4. le script **déchiffre** le JWE (clé privée locale), affiche son en-tête
   (`alg`/`enc`/`cty: JWT`) et **vérifie la signature HS256** du jeton
   imbriqué ainsi que `iss` / `aud` / `nonce` ;
5. `PUT /register/{client_id}` (RFC 7592) bascule en **`dir` +
   `A256CBC-HS512`** : re-flow → déchiffrement avec la clé **dérivée du
   secret partagé**, signature toujours vérifiée ;
6. **défense** : tentative d'enregistrement avec un module RSA de **1024
   bits** → rejeté (`invalid_client_metadata`, RFC 7518 §4.3).

Sortie attendue :

```text
Discovery : signing=HS256, HS384, HS512, RS256, ... | JWE alg=... enc=...
Registration (RFC 7591) : client_id=<id>, HS256 + RSA-OAEP-256/A256GCM
Flow Authorization Code + PKCE (login inclus) :
  JWE header : alg=RSA-OAEP-256 enc=A256GCM cty=JWT
  id_token déchiffré + signature HS256 vérifiée :
    iss=http://127.0.0.1:8000 aud=<id> sub=...
Bascule symétrique (PUT /register -> dir + A256CBC-HS512) :
  JWE header : alg=dir enc=A256CBC-HS512 cty=JWT
  id_token déchiffré + signature HS256 vérifiée :
    iss=http://127.0.0.1:8000 aud=<id> sub=...
Défense du serveur (module RSA de 1024 bits, RFC 7518 §4.3) :
  -> HTTP 400 : {"error": "invalid_client_metadata", ...}
```

## 3. Test automatisé (hermétique)

Le smoke test génère sa propre configuration (port dédié `8115`,
registration activée, algorithmes `RS256`/`HS*`, compte `alice`) et vérifie
aussi les défenses : clé RSA de 1024 bits, JWK `use: sig` pour `RSA-OAEP*`,
`id_token` altéré (rejet d'intégrité) et émission d'un `id_token` HS256 seul.

```bash
uv run python samples/id-token-algos-client/smoke_test.py
```

Sortie attendue :

```text
Scénario algorithmes d'id_token HS* + JWE (deadline=90s)...
  [1/7] discovery OK (HS256 + RSA-OAEP-256 + A256GCM annoncés)
  [2/7] POST /register asym + flow -> id_token JWE (RSA-OAEP-256/A256GCM) OK
  [3/7] PUT /register -> dir + A256CBC-HS512 (dérivé du secret partagé) OK
  [4/7] module RSA de 1024 bits -> 400 invalid_client_metadata (RFC 7518 §4.3) OK
  [5/7] clé RSA use:sig pour RSA-OAEP -> 400 invalid_client_metadata OK
  [6/7] id_token altéré -> déchiffrement rejeté (intégrité) OK
  [7/7] id_token HS256 seul (sans chiffrement) émis en JWS OK
=== SCÉNARIO OK en XX.Xs ===
```

## Vérification manuelle avec curl

```bash
# 1. enregistrer un client HS256 + RSA-OAEP-256 (jwks : clé publique RSA use enc >= 2048 bits)
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Authorization: Bearer dev-registrar-token" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["http://127.0.0.1:8000/callback"],
       "id_token_signed_response_alg": "HS256",
       "id_token_encrypted_response_alg": "RSA-OAEP-256",
       "id_token_encrypted_response_enc": "A256GCM",
       "jwks": {"keys": [{"kty": "RSA", "use": "enc", "alg": "RSA-OAEP-256", "kid": "idtoken-rsa", "n": "...", "e": "AQAB"}]}}'

# 2. jouer le flow Authorization Code + PKCE (login alice@example.com / password)
#    puis /token -> l'id_token retourné est un JWE compact à 5 segments
#    (alg=RSA-OAEP-256 enc=A256GCM cty=JWT) ; le déchiffrer passe par pyjwt + cryptography.
```

> L'`id_token` est d'abord **signé** (ici HS256 avec le `client_secret`,
> sinon RS*/PS*/ES* avec une clé serveur du JWKS), puis, si le client a déclaré
> un `id_token_encrypted_response_alg`, **chiffré** en JWE compact pour le
> client destinataire. Les clés JWKS enregistrées sont validées à la
> registration **et re-vérifiées à l'émission** : un module RSA < 2048 bits
> (RFC 7518 §4.3), une clé `use: sig` pour un `RSA-OAEP*`, ou l'absence de
> matériel exploitable sont rejetés (`invalid_client` /
> `invalid_client_metadata`).