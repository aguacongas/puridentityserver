# Authentification client JWT + grant jwt-bearer (RFC 7523, issue #46)

Script de démonstration des briques **#46** de PurIdentityServer : le client
**machine à machine** s'authentifie au token endpoint **sans jamais envoyer
son secret en clair**, puis délègue un `sub` (un utilisateur) à un jeton.

Deux mécanismes OAuth 2.0 / OIDC sont exercés :

1. **`client_secret_jwt`** (RFC 7523 §2.2) : méthode d'authentification client
   où le secret partagé HMAC n'est prouvé qu'à travers une **assertion JWT**
   (`client_assertion`). Le client est enregistré avec la métadonnée
   `token_endpoint_auth_method: "client_secret_jwt"` ; le serveur stocke son
   secret **chiffré au repos** (RSA-OAEP, clé de scellement auto-rotée) et ne
   le rend en clair qu'une seule fois, à la registration.
2. **Grant `jwt-bearer`** (RFC 7523 §2.1) : une assertion signée du client
   (`iss` = client, `sub` = utilisateur délégué, `aud` = token endpoint) est
   échangée contre un access token émis **au nom de ce `sub`**.

Le scénario complet (registration dynamique incluse) est aussi joué en auto
par `smoke_test.py`.

## 1. Lancement du serveur

La configuration **par défaut** active déjà la registration dynamique ; la
clé de scellement des secrets (`KeyUse.SECRET`) est **générée
automatiquement** au démarrage et tourne suivant `jwks_rotation_days` —
aucune clé à fournir :

```bash
# terminal 1 - serveur de développement (port 8000 par défaut)
uv run python -m puridentityserver
```

> La rotation de cette clé est transparente pour le client : elle ajoute une
> clé sans jamais en purger, puis chaque `PUT /register/{client_id}` d'un
> client `client_secret_jwt` **re-scellé** son secret sous la clé récente
> (aucun secret ré-émis). Une fois le drain terminé, l'ancienne clé peut être
> retirée manuellement de la table `key_pairs`. Optionnellement,
> `PURIDENTITYSERVER_CLIENT_SECRET_SEAL_KEY_PEM` permet de seed une clé privée
> (mondes déterministes / serveurs en mémoire).

## 2. Le client de démonstration

```bash
# terminal 2 - enregistrement + deux flux #46
uv run python samples/jwt-bearer-client/client.py
```

Étapes exécutées :

1. `GET /.well-known/openid-configuration` : vérifie que
   `urn:ietf:params:oauth:grant-type:jwt-bearer` et `client_secret_jwt` sont
   annoncés ;
2. `POST /register` (RFC 7591) : création du client avec
   `token_endpoint_auth_method: "client_secret_jwt"` → `client_id` +
   `client_secret` (émis **une seule fois** en clair) ;
3. **grant jwt-bearer** : `POST /token` avec `assertion` signée HS256
   (`iss`=client, `sub`=alice, `aud`=token endpoint) → access token dont le
   `sub` est celui l'utilisateur délégué (Alice) ;
4. **client_secret_jwt** : `POST /token` du grant `client_credentials`
   authentifié par `client_assertion` au lieu du `client_secret` → access
   token dont le `sub` est le client lui-même.

Sortie attendue :

```text
Registration (RFC 7591) : client_id=<id>, auth=client_secret_jwt
Grant jwt-bearer contre http://127.0.0.1:8000 : token au nom de alice
  scope     : openid profile email
client_secret_jwt (RFC 7523 §2.2) : token au nom du client lui-même
  scope     : openid profile email

Claims du access_token (décodés, non vérifiés - démo) :
{ ... "sub": "alice", ... }
```

## 3. Test automatisé (hermétique)

Le smoke test génère sa propre configuration (port dédié `8114`,
registration activée) et vérifie aussi les cas d'erreur : assertion expirée,
`aud` éronée, client inconnu, et le **drain** d'une rotation (un `PUT` sans
secret re-scellé le ciphertext sans ré-émettre le secret).

```bash
uv run python samples/jwt-bearer-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...
  [1/8] discovery OK (grant jwt-bearer + client_secret_jwt annoncés)
  [2/8] POST /register client_secret_jwt -> 201 (client_id=<id>, secret émis une seule fois, chiffré au repos)
  [3/8] grant jwt-bearer -> access_token au sub d'Alice OK
  [4/8] client_credentials via client_assertion (client_secret_jwt) OK
  [5/8] PUT /register sans secret -> 200 (ciphertext re-scellé, secret conservé)
  [5/8] grant jwt-bearer toujours OK après le re-scellement
  [6/8] assertion expirée -> 400 invalid_grant OK
  [7/8] assertion avec aud éronée -> 400 invalid_grant OK
  [8/8] assertion d'un client inconnu -> 400 invalid_client OK
=== SCÉNARIO OK en X.Xs ===
```

## Vérification manuelle avec curl

```bash
# 1. enregistrer un client client_secret_jwt (secret à conserver)
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Authorization: Bearer dev-registrar-token" \
  -H "Content-Type: application/json" \
  -d '{"token_endpoint_auth_method": "client_secret_jwt", "scope": "openid profile"}'

# 2. échanger une assertion jwt-bearer (remplacez client_id / assertion)
curl -s -X POST http://127.0.0.1:8000/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "client_id=<client_id>" \
  --data-urlencode "assertion=<assertion JWT signée HS256 avec le client_secret>"
```

> L'assertion est un JWT (HS256) : `{"iss": "<client_id>", "sub": "alice",
> "aud": "http://127.0.0.1:8000/token", "exp": <now+600>, "iat": <now>}`
> signé avec le `client_secret` retourné à la registration. Après expiration
> ou avec une `aud`/un `iss` invalides, `/token` répond `400 invalid_grant` /
> `invalid_client`.