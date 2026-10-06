# Test manuel : CIBA — Client-Initiated Backchannel Authentication

Script de démonstration/test manuel du **CIBA** (OIDC CIBA 1.0) : le
client initie une authentification en back-channel, l'utilisateur
approuve la demande côté serveur, puis le client récupère les jetons
sans redirection navigateur.

## Principes

1. le client envoie une `backchannel authentication request` à
   `POST /bc-authorize` (authentification Basic, `login_hint`) et
   reçoit un `auth_req_id` (+ `expires_in`, `interval`) ;
2. la demande est approuvée via l'endpoint démo
   `POST /ciba/approve?token=<auth_req_id>&type=allow` (ou `deny`) ;
3. le client boucle en poll sur `/token` (grant
   `urn:openid:params:grant-type:ciba`) jusqu'à obtenir les jetons
   (`authorization_pending`, `slow_down` + 5 s, puis succès ou refus) ;
4. en mode **ping**, le serveur notifie en plus le client par un POST
   JSON sur `backchannel_client_notification_endpoint` (avec
   `Authorization: Bearer <client_notification_token>`) avant le poll.

## Prérequis

- Serveur PurIdentityServer lancé sur `http://127.0.0.1:8000` avec les
  réglages CIBA actifs et les clients seedés (défauts du `config.toml`
  racine : `ciba_enabled = true`, `ciba_approval_enabled = true`,
  `sample-ciba-client` + `sample-ciba-ping-client`) ;
- profil `alice` dans `users_seed` (`alice.martin@example.com`) — le
  `login_hint` est résolu contre le user store.

```sh
python -m puridentityserver
```

## Exécution du client (mode poll)

```sh
cd samples/ciba-client
python client.py
```

Le client affiche l'`auth_req_id` puis la commande `curl` équivalente ;
appuyez sur Entrée pour approuver (ou `n` pour refuser), les jetons
s'affichent ensuite dans le terminal.

> Pour tests, les défauts sont : `CIBA_ISSUER=http://127.0.0.1:8000`,
> `CIBA_CLIENT_ID=sample-ciba-client`,
> `CIBA_CLIENT_SECRET=ciba-demo-secret`,
> `CIBA_LOGIN_HINT=alice.martin@example.com`.

## Approbation manuelle (autre terminal)

```sh
curl -X POST "http://127.0.0.1:8000/ciba/approve?token=<auth_req_id>&type=allow"
```

Réponse `200` vide ; `type=deny` provoque `access_denied` au poll
suivant. L'endpoint est protégé par le flag `ciba_approval_enabled`
(sans le flag : `404`).

## Mode ping

```sh
CIBA_MODE=ping CIBA_CLIENT_ID=sample-ciba-ping-client \
  CIBA_CLIENT_SECRET=ciba-ping-demo-secret python client.py
```

Le client démarre un listener local sur le port 8118 (endpoint
`http://127.0.0.1:8118/notify` déclaré sur `sample-ciba-ping-client`) :
la notification JSON du serveur s'affiche, puis les jetons sont
récupérés par poll. `CIBA_NOTIFY_PORT` change le port d'écoute.

## Mode signé (FAPI-CIBA-ID1 — request object JAR)

```sh
CIBA_SIGNED=1 python client.py
```

Le client s'enregistre d'abord par **Dynamic Client Registration**
(`POST /register`, Bearer `CIBA_REGISTRATION_TOKEN`, défaut
`dev-registrar-token`) avec une **clé RSA éphémère générée à la volée**
(JWKS embarqué, aucune clé écrite sur disque), puis :

- envoie la backchannel request sous la forme FAPI-CIBA-ID1
  `{request, client_assertion, client_assertion_type}` — le
  `request` est un **JWT signé PS256** (`iss`/`aud` = client/issuer,
  `exp − nbf ≤ 60 min`, `jti` anti-replay) portant `scope`,
  `login_hint`… — **sans `client_id` ni secret dans le corps** :
  le serveur déduit l'appelant de l'`iss` de l'assertion puis vérifie
  la signature du request object ;
- authentifie son poll `/token` par `client_assertion` (RFC 7523).

Toute défaillance du JAR (signature, `iss`, `aud`, `exp`, `jti`
réjoué, alg non enregistré…) répond `invalid_request` en 400. Le
discovery publie les algos admis dans
`backchannel_authentication_request_signing_alg_values_supported`
(PS256, ES256, RS256).

> `CIBA_REGISTRATION_TOKEN` = token d'inscription initial (config
> racine : `registration_enabled = true` +
> `registration_initial_access_tokens = ["dev-registrar-token"]`).

## Smoke test

Le smoke test enchaîne deux scénarios de façon automatique (port dédié
8116, aucun impact sur le serveur courant) :

```sh
cd samples/ciba-client
python smoke_test.py
```

Scénario non signé (4 étapes) : discovery (métadonnées CIBA),
`/bc-authorize` (`auth_req_id`), `/ciba/approve`, `/token`
(`access_token` + `id_token`).

Scénario signé (6 étapes) : discovery (algos de signature), DCR
(`private_key_jwt` + PS256), rejet d'une demande **non** signée
(`invalid_request` 400), `/bc-authorize` avec `request` signé,
approbation, poll authentifié par assertion → jetons.
