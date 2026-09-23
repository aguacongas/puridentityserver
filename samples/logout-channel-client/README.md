# Test manuel : notification front/back-channel au logout (OIDC Session Management)

Sample de démonstration des **canaux de notification de déconnexion** de
PurIdentityServer : après l'émission d'un `sid` (Jeton de session OIDC,
Session Management 1.0 §2), le RP-Initiated Logout (`/end_session`)
prévient les autres applications de l'utilisateur que sa session a pris fin.

Deux mécanismes OIDC sont exercés de bout en bout :

- **Front-Channel Logout 1.0** — l'op affiche dans sa page de déconnexion
  une iframe invisible pointant vers la `frontchannel_logout_uri` du client
  (`GET /front-logout?sid=<sid>` quand `frontchannel_logout_session_required`
  est vrai) ; le user agent appelle automatiquement cette URI.
- **Back-Channel Logout 1.0** — l'op envoie directement (serveur à serveur)
  un `logout_token` signé RS256 (`POST /back-logout`, formulaiire
  `logout_token=…`) vers la `backchannel_logout_uri` du client.

## Lancement (automatique, bout en bout)

```bash
uv run python samples/logout-channel-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...

Scénario front/back-channel logout (RP listener 8200, OP 8105, deadline=60s)...
  [1/6] discovery : booleans front/back-channel logués
  [2/6] login -> cookie de session RS256 avec sid OK
  [3/6] authorize/token -> id_token sid=77864991... OK
  [4/6] /end_session -> notifications front/back déclenchées
  [5/6] back-channel : logout_token valide (iss/aud/sub/sid/events) OK
  [6/6] front-channel : iframe /front-logout?sid=<sid> chargée OK

=== SCÉNARIO OK en 8.8s ===
```

Ce que fait le scénario :

1. le discovery annonce `frontchannel_logout_supported`,
   `frontchannel_logout_session_supported`, `backchannel_logout_supported`
   et `backchannel_logout_session_supported` ;
2. connexion (`/login`) → cookie de session RS256 portant un `sid` ;
3. flux PKCE complet → `id_token` dont le claim `sid` vaut celui du cookie ;
4. `GET /end_session?id_token_hint=<id_token>&post_logout_redirect_uri=…` :
   l'op notifie le client en back-channel (POST `logout_token`), et la page
   affichée rend l'iframe `GET /front-logout?sid=<sid>` ;
5. le sample **vérifie le `logout_token` reçu** (signature via le JWKS de
   l'op, `iss`/`aud`/`sub`/`sid`/`events`/`jti`) ;
6. le smample simule le user agent en chargeant l'iframe et contrôle que la
   « RP » reçoit bien le `sid`.

## Configuration

Le smoke test génère sa configuration (port dédié `8105`, comptes
`alice@example.com` / `password`, client unique `sample-logout-channel-client`)
via [`smoke_common.py`](../smoke_common.py), et lance un mini serveur HTTP
dans un thread pour jouer les deux endpoints « RP » sur le port `8200`.
Aucun fichier de configuration n'est committé par sample.

| Clé | Valeur |
| ---- | ---- |
| `client_id` | `sample-logout-channel-client` |
| `client_type` | `confidential` (secret `logout-demo-secret`) |
| `frontchannel_logout_uri` | `http://127.0.0.1:8200/front-logout` |
| `frontchannel_logout_session_required` | `true` |
| `backchannel_logout_uri` | `http://127.0.0.1:8200/back-logout` |
| `post_logout_redirect_uris` | `http://127.0.0.1:5178/done` |

## Reproduction pas à pas avec le serveur par défaut (optionnel)

En local, sur un port dédié à la démo (port par défaut `8000` sinon) :

```bash
uv run python -m puridentityserver
```

Enregistrez un client qui pointe ses deux canaux vers vos propres endpoints
(ex. `http://127.0.0.1:9999/front` / …`/back`) et déclarez
`frontchannel_logout_session_required = true`. Ensuite, dans le navigateur :
connexion, puis n'importe quel flux d'autorisation ; notez le `sid` du
`id_token` (décodé par exemple avec `samples/id-token-algos-client/client.py`).
À la déconnexion (`/end_session?id_token_hint=<id_token>`), votre endpoint
front-channel doit recevoir `GET /front?sid=<sid>` et votre endpoint
back-channel un POST `logout_token` dont vous pouvez vérifier la signature
avec le JWKS de l'op.