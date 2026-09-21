# Client démo : SPA statique (tous les flows)

Page web **statique** (`index.html` + `app.js`, aucun framework, aucune
dépendance ni CDN) qui agit comme une *relying party* à l'intérieur du
navigateur et exerce **tous** les flows du serveur PurIdentityServer :

| Bouton | Flow | Référence |
| ------ | ---- | --------- |
| Se connecter | Authorization Code + PKCE | RFC 6749 §4.1 + RFC 7636 |
| Implicit | `id_token` + `access_token` dans le fragment | OIDC Core §3.2 |
| Hybrid | code + jetons en fragment, puis échange `/token` (PKCE) | OIDC Core §3.3 |
| PAR | requête poussée `POST /par` puis `/authorize?request_uri` | RFC 9126 |
| Appareil | `POST /device_authorization` + sondage `/token` | RFC 8628 |
| Client Credentials | flow machine à machine | RFC 6749 §4.4 |
| API protégée | flow code avec scope d'API puis appel de l'API échantillon qui valide le token | ApiResources |
| Rafraîchir | rotation du `refresh_token` | RFC 6749 §6 |
| Introspection | `POST /introspect` du dernier `access_token` | RFC 7662 |
| Révoquer | `POST /revoke` du dernier `access_token` | RFC 7009 |
| Déconnexion | RP-Initiated Logout via `/end_session` | OIDC Core §5.2 |

Le callback est géré **dans le navigateur** (pas de serveur applicatif) : le
serveur redirige le user agent vers l'URI racine `http://127.0.0.1:5177/` —
le `code` arrive en query, les jetons en fragment — et `app.js` détecte ce
retour à l'initialisation, échange le code, vérifie l'`id_token`
(`iss`/`aud`/`nonce`), récupère `/userinfo` et affiche le résultat.

## Lancement

Prérequis : serveur PurIdentityServer démarré (depuis la racine du dépôt).

```bash
uv run python -m puridentityserver
```

Le serveur enregistre par défaut le client de démo `sample-spa-client`
(redirection `http://127.0.0.1:5177/`, `web_origins`
`http://localhost:5177`) dans [`config.toml`](../../config.toml). Le CORS est
**dérivé des URIs du client** : les origines `127.0.0.1:5177` et
`localhost:5177` sont autorisées sans liste statique à maintenir.

Démarrer la page statique :

```bash
python -m http.server 5177 --directory samples/spa-client
```

Ouvrir <http://127.0.0.1:5177> et cliquer sur **Se connecter**. Sur la page
de login du serveur, utiliser un compte de démonstration :

- `alice@example.com` / `password` — rôle `admin`
- `bob@example.com` / `password` — rôle `user`

### API protégée

Le bouton **API protégée** exerce la feature ApiResources : la page lance
un flow Authorization Code + PKCE avec les scopes `openid api.read`, reçoit
un access token dont l'`aud` porte la ApiResource `sample-api`, puis appelle
l'API protégée de démonstration. Il faut l'avoir démarrée dans un terminal :

```bash
# terminal 2 — API protégée échantillon (port 8120)
uv run python samples/api-resources-client/api_server.py
```

Celle-ci **valide le token** reçu (`Authorization: Bearer`) : signature
contre les JWKS de l'issuer, `iss` exact, expiration, `aud` = `sample-api`,
scope `api.read` requis — et répond `200` avec les claims du jeton, ou
`401 invalid_token` / `403 insufficient_scope`. La première demande vous
fait passer par la page de consentement, qui liste aussi les scopes d'API.
Voir [samples/api-resources-client/](../api-resources-client/README.md).

## Smoke test

Un test de bout en bout lance le serveur avec la configuration dédiée
(port 8117, client seed SPA) et vérifie que le **CORS est dérivé des URIs du
client** : discovery avec l'origine `http://127.0.0.1:5177`, prelude
`OPTIONS /token` depuis cette origine et depuis l'alias `localhost:5177`
(`web_origins`) -> `200`, origine étrangère -> `400` sans en-tête CORS, puis
`POST /token` (grant invalide) -> réponse du serveur **avec** les en-têtes
CORS (requête simple autorisée). Garde-fou temporel de 60 s.

```bash
uv run python samples/spa-client/smoke_test.py
```

## Quelles opérations

- **Se connecter / PAR / Implicit / Hybrid** : redirection navigateur vers
  `/login?next=<authorize>` de l'issuer, cookies de session posés côté
  serveur, retour sur la page. L'`id_token` est décodé et ses claims
  `iss`/`aud`/`nonce` vérifiés, `/userinfo` appelé avec le Bearer.
- **Appareil** : la page affiche `user_code` + URL de vérification ; ouvrir
  `verification_uri` dans un onglet, se connecter et saisir le code, puis
  regarder la page SPA recevoir les jetons au sondage suivant.
- **API protégée** : flow code avec scopes `openid api.read`, puis appel de
  `GET /api/data` sur l'API échantillon (`api_server.py`) qui vérifie la
  signature JWKS, `iss`/`exp`/`aud` et le scope; le résultat s'affiche
  dans le journal et la carte de résultat.
- **Client Credentials / Introspection / Révocation** : recourent au client
  **confidentiel de démo** `sample-cc-client` (identité d'un serveur de
  ressources). Le secret est **en clair dans le code** : c'est une
  démonstration, jamais un modèle de production.

## Configuration

Au sommet d'`app.js`, la constante `SPA_CONFIG` :

| Clé | Valeur par défaut | Rôle |
| --- | ----------------- | ---- |
| `issuer` | `http://127.0.0.1:8000` | Issuer (URL de base du serveur) |
| `clientId` | `sample-spa-client` | Client public dont la redirection est enregistrée |
| `redirectUri` | `http://127.0.0.1:5177/` | URI de callback (racine, servie par la page) |
| `postLogoutRedirectUri` | `http://127.0.0.1:5177/` | URI de retour du logout |
| `scope` | `openid profile email offline_access` | Scopes demandés au login |
| `ccClientId` / `ccClientSecret` | `sample-cc-client` / `cc-demo-secret` | Client confidentiel de démo |
| `apiBaseUrl` | `http://127.0.0.1:8120` | API protégée de démonstration (voir ci-dessous) |
| `apiResource` | `sample-api` | ApiResource attendue dans l'`aud` du token |
| `apiScope` | `openid api.read` | Scopes demandés par le bouton API protégée |

Les endpoints sont résolus dynamiquement depuis
`/.well-known/openid-configuration`.

## Limitations (documentées)

- **Signature de l'`id_token` non vérifiée** : un client de production doit
  valider le JWT contre les JWKS de l'issueur (lib du type `oidc-client-ts`).
  Ici seuls `iss`, `aud`, `nonce` et l'horodatage d'expiration des jetons
  sont contrôlés.
- **Client confidentiel de démo exposé** : uniquement pour exercer
  introspection/révocation/client_credentials dans le navigateur.
- Le formulaire `/login` du serveur est une page HTML de démonstration ;
  une SSO réelle branchée sur ce SPA passerait par l'authentification du
  serveur.