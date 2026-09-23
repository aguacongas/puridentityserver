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
| id_token HS*/JWE | registration RFC 7591 + flow code, `id_token` chiffré JWE | OIDC Core §3.1.3.6 |
| Rafraîchir | rotation du `refresh_token` | RFC 6749 §6 |
| Introspection | `POST /introspect` du dernier `access_token` | RFC 7662 |
| Révoquer | `POST /revoke` du dernier `access_token` | RFC 7009 |
| Supervision de session | iframe `check_session_iframe` + `session_state` | OIDC Session Management 1.0 §3.2 |
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

> La page construit son `redirect_uri` à partir de l'origine réellement
> ouverte (`window.location.origin`) : <http://127.0.0.1:5177> et
> <http://localhost:5177> fonctionnent tous les deux, les deux URIs étant
> déclarées dans `config.toml`. Pas de « redirect_uri mismatch » selon
> l'adresse tapée dans le navigateur.

### id_token HS* + JWE

Le bouton **id_token HS*/JWE** exerce la feature des algorithmes d'`id_token`
(issue #47) **depuis le navigateur** : la page génère une paire RSA-OAEP-256
(WebCrypto), **enregistre un client à la volée** (`POST /register`, RFC 7591,
avec le jeton d'inscription de la démo) demandant
`id_token_signed_response_alg: HS256` +
`id_token_encrypted_response_alg: RSA-OAEP-256` +
`id_token_encrypted_response_enc: A256GCM`, puis joue un flow Authorization
Code + PKCE (login inclus). Le serveur retourne un `id_token` **chiffré en
JWE compact** (en-tête `alg=RSA-OAEP-256`, `enc=A256GCM`, `cty=JWT`) : la page
décode et affiche l'en-tête JWE. Le **déchiffrement** et la **vérification de
la signature HS256** (secret partagé du client) sont démontrés par le sample
serveur [`samples/id-token-algos-client/`](../id-token-algos-client/README.md)
(Python + `cryptography`) — l'`id_token` *ne doit pas* être inspecté dans le
navigateur en production.

Prérequis : Dynamic Client Registration activée avec le jeton d'inscription
par défaut (`registration_enabled = true`,
`registration_initial_access_tokens = ["dev-registrar-token"]` dans
`config.toml`) — la configuration par défaut du dépôt les fournit.

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

> La supervision de session relève du navigateur (iframe + `postMessage` +
> cookie HttpOnly) : elle n'est pas couverte par le smoke test CORS ci-dessous.
> Le contrat serveur (paramètre `session_state` d'/authorize, page
> `/session_state`, endpoint `/check_session`) est couvert par
> `tests/test_session_management.py`.

### Supervision de session (Session Management — issue #62)

Le bouton **Supervision de session** exerce le **Session Management natif
navigateur** (OIDC Session Management 1.0) : le serveur est l'OP, la page
SPA joue la *relying party* qui garde l'œil sur sa session SSO.

1. **Lancement** : serveur démarré (port 8000) + page ouverte sur
   <http://127.0.0.1:5177>. Exécuter un flow connecté (**Se connecter**,
   **Implicit**, **Hybrid** ou **PAR**) et se connecter avec un compte de
   démo (`alice@example.com` / `password`).
2. **Config** : à la redirection de retour, le serveur ajoute le paramètre
   `session_state` à la réponse d'autorisation (query du code flow,
   fragment des flows à jeton) — la page le mémorise. La métadonnée
   `check_session_iframe` de `/.well-known/openid-configuration` pointe vers
   `http://127.0.0.1:8000/session_state`.
3. **Résultat attendu** : cliquer sur **Supervision de session** — la page
   embarque l'iframe d'état du serveur (cachée) et lui envoie toutes les
   5 s le message `postMessage("sample-spa-client <session_state>")`. Le
   serveur recalcule l'empreinte avec l'origine de la page (`event.origin`)
   et son propre cookie de session, puis répond `unchanged` — l'état
   s'affiche en vert, la session est toujours active.

**Changement d'état** : pendant que la supervision tourne, ouvrir
**Déconnexion** (RP-Initiated Logout) puis revenir sur la page : au sondage
suivant l'iframe répond `changed` — le serveur ne retrouve plus de session
active correspondant au `session_state` ; un vrai RP déclencherait alors
une ré-authentification silencieuse (`prompt=none`).

Note : rien d'identitaire ne transit par le postMessage ni par
`/check_session` — seule l'empreinte salée `session_state` est échangée,
et le cookie de session reste HttpOnly côté serveur (l'OP n'expose jamais
le `sid` au JavaScript, cf. spec §5.1 et §6).

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

> Le bouton **id_token HS*/JWE** relève du navigateur (WebCrypto + UI) : il
> n'est pas couvert par ce smoke test CORS. Le flow qu'il exerce (registration
> `HS256` + `RSA-OAEP-256`/`A256GCM`, flow code, bascule `dir`+`A256CBC-HS512`,
> défenses) est couvert de bout en bout par
> `uv run python samples/id-token-algos-client/smoke_test.py`.

## Quelles opérations

- **Se connecter / PAR / Implicit / Hybrid** : redirection navigateur vers
  `/login?next=<authorize>` de l'issuer, cookies de session posés côté
  serveur, retour sur la page. L'`id_token` est décodé et ses claims
  `iss`/`aud`/`nonce` vérifiés, `/userinfo` appelé avec le Bearer.
- **Appareil** : la page affiche `user_code` + URL de vérification ; ouvrir
  `verification_uri` dans un onglet, se connecter et saisir le code, puis
  regarder la page SPA recevoir les jetons au sondage suivant.
- **Supervision de session** : iframe OP cachée (`check_session_iframe`),
  `postMessage` de `client_id + session_state` toutes les 5 s, affichage de
  la réponse `unchanged` / `changed` / `error`. La déconnexion depuis le
  même navigateur fait basculer le statut sur `changed`.
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
| `registerToken` | `dev-registrar-token` | Initial access token de `POST /register` (config.toml) |
| `idTokenSigningAlg` | `HS256` | `id_token_signed_response_alg` du client enregistré |
| `idTokenEncryptionAlg` | `RSA-OAEP-256` | `id_token_encrypted_response_alg` (JWE) |
| `idTokenEncryptionEnc` | `A256GCM` | `id_token_encrypted_response_enc` (JWE) |

Les endpoints sont résolus dynamiquement depuis
`/.well-known/openid-configuration`.

## Limitations (documentées)

- **Signature de l'`id_token` non vérifiée** : un client de production doit
  valider le JWT contre les JWKS de l'issueur (lib du type `oidc-client-ts`).
  Ici seuls `iss`, `aud`, `nonce` et l'horodatage d'expiration des jetons
  sont contrôlés.
- **`id_token` chiffré non déchiffré** : le bouton HS*/JWE affiche l'en-tête
  JWE mais ne déchiffre ni ne vérifie l'`id_token` dans le navigateur (c'est
  le rôle du sample Python `id-token-algos-client`, WebCrypto n'étant pas
  utilisé pour la cryptographie JWE ici).
- **Client confidentiel de démo exposé** : uniquement pour exercer
  introspection/révocation/client_credentials dans le navigateur, et le
  `client_secret` du client enregistré par le bouton HS*/JWE vit dans la page
  (règle à ne pas reproduire en production).
- Le formulaire `/login` du serveur est une page HTML de démonstration ;
  une SSO réelle branchée sur ce SPA passerait par l'authentification du
  serveur.
- **Supervision de session en déploiement cross-site** : dans cette démo,
  SPA (`127.0.0.1:5177`) et serveur (`127.0.0.1:8000`) partagent le même
  site (`127.0.0.1`) : le cookie de session SameSite=Lax circule jusqu'à
  l'iframe du serveur. Un RP réel sur un domaine distinct se heurterait aux
  restrictions tierces (SameSite=Lax/None, ITP) décrites par la spec §5.1 —
  limitation documentée, pas un défaut de cette implémentation.