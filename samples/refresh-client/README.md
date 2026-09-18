# Test manuel : refresh token avec rotation (RFC 6749 §6)

Script de démonstration/test manuel du **grant type `refresh_token`** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8101`, client public `sample-refresh-client` avec le scop
`offline_access`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `grant_types_supported` incluant `refresh_token` ;
2. `/authorize` émet un code d'autorisation (PKCE S256, client public) ;
3. `/token` échange le code → access_token, id_token **et refresh_token** ;
4. `/token` avec `grant_type=refresh_token` → nouveaux access_token et
   refresh_token (rotation : les valeurs diffèrent) ;
5. rejeu de l'ancien refresh token → `400 invalid_grant` (rotation) ;
6. refresh token inconnu → `400 invalid_grant` ;
7. refresh avec un scope restreint (`openid email`) → access_token au
   scope `email openid` (sous-ensemble accordé).

## Lancement

```bash
uv run python samples/refresh-client/smoke_test.py
```

Sortie attendue :

```text
Démarrage du serveur puridentityserver (config générée par le test)...
  [1/7] discovery OK ...
  [2/7] code d'autorisation émis (...)
  [3/7] échange code -> access_token + refresh_token OK
  [4/7] refresh -> nouveaux jetons (rotation) OK
  [5/7] rejeu de l'ancien refresh token -> 400 invalid_grant OK
  [6/7] refresh token inconnu -> 400 invalid_grant OK
  [7/7] refresh avec scope restreint (openid email) OK

=== SCÉNARIO OK en X.Xs ===
```

## Test manuel avec l'application web

L'application de démonstration [`app.py`](app.py) illustre le cycle
complet dans un navigateur. Le client `sample-refresh-client` est
**déjà enregistré dans la configuration par défaut du serveur**
([`config.toml`](../../config.toml) à la racine) :

```bash
# terminal 1 — serveur PurIdentityServer (port par défaut 8000)
uv run python -m puridentityserver

# terminal 2 — client de démonstration http://127.0.0.1:5174
uv run python samples/refresh-client/app.py
```

Parcours : « Se connecter » (login + consentement sur le serveur) →
le client affiche access_token et refresh_token → « Rafraîchir les
jetons » → rotation visible (nouveau refresh_token, compteur) → un
troisième clic échoue avec `400 invalid_grant` (rejeu interdit) →
« Se déconnecter (RP-Initiated Logout) » redirige vers l'`end_session`
du serveur (id_token_hint + URI de sortie + state), le cookie est effacé
et `/post-logout` (state rejoué) purge la session locale du client.

## Configuration

Le smoke test génère sa configuration (port dédié `8101`, clés de signature
limitées à `RS256` pour un démarrage rapide, client public unique) via
[`smoke_common.py`](../smoke_common.py). Aucun fichier
de configuration n'est committé par sample.

| Clé           | Valeur                                       |
| ------------- | -------------------------------------------- |
| `client_id`   | `sample-refresh-client`                      |
| `client_type` | `public` (aucun secret, PKCE obligatoire)    |
| `scope`       | `openid profile email offline_access`        |
| `redirect`    | `http://127.0.0.1:5174/callback`             |

Le fichier [`config.toml`](config.toml) du sample ne contient que les
réglages **client** de l'application `app.py` (comme `pkce-client`) :
issuer `http://127.0.0.1:8000`, port d'écoute `5174` et URI de sortie
`post_logout_redirect_uri` (doit figurer dans les
`post_logout_redirect_uris` du client côté serveur). Surchargeable via
`OIDC_SETTINGS_FILE`.