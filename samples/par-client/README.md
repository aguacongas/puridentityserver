# Test manuel : Pushed Authorization Request (RFC 9126)

Script de démonstration de la **Pushed Authorization Request** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8105`, client seed `sample-par-client` *public* avec
`par_required = true`) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `pushed_authorization_request_endpoint` (`/par`) ;
2. `/authorize` **sans** `request_uri` (demande directe) → `400
   invalid_request` : le client exige PAR (RFC 9126 §6.1) ;
3. `POST /par` (form) → `201` `{request_uri, expires_in}` ; le
   `request_uri` est opaque (`urn:ietf:params:oauth:request_uri:<…>`) ;
4. `/authorize?client_id=…&request_uri=…` → `302` code d'autorisation
   (seuls ces deux paramètres sont acceptés) ;
5. `/token` échange du code (PKCE) → `200` access_token ;
6. réutilisation du même `request_uri` → `400 invalid_request` (usage
   unique, RFC 9126 §4) ;
7. `/authorize` avec `request_uri` + paramètre supplémentaire (ex.
   `scope`) → `400 invalid_request` (RFC 9126 §6.2).

## Lancement

```bash
uv run python samples/par-client/smoke_test.py
```

## À quoi sert PAR ?

PAR (RFC 9126) permet au client de pousser **en back-channel** les
paramètres de la demande d'autorisation (`POST /par`) et de ne transmettre
au navigateur / à l'endpoint `/authorize` qu'une référence opaque à usage
unique (`request_uri`). Les paramètres ne transitent plus en front-channel :
plus de fuite de `state`, `nonce` ou `code_challenge` dans l'historique ni
de manipulation possible par un tiers sur des paramètres poussés.

`par_required` (RFC 9126 §6.1, métadonnées client) force un client à
utiliser PAR : toute demande directe à `/authorize` (sans `request_uri`)
est rejetée en `invalid_request`. Cette obligation se configure **par
client** dans `config.toml` (ou via l'enregistrement dynamique, champ
`require_pushed_authorization_requests`).