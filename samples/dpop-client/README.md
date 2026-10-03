# Test manuel : extension DPoP (RFC 9449)

Script de démonstration de l'extension **DPoP** (Demonstrating Proof-of-Possession
at Proof of Possession) de PurIdentityServer. Il lance un serveur en
sous-processus avec une configuration **spécifique à ce test** (générée par
`smoke_common.py` : port `8110`, client seed `sample-dpop-client` *public* avec
`require_dpop = true`) puis joue le scénario complet : le client signe une
preuve `dpop+jwt` (clé EC P-256) et le serveur lie l'access token à cette clé.

Le scénario vérifie :

1. le discovery annonce `dpop_signing_alg_values_supported` (algorithmes
   asymétriques — `none` et les familles symétriques HS* sont exclus) ;
2. `/token` **sans** preuve DPoP → `400 invalid_request` : le client exige une
   preuve (RFC 9449 §5.2, drapeau `require_dpop`) ;
3. `/token` avec une preuve valide → `200` `token_type: DPoP` et access token
   lié (claim `cnf.jkt`, RFC 9449 §5.1) ;
4. rejeu de la même preuve (`jti` déjà présenté) → `400 invalid_dpop_proof`
   (anti-replay, RFC 9449 §11) ;
5. `/userinfo` du jeton lié avec le scheme `Bearer` → `401` +
   `WWW-Authenticate: DPoP error="invalid_token"` (RFC 9449 §7.2) ;
6. `/userinfo` avec le scheme `DPoP` + preuve portant `ath` → `200` (claims) ;
7. grant `refresh_token` : sans preuve → `400 invalid_request` (refresh lié),
   avec preuve → `200` `token_type: DPoP` — le lien se conserve au
   renouvellement (RFC 9449 §5.1) ;
8. `/authorize` avec `dpop_jkt` (autre clé) puis `/token` avec la preuve d'une
   autre clé → `400 invalid_grant` (mismatch d'empreinte, RFC 9449 §10).

## Lancement

```bash
uv run python samples/dpop-client/smoke_test.py
```

Attendu : `=== SCÉNARIO OK en <n>s ===` (8 étapes `[1/8]` à `[8/8]`).

## À quoi sert DPoP ?

DPoP (RFC 9449) prouve la **possession** du token : le client signe une preuve
(asymétrique, un par appel) et le serveur émet un access token **lié** à la
clé publique de cette preuve (`cnf.jkt` + `token_type: DPoP`). Un token volé
(intercepté en log, en fuite de mémoire, via un XSS…) ne peut plus être rejoué
sans la clé privée : chaque ressource vérifie que la preuve présentée est
signée par la clé liée au jeton.

Points du scénario, par clause RFC 9449 :

- **§5.2** `require_dpop` (par client, `config.toml` ou enregistrement
  dynamique `dpop_bound_access_tokens`) force une preuve à chaque appel au
  token endpoint — sans elle, `invalid_request` ;
- **§5.1** le jeton émis porte `cnf.jkt` (empreinte RFC 7638 de la clé) et
  `token_type: DPoP`, au premier échange comme au renouvellement du refresh ;
- **§11** le `jti` de chaque preuve est mémorisé (anti-replay) : rejouer la
  même preuve vaut `invalid_dpop_proof` ;
- **§7** `/userinfo` exige le scheme `DPoP` + une preuve `ath` (empreinte du
  jeton présenté) pour un jeton lié — le scheme `Bearer` est refusé avec un
  challenge `DPoP error="invalid_token"` ;
- **§10** `dpop_jkt` à `/authorize` (ou `/par`) lie d'emblée la demande à une
  clé : une preuve d'une autre clé au `/token` vaut `invalid_grant`.

Le serveur gère DPoP pour **tous** les clients (preuve facultative et donc
jeton porteur `Bearer` par défaut) ; `require_dpop = true` est le drapeau qui
rend la preuve **obligatoire** pour un client donné.
