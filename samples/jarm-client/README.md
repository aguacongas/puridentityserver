# Test manuel : response mode JWT (JARM Final 1.0)

Script de démonstration de la **response mode JWT** (JARM — JWT Secured
Authorization Response Mode for OAuth 2.0) de PurIdentityServer. Il lance
un serveur en sous-processus avec une configuration **spécifique à ce
test** (générée par `smoke_common.py` : port `8120`, `require_login =
true`, client seed public `sample-jarm-client` avec
`authorization_signed_response_alg = "RS256"`, plus un second client sans
algorithme) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `jwt` dans `response_modes_supported` et publie
   `authorization_signing_alg_values_supported` (`PS256`/`ES256`/`RS256`) ;
2. `/authorize` avec `response_mode=jwt` + `prompt=none` (sans session) →
   `302` : l'URL ne porte **que** `?response=<jwt>` et l'enveloppe est une
   erreur `login_required` **signée** (kid opposable, vérifiable via le
   JWKS de l'OP) ;
3. `POST /login` (alice) → session authentifiée ;
4. `/authorize` + `prompt=none` avec session active : `max_age=1` dépassé
   (session vieillie) ou `acr_values` étranger → erreur
   `unmet_authentication_requirements` **signée** dans l'enveloppe (RFC 9470
   §2) — la session existe, seul le niveau demandé n'est pas atteint ;
5. `/authorize` avec `response_mode=jwt` → `302` : toujours uniquement
   `?response=<jwt>` (aucun `code`/`state` en clair, pas de fragment) ;
   l'enveloppe contient `code` + `state` avec `iss`, `aud` = client_id et
   `exp` - `iat` = 600 s ;
6. vérification de la signature de l'enveloppe contre le JWKS de l'OP
   (`kid` du header opposé à la clé publiée) ;
7. `/token` échange du code extrait de l'enveloppe (PKCE) → `200`
   access_token ;
8. un client **sans** `authorization_signed_response_alg` qui demande
   `response_mode=jwt` reçoit `unsupported_response_mode` en
   **transport clair** (le refus ne peut pas être porté par l'enveloppe
   qu'il refuse — JARM Final 1.0 §4).

## Lancement

```bash
uv run python samples/jarm-client/smoke_test.py
```

## À quoi sert JARM ?

JARM (JWT Secured Authorization Response Mode) enveloppe la **réponse de
l'endpoint d'autorisation** (code d'autorisation ou erreur redirigeable)
dans un JWT signé par l'OP, porté par le unique paramètre `response` de la
query string du callback. Le client reçoit un objet unique qu'il peut
vérifier (signature `kid` via le JWKS de l'OP, `iss`, `aud`, `exp`) avant
de l'utiliser : le `code` et les erreurs ne transitent plus en clair dans
l'URL, ni dans l'historique du navigateur.

L'algorithme de signature est déclaré **par client** via
`authorization_signed_response_alg` (JARM Final 1.0 §4.1) : `PS256`,
`ES256` ou `RS256` pour PurIdentityServer. Un client sans cet attribut
(ou avec un algorithme non signable) ne peut pas demander
`response_mode=jwt` : l'OP rejette la demande en `unsupported_response_mode`
en transport clair — le refus ne peut pas être porté par l'enveloppe qu'il
refuse.

Les erreurs redirigeables (`login_required`,
`unmet_authentication_requirements`, `access_denied`, …) sont **aussi**
signées dans l'enveloppe, conformément à JARM Final 1.0 §3 : le client
distingue une erreur authentique de l'OP d'une injection d'URL. Le code
`unmet_authentication_requirements` (RFC 9470 §2) signale une session
active dont le niveau demandé (`max_age`, `acr_values`) n'est pas atteint —
il diffère de `login_required`, qui suppose justement l'absence de session.
