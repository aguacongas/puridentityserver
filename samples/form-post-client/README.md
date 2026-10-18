# Test manuel : response mode form_post (Form Post Response Mode 1.0)

Script de démonstration de la **response mode form_post** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` : port
`8121`, `require_login = true`, client seed public
`sample-form-post-client`) ainsi qu'un mini-callback local (port `8122`) qui
joue le rôle du RP côté navigateur — c'est lui qui reçoit le `POST`
`application/x-www-form-urlencoded` que la page de l'OP soumet
automatiquement. Puis il joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce `form_post` dans `response_modes_supported` ;
2. `/authorize` avec `response_mode=form_post` + `prompt=none` (sans
   session) → **200** (jamais `302`) : page HTML auto-soumise dont le
   formulaire porte `error=login_required` + `state` + `iss` vers la
   callback **nue**, avec les en-têtes `Cache-Control: no-cache, no-store`
   et `Pragma: no-cache` (Form Post §4) ;
3. la soumission du formulaire — comme le ferait le navigateur via
   `onload="document.forms[0].submit()"` — arrive au callback RP en
   `application/x-www-form-urlencoded` avec les mêmes paramètres
   (`error` / `state` / `iss`) que les transports `query`/`fragment` ;
4. `POST /login` (alice) → session authentifiée ;
5. `/authorize` avec `response_mode=form_post` → **200** : page
   auto-soumise portant `code` + `state` + `iss` en champs cachés,
   `action` = callback nue sans query ni fragment (aucun en-tête
   `Location` : pas de redirection 302) ;
6. soumission du formulaire reçue par le callback, puis `/token` échange
   du code (PKCE) → `200` access_token ;
7. une demande **sans** `response_type` + `form_post` → `200` avec
   `error=invalid_request` réfléchi dans le formulaire (RFC 6749 §4.1.2.1).

## Lancement

```bash
uv run python samples/form-post-client/smoke_test.py
```

Résultat attendu : les 7 étapes s'affichent avec `OK`, puis
`=== SCÉNARIO OK en <n>s ===`.

## À quoi sert form_post ?

Form Post Response Mode 1.0 (OpenID Foundation) fait voyager la **réponse
de l'endpoint d'autorisation** (code d'autorisation ou erreur redirigeable)
dans le **corps d'un `POST`** soumis par le user agent vers la
`redirect_uri`, au lieu d'une query string ou d'un fragment. L'OP renvoie
une page HTTP 200 contenant un formulaire à champs cachés et
l'auto-soumission (`onload="document.forms[0].submit()"`), avec repli
`<noscript>` (un client doit pouvoir traiter la réponse sans script,
§2) :

- le `code` et les jetons n'apparaissent **ni dans l'URL**, ni dans
  l'historique du navigateur, ni dans les logs serveur des requêtes
  (contrairement à `query`, contrairement aussi à `fragment` qui reste
  exposé à l'analyse des fragments côté client) — §4 exige d'ailleurs les
  en-têtes `Cache-Control: no-cache, no-store` / `Pragma: no-cache` pour
  que rien ne soit conservé ;
- `state` est toujours réfléchi, et `iss` accompagne la réponse comme les
  autres transports (RFC 9207 §2) ;

`response_mode=form_post` est déclaré dans `response_modes_supported` du
discovery et accepté aussi bien pour les `response_type` à défaut `query`
(`code`) que pour ceux à défaut `fragment` (`id_token token` — Form Post
§4 : le `POST` ne passe ni par la query ni par le fragment, la règle du
fragment n'a donc pas lieu de s'appliquer).

Dans un navigateur réel, aucune intervention n'est nécessaire : la page se
soumet d'elle-même. Le smoke test simule cette soumission en soumettant le
formulaire au callback, ce qui démontre le transport de bout en bout.

La certification locale rejoue ce transport avec le dédié
`bash certification/local/run-plan.sh formpost` (38 modules Basic dont la
variante `ResponseMode` est forcée à `form_post`).
