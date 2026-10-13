# Certification OIDC (suite officielle OpenID Foundation)

Ce dossier contient tout ce qu'il faut pour faire tourner la suite de
certification OIDC officielle (<https://gitlab.com/openid/conformance-suite>)
contre une instance **publique** de PurIdentityServer, en CI ou en local.

L'OP étant testé **à distance** par la suite (l'OP doit recevoir des
redirections, des posts form_post et des appels du navigateur Selenium de la
suite), il faut que le serveur soit joint de l'extérieur. L'architecture
retenue :

1. l'OP est déployé sur **Render** (service gratuit, `storage_type = "sql"` /
   SQLite) — configuration committée dans `render.yaml` + `Dockerfile` +
   `certification/config.render.toml` ;
2. la suite de certification tourne dans le **runner GitHub** (docker) et est
   pilotée par `.github/workflows/certification.yml` via le script officiel
   `scripts/run-test-plan.py` de la suite ;
3. chaque run produit un rapport brut (artefact + commentaire) et une page
   **GitHub Pages** publique consolidée.

> Mode **witness** (PR 1) : le job CI est informatif, non bloquant. Le passage
> en gate bloquant sera ajouté quand les plans Core seront stables.

## Résultat attendu

- Le workflow `Certification OIDC` se termine avec, pour chaque plan
  (`oidcc-basic-`, `oidcc-implicit-`, `oidcc-hybrid-certification-test-plan`,
  `fapi-ciba-id1-test-plan` — witness CIBA, `fapi1-advanced-final-test-plan`,
  `fapi2-security-profile-final-test-plan`),
  le détail des modules testés et leur verdict (PASSED / FAILED / WARNING /
  REVIEW / SKIPPED) dans le résumé du run ;
- les artefacts `certification-results-<plan>` (un par plan) contiennent les
  exports bruts ; le job final les fusionne dans l'artefact
  `certification-results` ;
- l'artefact `certification-screenshots` contient les captures d'écran réelles
  téléversées aux modules de relecture (voir
  « Captures d'écran des modules de relecture ») ;
- une page `https://<owner>.github.io/puridentityserver/certification/`
  consolide les derniers résultats **et affiche, dans la section du module,
  la capture d'écran réelle téléversée** (fichiers aussi disponibles sous
  `<page>/screenshots/<testName>.png`).

## Mise en place (une fois)

1. **Créer le service Render** : sur <https://dashboard.render.com>,
   *New → Blueprint*, sélectionner ce dépôt (le `render.yaml` à la racine est
   lu automatiquement), ajouter le service `puridentityserver-certification`
   (plan free). L'instance est jointe sur
   `https://puridentityserver-certification.onrender.com`.
2. **Récupérer le Deploy Hook** : dans le service Render, *Settings → Deploy
   Hook*, copier l'URL.
3. **Ajouter les secrets/variables GitHub** :
   - secret `RENDER_DEPLOY_HOOK_URL` = URL du deploy hook (déclenche un
     redéploiement propre à chaque run) ;
   - variable `CERTIFICATION_OP_URL` =
     `https://puridentityserver-certification.onrender.com` (par défaut si
     absente).
4. **Activer GitHub Pages** : *Settings → Pages → Source: GitHub Actions*.

## Lancer un run

- **En CI** : *Actions → Certification OIDC → Run workflow* (ou laisser le
  cron hebdomadaire). Le workflow : attend que
  `/.well-known/openid-configuration` réponde (réveil de l'instance),
  photographie les `kid` du JWKS, déclenche le deploy hook puis patiente
  (15 min max) jusqu'à ce que les `kid` changent — preuve que le build est
  terminé **et** que le disque éphémère (donc l'état) a été recréé avant le
  premier enregistrement de client ; joue ensuite les **six plans en
  parallèle** (6 jobs matrix, `fail-fast: false` — ~40 min au lieu de ~3 h
  séquentielles, issue #122 ; les plans FAPI1 Advanced et FAPI2 Security
  Profile ont été ajoutés par l'issue #113), chaque plan exportant son propre
  artefact,
  puis un job final fusionne les exports, génère le rapport et déploie la
  page GitHub Pages.
- **En local** : (optionnel) pour reproduire le même principe contre un
  serveur local :

  ```bash
  # 1. configurer un mini-serveur public atteignable par la suite (ici Render)
  # 2. cloner et démarrer la suite, comme le workflow :
  git clone --depth 1 --branch release-v5.2.4 https://gitlab.com/openid/conformance-suite.git
  cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
  # 3. substituer {OPURL} et {SUITEURL} dans les plans puis jouer un plan :
  export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/
  export CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/
  sed -i "s#{OPURL}#https://mon-op.example#g; s#{SUITEURL}#$CONFORMANCE_SERVER#g" \
    ../certification/plans/*.json
  python3 scripts/run-test-plan.py \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]" \
    ../certification/plans/basic.json
  ```

## Rejeu local auto-hébergé (harness sans Render ni Fondation)

Le mode ci-dessus pilote un OP **public** (Render) avec la suite hébergée de la
Fondation. Le harness `certification/local/` fait mieux : il monte **toute** la
topologie en docker sur la machine (ou le runner CI), sans dépendre ni de
Render ni de l'infra de la Fondation — assurance conformité **courante et
déterministe**, en complément du run hébergé officiel.

Topologie (voir `certification/local/setup.sh`) :

```
driver (hôte) --API--> suite docker nginx :8443 (alias localhost.emobix.co.uk)
                              |
                     navigateur HtmlUnit (conteneur)
                              |
                     OP nginx mTLS :9443 (conteneur, alias réseau `op`)
                              |
                     OP uvicorn (hôte :8000)
```

- la **suite** (`release-v5.2.4`) tourne en docker (mongodb + server + nginx) ;
- l'**OP local** tourne sur l'hôte (uvicorn), avec une config générée à partir de
  `config.render.toml` (issuer `https://op:9443`, `redirect_uris` = callbacks de
  la **suite locale**, SQLite éphémère) ;
- un **nginx mTLS** (conteneur `op-mtls`, alias réseau `op` sur le réseau de la
  suite) termine le mTLS devant l'OP : certificat serveur auto-signé généré à la
  volée, certificat client **optionnel** (`optional_no_ca` — les plans FAPI1
  mélangent modules mTLS et `private_key_jwt`), cert extrait transmis via
  `X-SSL-Client-Cert` **URL-encodé** (`$ssl_client_escaped_cert`, dé-encodé par
  l'OP).

Lancer en local (Linux, prérequis : docker, uv, openssl) :

```bash
# 1. monter le harness (suite + OP + nginx mTLS) et attendre la disponibilité
bash certification/local/setup.sh

# 2. substituer les URLs LOCALES dans le plan puis jouer fapi1
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/
sed -i "s#{OPURL}#https://op:9443#g; s#{SUITEURL}#$CONFORMANCE_SERVER#g" \
  certification/plans/fapi1.json
# le driver tourne SANS token (la suite en mode dev injecte un utilisateur via
# DummyUserFilter) et ignore le cert auto-signé :
export CONFORMANCE_TOKEN="" DISABLE_SSL_VERIFY=1
git clone --depth 1 --branch release-v5.2.4 https://gitlab.com/openid/conformance-suite.git  # déjà cloné par setup.sh
# appliquer les 5 patches du driver (voir certification-local.yml), puis :
cd conformance-suite
python3 scripts/run-test-plan.py --export-dir ../results \
  "fapi1-advanced-final-test-plan[fapi_profile=plain_fapi][client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_response_mode=plain_response]" \
  ../certification/plans/fapi1.json
```

En CI : le workflow `Certification OIDC (local)`
(`.github/workflows/certification-local.yml`) exécute exactement cette séquence
en mode **witness** (les gaps module ne bloquent pas ; seule l'absence d'export
signale un crash du harness) et téléverse les exports + le rapport en artefacts
(pas de deploy Pages : le job hébergé en reste propriétaire). État attendu au
2026-10-13 : 46 modules, ~26 PASSED, ~16 REVIEW (pages d'erreur, captures de
secours), **3 FAILED = lacunes d'enforcement mTLS de l'OP** (holder-of-key :
accepte le mauvais certificat sur un jeton mTLS-bound, n'exige pas le cert au
refresh) — correctifs produit à venir, tolérés ici en witness.

## Rejeu local sans la suite

Le chantier « rejouer la certification OIDC en tests Python locaux » rejoue les
checks des plans Core, FAPI-CIBA-ID1 et **FAPI1 Advanced Final** (issue #110)
**sans docker ni suite de la Fondation** : les définitions
des modules (`release-v5.2.4`) ont été extraites dans
`tests/conformance/` (traçabilité complète : matrices module → test dans
`tests/conformance/TRACEABILITY.md`).

```bash
# rejeu in-process (FastAPI via ASGITransport) — 435 scénarios :
# 435 passed, 0 skipped
uv run --no-sync --no-build --locked python -m pytest -m conformance --no-cov -p no:cacheprovider

# variante contre un VRAI serveur uvicorn (sous-processus, port 8121,
# seeds alignés sur le harness) — même résultat, preuve du rejeu en réel
uv run python samples/conformance-smoke/smoke_test.py
```

- Les tests sont exclus du gate (`addopts` porte `-m "not conformance"`) et
  `--no-cov` est requis : ce sous-ensemble ne couvre pas le seuil de 80 %.
- **Plan FAPI1 (#110)** : `tests/conformance/test_plan_fapi1.py` rejoue
  106 exécutions (44 by-value + 62 pushed) sur les 63 modules applicables
  des 68 du plan (exclusions documentées dans `TRACEABILITY.md`) ; le plan
  de certification officiel est `certification/plans/fapi1.json` et le
  parcours de démonstration `samples/fapi1-client/`.
- **Plan FAPI2 (#111)** : `tests/conformance/test_plan_fapi2.py` rejoue
  les 61 scénarios consolidés des plans Final + ID2 (127 modules, 114
  applicables) → 107 tests (107 verts) ; le plan
  de certification officiel est `certification/plans/fapi2.json` et le
  parcours de démonstration `samples/fapi2-client/`.
- **Plus aucun skip** : `alg=none` est émis (id_token non signé) et les
  request objects `request`/`request_uri` (RFC 9101) sont traités — les 19
  scénarios qui sautaient (`oidcc-idtoken-unsigned` ×1, modules
  `request`/`request_uri` ×6 ×3 plans) rejouent pour de vrai, voir issue
  #76. L'access_token dans le corps de `/userinfo` est accepté (#83).
- Le smoke propage le code retour de pytest et borne la durée (`watchdog`) ;
  il sert de vérification « OP réel » du même rejeu.

## Dépannage

- **L'OP ne répond pas** : le service Render libre s'endort après ~15 min
  d'inactivité ; le workflow patiente (cold start ~1 min) avant d'échouer.
- **`DELETE /register/{client_id}` en 404 `invalid_client`** (module en
  WARNING « Error when calling registration_client_uri ») : le build Render
  démarre pendant que l'ancienne instance sert encore ; au swap, le disque
  éphémère est recréé et les clients enregistrés par la suite disparaissent.
  Le workflow déclenche donc le hook après le réveil (discovery) et attend le
  changement de `kid` du JWKS avant de lancer la suite — voir le run
  `36681480504` (`oidcc-response-type-missing`).
- **Module en état WAITING qui ne termine pas** : c'est le navigateur Selenium
  de la suite qui exécute les tâches `browser` du plan. Consulter le
  `log-detail.html` du module dans l'interface de la suite pendant le run
  (logs visibles dans l'étape du workflow) ; ajouter un
  `"browser": [...]` plus précis dans le plan concerné.
- **Module en `WAITING` jusqu'au timeout (tous les plans)** : la page
  `implicitCallback` de la suite (y compris en flux `code`) envoie la soumission
  implicite (`implicitSubmitUrl`) au `DOMContentLoaded`, mais HtmlUnit émet cette
  requête **après** `document.readyState == "complete"` ; si le WebRunner ferme le
  navigateur (`driver.close()` dans son `finally`) aussitôt, la requête est
  annulée, le test instance ne reçoit rien et le module reste en attente jusqu'au
  timeout. Chaque plan termine donc ses tâches `browser` par deux tâches ancrées
  sur le callback de la suite (`{SUITEURL}test/a/*/callback?*` puis `#*`,
  exclusives du callback d'erreur `…/callback/<aléatoire>` qui ne porte pas cette
  page), qui attendent le marqueur posé par la page
  (`["wait", "id", "submission_complete", 30]`), ajouté une fois l'envoi effectué
  (ou après le repli de 5 s de la page). Le `match` doit rester ancré : un
  `*callback*` matcherait aussi l'`/authorize` de l'OP (qui contient
  `redirect_uri=…/callback` dans sa query) et ferait échouer les tests en page
  d'erreur.
- **`sub` vide dans l'id_token** : l'instance n'a pas `require_login = true`
  (config.render.toml) — l'utilisateur anonyme reçoit un code sans sujet ;
  activer le réglage pour forcer la page `/login` (remplie par le `browser`
  du plan) avant toute émission.
- **Plan inconnu** : la version de la suite peut renommer un plan/sélecteur ;
  l'erreur de `run-test-plan.py` liste les identifiants disponibles.
- **Conflit d'alias entre plans** : deux plans qui partagent le même `alias`
  s'entre-stoppent sur l'instance hébergée (ou échouent en `409 ... alias ... in
  use`). Chaque plan doit porter un alias distinct ; le workflow applique le patch
  `conformance-reuse-plan.patch`, qui réutilise le plan existant (même config) au
  lieu de le recréer à chaque run. C'est aussi cette garantie qui rend la
  **parallélisation intra-run** sûre (issue #122) : les 4 jobs matrix ne
  partagent aucun alias et `release_alias` ne stoppe que le sien.
- **« Stopping test due to alias conflict »** : la suite réserve l'alias à la
  *création* de chaque module ; si le module précédent n'est pas encore terminé
  (timeout `CONFORMANCE_MODULE_TIMEOUT` dépassé, run annulé en cours de route…),
  elle l'interrompt avec ce message avant de laisser place au suivant. Le patch
  `conformance-alias-release.patch` fait l'inverse : le driver libère lui-même
  l'alias (`DELETE api/runner/{id}` + attente de l'état final) avant chaque
  création de module, et à la fin de chaque plan. Voir « Libération de l'alias ».
- **« has moved to INTERRUPTED » / « Timed out waiting »** : un module ne se
  termine pas. L'interruption vient soit d'un échec de *configuration/demarrage*
  (contrairement au conflit d'alias, où c'est le module **précédent** qui est
  arrêté), soit d'un module bloqué en `WAITING` (navigation/login côté navigateur
  de la Fondation) jusqu'au timeout. Le patch `conformance-interrupted-diagnostics.patch`
  complète le message de `wait_for_state` avec la cause réelle (statut, résultat,
  10 dernières entrées de `GET api/log/{id}`) pour la lire directement dans le log
  du job.
- **500 `test module not found`** : la suite hébergée a renommé ou supprimé un
  test alors que le plan réutilisé référence encore l'ancien id : chaque
  création de module échoue alors de façon déterministe (jusqu'à 28 réessais ×
  `CONFORMANCE_RETRY_TIMEOUT` par module). Le patch
  `conformance-stale-plan-recovery.patch` valide la membership du plan
  réutilisé contre le catalogue (`api/runner/available`) **avant** le run et
  recrée le plan si un module n'existe plus : la membership fraîche prend effet
  dès ce run (les tests renommés y repassent, les tests supprimés en
  disparaissent proprement). Ce 500 n'est jamais réessayé (1 tentative au lieu
  de 28). Le run suivant réutilise le plan ainsi recréé (plan le plus récent
  privilégié par `_plan_matching_configuration`).
- **« Aucun export pour le plan » (garde-fou du workflow)** : le plan a
  crashé avant tout module terminé (`run-test-plan` en code retour non nul,
  `results/` vide) alors que le job resterait vert en mode witness. Causes
  vécues (issue #113) : client statique absent de la config
  (« must contain a client configuration »), variante de plan manquante au
  sélecteur (« requires a value for variant … »), ou
  `ValidateMTLSCertificatesAsX509` en précondition échouée
  (« couldn't find required object … mutual_tls_authentication »). Corriger
  la config du plan (`plans/<plan>.json`, `config.render.toml`) ou le
  sélecteur de `certification.yml`.
- **`mtls` / `mtls2` obligatoires (plan fapi1)** : la suite FAPI1 Advanced Final
  valide le certificat client en X.509 à chaque module
  (`ValidateMTLSCertificatesAsX509`, precondition = interruption fatale même
  en mode continue) et lit `config.mtls.*` / `config.mtls2.*` — soit les clés
  de **racine** du plan (pas dans `client`) : `fapi1.json` porte `mtls`,
  `mtls2` et `mtls.ca`/`mtls2.ca` (certificats auto-signés PEM, clé PKCS8) ;
  `fapi2` n'a pas besoin de certs (contrôle conditionnel au variant
  `client_auth_type=mtls`).
- **Liaison mTLS des jetons (RFC 8705, issue #127)** : le flag
  `tls_client_certificate_bound_access_tokens` (par client) exige la
  présentation d'un certificat à chaque appel `/token` (et `/bc-authorize`),
  émet `cnf.x5t#S256` sur les access tokens et lie les refresh tokens au
  certificat d'émission. L'OP lit le PEM via deux sources : le contexte TLS
  direct d'uvicorn, ou — derrière un proxy de terminaison — les en-têtes
  dont les noms sont configurables (`client_certificate_header` /
  `client_certificate_dn_header` dans `config.toml`, défauts
  `X-SSL-Client-Cert` / `X-SSL-Client-S-DN`). Sur l'instance Render derrière
  Cloudflare : activer mTLS sur le hostname (CA managée — le certificat CF
  est alors injecté dans `mtls.cert`/`mtls.key` du plan — ou BYOCA, plan
  Enterprise), poser une Transform Rule RFC 9440 (`cf.tls_client_auth.cert`
  → `X-SSL-Client-Cert`, gate `cert_verified`, Remove avant Set), puis
  activer dans cet ordre : (1) CF mTLS + Transform Rules, (2) déploiement du
  code, (3) flip des seeds `config.render.toml`, (4) rejeu. **Plafond
  environnemental** : la liste de cipher du edge Cloudflare accepte un
  certificat ECDSA (`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`) que le check
  `DisallowInsecureCipher` (FAPI1-ADV-8.5-x, liste RSA-only) rejette — les
  modules `ensure-mtls-holder-of-key` / `bare` resterontFAILED sur ce seul
  check derrière CF ; le module `refresh-token` peut devenir 100 % vert.
  Démo locale hermétique : `samples/mtls-holder-of-key-client/` (en-têtes
  proxy personnalisés, PEM `\n`-échappé, 8 étapes).
- **OP déployé sans la config de la branche** (`error=invalid_client` au PAR) :
  `render.yaml` verrouille `branch: main` — le workflow ajoute `ref=$GITHUB_SHA`
  au deploy hook Render pour déployer le commit exact du run.
- **ERREUR sur Redis/nginx** : relancer ; le premier pull des images
  `registry.gitlab.com/openid/conformance-suite` est long (~10 min).

## Fichiers

| Fichier | Rôle |
| --- | --- |
| `render.yaml` / `Dockerfile` / `.dockerignore` | déploiement de l'OP sur Render (SQLite, disque éphémère) |
| `config.render.toml` | config de l'instance de certification (registre dynamique ouvert, users de démo, `require_login = true`, 4 clients statiques FAPI `private_key_jwt` + JWKS public pour les plans fapi1/fapi2) |
| `plans/basic|implicit|hybrid|ciba|fapi1|fapi2.json` | configs des plans de la suite (alias **unique par plan**, discovery, règles navigateur login/consent ; fapi1/fapi2 portent aussi `client`/`client2` en clé privée et `resource`) |
| `conformance-reuse-plan.patch` | patch du driver : `create_test_plan` idempotent (réutilise le plan existant quand sa config n'a pas changé) |
| `conformance-screenshots.patch` | patch du driver : remplit les placeholders REVIEW « capture d'écran » avec la **capture réelle** du module (`SCREENSHOTS_DIR/<testName>.png`) ou, à défaut, un PNG 1x1 de secours, après une période de tolérance `SCREENSHOT_FILL_GRACE` (60 s) pendant laquelle le module a le droit de se terminer seul, pour que les modules Core se terminent sans intervention humaine (mode witness) |
| `capture_screenshots.py` | rejoue les 4 scénarios de relecture contre l'OP déployé (Playwright/chromium headless) et dépose les PNG `screenshots/<testName>.png` ensuite téléversés par le driver |
| `conformance-alias-release.patch` | patch du driver : libère l'alias avant chaque création de module (et à la fin du plan), pour qu'un module encore actif ne soit jamais interrompu par « alias conflict » |
| `conformance-interrupted-diagnostics.patch` | patch du driver : quand un module est interrompu ou dépasse le timeout, affiche dans la CI la cause réelle (statut, résultat + 10 dernières entrées du journal du test) au lieu d'un simple « has moved to INTERRUPTED » / « Timed out waiting » |
| `conformance-stale-plan-recovery.patch` | patch du driver : n'est jamais réessaie le 500 déterministe « test module not found » (1 tentative au lieu de 28) et valide la membership du plan réutilisé contre le catalogue avant le run — recréation automatique du plan stale (membership fraîche dès le premier run), plan le plus récent privilégié à la réutilisation |
| `report.py` | génère la page statique GH Pages à partir des JSON exportés ; recopie les captures réelles dans `_site/screenshots/` (`--screenshots`) et les affiche dans la section du module correspondant |
| `local/setup.sh` | bootstrap du harness **auto-hébergé** : alias réseau, clone + déploiement docker de la suite, cert auto-signé + nginx mTLS `op`, config OP locale (issuer `https://op:9443`), OP uvicorn, attente de disponibilité |
| `local/nginx-mtls.conf` | nginx de terminaison mTLS devant l'OP local : certificat client optionnel (`optional_no_ca`), extraction `$ssl_client_escaped_cert` → `X-SSL-Client-Cert` (pas de newline brute), proxy vers l'OP uvicorn de l'hôte |
| `../.github/workflows/certification.yml` | workflow witness en 3 jobs : `prepare` (deploy + captures, une fois), `plan` (les 6 plans en parallèle, un job matrix chacun), `report` (fusion des exports + Pages) |
| `../.github/workflows/certification-local.yml` | workflow **auto-hébergé** witness (1 job fapi1) : `setup.sh`, substitution des URLs locales, 5 patches, run du plan, exports + rapport en artefacts (sans Pages) |

## Captures d'écran des modules de relecture (mode witness)

Certains modules Core s'arrêtent sur un événement **REVIEW** demandant une capture
d'écran : sans intervention, le driver attend jusqu'au timeout
`CONFORMANCE_MODULE_TIMEOUT` puis marque le module en échec. Sur l'instance hébergée,
l'« upload » se fait à la main via la console navigateur — impossible en CI. Les
quatre modules concernés (verdicts `review` du run de référence) captent chacun une
page différente de l'OP :

| Module | Page capturée |
| --- | --- |
| `oidcc-response-type-missing` | erreur 400 « Paramètres requis manquants : `response_type` » (avant login) |
| `oidcc-ensure-registered-redirect-uri` | erreur 400 `invalid_redirect_uri`, servie **après** login/consentement |
| `oidcc-prompt-login` | second formulaire de connexion (`prompt=login`) |
| `oidcc-max-age-1` | second formulaire de connexion (`max_age=1`, une seconde après le premier) |

Deux étapes couvrent ce besoin :

1. **`capture_screenshots.py`** (étape « Captures d'écran réelles des modules de
   relecture », `continue-on-error`) : enregistre un client via RFC 7591, rejoue les
   4 scénarios avec chromium headless contre `$OP_URL`, **contrôle chaque page avant
   export** (statut 400 + marqueur `<code>` du motif, ou titre et
   `form[action="/login"]`, sans redirection de l'erreur) puis dépose
   `screenshots/<testName>.png` — PNG sous les 500 Ko imposés par l'ImageAPI de la
   suite. Le callback des clients de capture est `https://rp.example.invalid/callback`
   (RFC 2606) : la navigation finale échoue au DNS, erreur que le script absorbe.
   Un échec (installation du navigateur, OP indisponible…) sort avec un code non nul,
   l'étape passe en warning et aucun PNG n'est produit : le run n'est jamais arrêté
   pour une capture.
2. **`conformance-screenshots.patch`** couple deux points du driver :
   - `conformance.py` : `screenshot_data_uri(test_name)` lit
     `SCREENSHOTS_DIR/<testName>.png` (répertoire fourni à l'étape des plans) ;
     `fill_required_screenshots(module_id, test_name)` liste les placeholders en
     attente (`GET api/log/{id}/images`, entrées avec le champ `upload`) puis les
     remplit (`POST api/log/{id}/images/{placeholder}`) avec cette **capture réelle**
     ou, si le fichier est absent/invalide, avec le **PNG 1x1 de secours** (data URI
     `image/png`) ;
   - `run-test-plan.py` : appel de cette méthode pour les modules purement OP
     (pas de client à piloter), **après une période de tolérance** puis l'attente de
     `FINISHED`.

Le remplissage déclenche `setTestReviewNeeded`, ce qui relance le module jusqu'à
son terme : le verdict reste `REVIEW` (la suite n'attend que le justificatif), mais
la preuve exhibée est désormais la page réellement servie par l'OP, téléversée dans
le même run. Le rapport la rend visible aux deux endroits où l'on regarde un run :
la **page GitHub Pages** (`report.py --screenshots` recopie les PNG dans
`_site/screenshots/` et les affiche dans la section du module) et l'artefact
`certification-screenshots`. Sans capture réelle, la capture de secours reste ce
qu'elle était : un artifice pour que la suite se termine et produise le rapport
complet.

Le remplissage **immédiat** est interdit : le watcher de placeholders
d'`AbstractTestModule` conclut le test dès que la liste est vide pendant que le
module est `WAITING`, donc la finalisation démarre pendant que le navigateur
scripté est encore actif — les modules qui passent ensuite par le callback
(ex. `oidcc-ensure-request-without-nonce-fails`) échouent alors avec
*« runInBackground called after runFinalisationTaskInBackground »*
(module `INTERRUPTED`). Le driver attend donc d'abord `FINISHED` pendant
`SCREENSHOT_FILL_GRACE` secondes (60 par défaut) et ne remplit les placeholders
qu'en cas de dépassement de ce délai ; seul ce dépassement de délai est
rattrapé silencieusement, les autres erreurs sont propagées.

## Alias des plans : création unique puis ré-exécution

Chaque plan porte un **alias stable et distinct** : `puridentityserver-basic`,
`puridentityserver-implicit`, `puridentityserver-hybrid`. Sur l'instance hébergée
de la Fondation, cet alias est l'identité du test : tous les modules créés depuis
un plan l'héritent, et la suite **stoppe (ou rejette en 409)** tout nouveau module
qui réclame un alias déjà en cours d'utilisation. D'où la règle : les trois plans
ne doivent jamais partager le même alias, et un plan ne doit pas être recréé à
chaque run.

Le patch `conformance-reuse-plan.patch` rend la création idempotente côté driver :
avant de POSTER `api/plan`, il liste les plans du user courant (`GET api/plan`) et
réutilise celui dont `planName` + config (alias, serveur, règles navigateur) **et**
variante sont strictement identiques. Un plan n'est donc créé **qu'une seule fois**,
puis ré-exécuté à chaque run ; il n'est recréé que si sa config a changé (ex. l'URL
de l'OP `CERTIFICATION_OP_URL` a bougé, ou les sélecteurs navigateur du plan ont
été modifiés), ce qui est le moyen voulu de déployer le changement.

## Libération de l'alias : plus de « Stopping test due to alias conflict »

La suite réserve l'alias **au moment de la création** de chaque module
(`TestRunner.createTestAlias`) : si le test qui détient encore l'alias n'est pas
`FINISHED` / `INTERRUPTED`, elle l'arrête avec
*« Stopping test due to alias conflict - before this test finished, you have
started another test using the same alias »*. Concrètement, cela se produisait
dans deux cas :

1. **un module dépasse `CONFORMANCE_MODULE_TIMEOUT`** (il reste `WAITING` /
   `RUNNING` côté Fondation) : le driver enregistre l'échec et crée le module
   suivant, ce qui interrompt le précédent ;
2. **un run est annulé en cours de route** (push pendant le run, job tué) : ses
   modules continuent de tourner sur l'instance et le run suivant les interrompt
   dès sa première création.

Le patch `conformance-alias-release.patch` ajoute `Conformance.release_alias(alias)` :

- `GET api/runner/running` ne renvoie que **nos** tests (filtre côté serveur sur le
  propriétaire) ; pour chacun, `GET api/info/{id}` donne `alias` + `status` ;
- tout test portant notre alias et non encore finalisé est arrêté par nos soins
  (`DELETE api/runner/{id}` → *« The test was requested to stop via the conformance
  suite API »*) puis suivi jusqu'à `INTERRUPTED` (timeout 180 s) ;
- l'appel est fait **avant chaque création de module** et **à la fin de chaque plan** :
  la revendication de l'alias se fait donc toujours sur un détenteur déjà finalisé,
  d'où plus jamais le message de conflit.

Deux compléments côté workflow : `concurrency.cancel-in-progress: false` sérialise
les runs (un run en cours n'est plus tué en laissant ses modules orphelins), et les
modules qui restent bloqués sont arrêtés à la fin du plan plutôt que d'attendre le
prochain run. Au sein d'un run, les plans parallèles (issue #122) ne se gênent pas :
alias distincts par plan + `release_alias` limité au sien.