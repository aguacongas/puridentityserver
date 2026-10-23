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
   pilotée par deux workflows partageant les mêmes plans :
   `.github/workflows/certification.yml` (**Certification OIDC**, instance
   hébergée de la Fondation, à la demande) et
   `.github/workflows/certification-local.yml` (**Certification OIDC
   (Local)**, harness auto-hébergé) — via le script officiel
   `scripts/run-test-plan.py` de la suite ;
3. chaque run du workflow **local** produit un rapport brut (artefact) et
   publie une page **GitHub Pages** publique consolidée — sauf sur les PR,
   qui ne publient qu'en artefact. Le workflow hébergé ne publie plus sur
   Pages : ses résultats seront soumis directement à l'OpenID Foundation
   (à venir, issue #150).

> Sortie **stricte** (workflow local, issue #130) : chaque job plan échoue
> dès qu'un module est FAILED ou INTERRUPTED (ou que le driver remonte un
> warning inattendu) — le run `Certification OIDC (Local)` est alors rouge,
> même si le rapport GitHub Pages reste publié. Les modules REVIEW (relecture
> humaine, captures d'écran) restent tolérés. Le workflow hébergé reste en
> mode witness et ne s'exécute plus qu'à la demande.

## Résultat attendu

- Le workflow `Certification OIDC (Local)` se termine avec, pour chaque plan
  (`oidcc-basic-`, `oidcc-implicit-`, `oidcc-hybrid-`, `oidcc-formpost-basic-`,
  `oidcc-dynamic-certification-test-plan`, `fapi-ciba-id1-test-plan`,
  `fapi1-advanced-final-test-plan`, `fapi2-security-profile-final-test-plan`,
  `fapi2-message-signing-final-test-plan`, `ekyc-test-plan-oidccore`,
  `openid-federation-entity-joined-to-test-federation-op-test-plan`),
  le détail des modules testés et leur verdict (PASSED / FAILED / WARNING /
  REVIEW / SKIPPED) dans le résumé du run ;
- les artefacts `certification-local-results-<plan>` (un par plan) contiennent
  les exports bruts ; le job final les fusionne dans l'artefact
  `certification-local-report` ;
- une page `https://<owner>.github.io/puridentityserver/certification/`
  consolide les derniers résultats (publish réservé aux runs sur `main` ou
  lancés à la main) ; les **captures d'écran réelles** des modules de
  relecture sont produites par le workflow local lui-même (artefact
  `certification-local-screenshots`, issue #158) et affichées dans la page
  (`<page>/screenshots/<testName>.png`) ; le run hébergé les publie aussi
  dans son artefact `certification-screenshots` ;
- le workflow hébergé `Certification OIDC` téléverse ses exports
  (`certification-results-<plan>` puis `certification-results`) et l'artefact
  `certification-screenshots` (captures réelles des modules de relecture,
  voir « Captures d'écran des modules de relecture ») — sans publication
  Pages (issue #150).

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

- **En CI — local (courant)** : automatique à **chaque merge sur `main`**
  (sans filtre de chemins) et sur chaque PR touchant `certification/**` ;
  manuellement : *Actions → Certification OIDC (Local) → Run workflow* avec
  le plan souhaité (défaut : les neuf). Seuls les runs sur `main` ou lancés à
  la main publient sur GitHub Pages.
- **En CI — hébergé (à la demande)** : *Actions → Certification OIDC → Run
  workflow* (plus de cron ni de déclenchement au merge pour l'instant — le
  déclenchement automatique reviendra à la publication d'une release,
  issue #150). Le workflow : attend que
  `/.well-known/openid-configuration` réponde (réveil de l'instance),
  photographie les `kid` du JWKS, déclenche le deploy hook puis patiente
  (15 min max) jusqu'à ce que les `kid` changent — preuve que le build est
  terminé **et** que le disque éphémère (donc l'état) a été recréé avant le
  premier enregistrement de client ; joue ensuite les **onze plans en
  parallèle** (11 jobs matrix, `fail-fast: false` — ~40 min au lieu de ~3 h
  séquentielles, issue #122 ; les plans FAPI1 Advanced, FAPI2 Security
  Profile, FAPI2 Message Signing (JARM, issue #164), Form Post
  (issue #165), Dynamic (issue #168) et Federation (issue #170) ont été
  ajoutés par les issues #113, #164, #165, #168 et #170), chaque
  plan exportant son propre
  artefact, puis un job final fusionne les exports et téléverse le rapport
  consolidé en artefact.
- **En local** : (optionnel) pour reproduire le même principe contre un
  serveur local :

  ```bash
  # 1. configurer un mini-serveur public atteignable par la suite (ici Render)
  # 2. cloner et démarrer la suite, comme le workflow (release-vX.Y.Z = dernière
  #    release publiée : les workflows la résolvent à l'exécution via
  #    git ls-remote, cf. issue #150 ; l'exemple ci-dessous la pinne) :
  git clone --depth 1 --branch release-v5.3.3 https://gitlab.com/openid/conformance-suite.git
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

- la **suite** (dernière release publiée, ex. `release-v5.3.3`) tourne en docker (mongodb + server + nginx) ;
- l'**OP local** tourne sur l'hôte (uvicorn), avec une config générée à partir de
  `config.render.toml` (issuer `https://op:9443`, `redirect_uris` = callbacks de
  la **suite locale**, SQLite éphémère) ;
- un **nginx mTLS** (conteneur `op-mtls`, alias réseau `op` sur le réseau de la
  suite) termine le mTLS devant l'OP : certificat serveur auto-signé généré à la
  volée, certificat client **optionnel** (`optional_no_ca` — les plans FAPI1
  mélangent modules mTLS et `private_key_jwt`), cert extrait transmis via
  `X-SSL-Client-Cert` **URL-encodé** (`$ssl_client_escaped_cert`, dé-encodé par
  l'OP) ;
- l'OP local est lancé avec `PURIDENTITYSERVER_REQUEST_URI_ALLOW_LOCAL_TARGETS=true`
  et `SSL_CERT_FILE` pointant sur un certificat **SAN** (`localhost.emobix.co.uk`,
  `localhost`, `127.0.0.1`) que `setup.sh` substitue dans le nginx de la suite
  (concaténé au bundle système) : les modules `oidcc-request-uri-*` font fetcher
  par l'OP le document servi par la suite sur `localhost.emobix.co.uk:8443`
  (alias → 127.0.0.1). Deux blocages levés (issue #152) : la destination loopback
  serait sinon **refusée par la garde anti-SSRF** du fetcher `request_uri` (l'OP
  bind `0.0.0.0`), et le cert cuit dans l'image de la suite (`CN=localhost`
  **sans SAN**) **échoue au hostname matching** OpenSSL/Python pour
  `localhost.emobix.co.uk` même en trusté — le module basculait alors en WAITING
  puis INTERRUPTED. Jamais à activer sur un déploiement exposé.

### Démarrage rapide (Linux, macOS, Windows)

Prérequis par environnement :

| Environnement | Prérequis |
| --- | --- |
| Linux | `docker` (+ plugin compose), `uv`, `openssl`, `curl`, `git` |
| macOS | Docker Desktop, `uv`, `openssl`, `curl`, `git` |
| Windows | Docker Desktop (backend WSL2), Git for Windows (fournit **git-bash**), `uv` |

Sur **Windows**, lancer tous les scripts avec **git-bash** (pas PowerShell) :
le harness est écrit en bash et gère lui-même les chemins et arguments MSYS.
`setup.sh` vérifie les prérequis, pose (ou signale) l'entrée hosts
`127.0.0.1 localhost.emobix.co.uk` — indispensable aux callbacks de la suite —
et est **idempotent** (relançable : l'OP résiduel est arrêté avant
redémarrage, les conteneurs sont réutilisés).

```bash
# 1. monter le harness (suite docker + OP uvicorn + nginx mTLS), idempotent
bash certification/local/setup.sh

# 2. rejouer un plan en une commande (même séquence stricte que la CI)
bash certification/local/run-plan.sh fapi2   # basic | implicit | hybrid | formpost | dynamic | ciba | fapi1 | fapi2 | fapi2-message-signing | ekyc | federation

# 3. arrêter / nettoyer
bash certification/local/down.sh             # OP + op-mtls + conteneurs de la suite
bash certification/local/down.sh --purge     # + suppression de .harness-local/
```

`run-plan.sh` reproduit le job plan du workflow CI : readiness (bootstrap via
`setup.sh` si besoin), application idempotente des 6 patches du driver
(`prepare-suite.sh`), obtention du jeton d'administration
(`admin-token.sh`), substitution `{OPURL}`/`{SUITEURL}` dans une copie
générée du clone (`conformance-suite/plans/<plan>.json` — gitignore, le
working tree git reste propre), lancement du driver officiel en **sortie
stricte** (code retour non nul dès
qu'un module est FAILED/INTERRUPTED ou qu'un warning inattendu survient), puis
bilan `PASSED/FAILED/REVIEW` lu dans l'export, avec les chemins du log
(`.harness-local/last-<plan>.log`) et des exports
(`.harness-local/results/<plan>/`). Le dossier d'export local **accumule les
sessions précédentes** (le nom de l'archive porte un id aléatoire et la
date) : le bilan ne compte donc que les archives **produites par le run
courant** (instantané des archives présentes avant le lancement du driver),
les archives anciennes étant conservées pour le diagnostic. Le nombre
d'archives du run est affiché avant le bilan. La CI n'est pas concernée :
chaque job part d'un dossier d'export neuf. Les sélecteurs de plans viennent de
`certification/selectors.sh`, la **source unique** partagée avec les deux
workflows CI ; `prepare-suite.sh` est le helper de patches partagé avec le
workflow local.

### Rotation des clés de signature (module `oidcc-server-rotate-keys`)

Ce module compare le JWKS **avant et après** le démarrage du test : la
rotation des clés de signature de l'OP doit avoir lieu **entre** les deux
relevés. Le driver démarre le module sans délai après sa configuration (les
deux relevés sont séparés de quelques dizaines de millisecondes) : l'opérateur
ne peut donc pas agir à ce moment-là — c'est l'OP qui doit le faire.

Le patch `conformance-key-rotation` du driver appelle l'endpoint
d'administration `POST /signing-keys/rotate` juste avant de démarrer le
module (l'appel est conditionné par les variables d'environnement
`KEY_ROTATION_ENDPOINT` et `KEY_ROTATION_TOKEN`, absentes ⇒ aucune rotation
et le module reproduit son écart attendu). Le jeton est un access token
d'administration obtenu par le grant `client_credentials` sur le client seed
`certification-admin` (`certification/local/admin-token.sh`) ; l'autorisation
de l'API d'administration est branchée sur le claim `client_id`
(`admin_required_claim` / `admin_required_claim_values` de
`certification/config.render.toml`) — le scope `admin` par défaut n'étant pas
enregistré, il serait impossible à un client d'obtenir un jeton d'administration.

Le **secret** du client `certification-admin` n'est **jamais committé** : le
seed le référence par `${CERTIFICATION_ADMIN_CLIENT_SECRET}` (résolu dans
l'environnement du serveur par les settings) et le job CI lit la même
variable. Deux valeurs sont donc à aligner manuellement :

| Où | Variable | Valeur |
|---|---|---|
| Instance hébergée (tableau de bord Render) | `CERTIFICATION_ADMIN_CLIENT_SECRET` | secret de l'opérateur |
| Secret GitHub du dépôt | `CERTIFICATION_ADMIN_CLIENT_SECRET` | **la même** valeur |
| Harnais local / job CI local | `CERTIFICATION_ADMIN_CLIENT_SECRET` | valeur locale par défaut (`local-certification-admin-secret`), l'instance tournant sur `localhost` |

Si le secret GitHub manque, le job hébergé ne peut pas appeler l'endpoint :
le module `oidcc-server-rotate-keys` reproduit alors son écart attendu
(l'auto-attestation OIDF reste alors possible).

Ainsi, **aucune rotation permanente** n'est configurée sur l'instance de
certification : les plans locaux (11) et hébergés (10) partagent le même
mécanisme, sans churn du JWKS sur les plans qui ne portent pas le module.

### Écarts de modules attendus (mode witness)

`certification/expected-failures/<plan>.json` déclare, au format du driver
(`--expected-failures-file`, cf. `conformance-suite/scripts/run-test-plan.py`),
les conditions de modules connues et non résolues. Son pendant
`certification/expected-failures/<plan>-skips.json` (`--expected-skips-file`,
même format) déclare les modules que l'OP **saute** faute de capacité : le
plan `federation` y déclare `with-jar-and-encrypted-request-object`, le
chiffrement des request objects (OIDC Core 1.0 §10.1) n'étant pas encore
supporté (issue #204 — purger l'entrée à la livraison). Les dix autres
plans locaux sont sans écart (la rotation des clés de signature de l'OP est
livrée — issue #189, le module `oidcc-server-rotate-keys` passe ; le rejeu
local affiche 17 PASSED / 6 REVIEW / 0 FAILED sur le plan `dynamic`).

Le driver classe ces conditions en « expected failure » : le plan ne sort en
code non nul que pour les écarts **inattendus** — la strictude #130 est
préservée et les gaps documentés ne bloquent pas (mode witness). Chaque entrée
non consommée (condition résolue entre-temps, ex. capacité implémentée) fait
échec `EXPECTED_*_NOT_HAPPEN` : le fichier doit être purgé dès qu'une
capacité est livrée. `run-plan.sh` et le job plan de
`certification-local.yml` appliquent les deux fichiers quand ils existent
(chemin et comportement identiques) ; le workflow hébergé reste witness pur
(`continue-on-error` sur le lancement).

En CI : le workflow `Certification OIDC (Local)`
(`.github/workflows/certification-local.yml`) exécute exactement cette
séquence en **sortie stricte** (issue #130) : le code retour non nul du
driver fait échouer le job plan (modules FAILED, INTERRUPTED ou warnings
inattendus — hors écarts déclarés witness, voir ci-dessus ; seule l'absence
totale d'export signale un crash du harness) et
téléverse les exports + le rapport en artefacts ; le rapport est **publié sur
GitHub Pages** pour les runs sur `main` ou lancés à la main (pas pour les
PR). Les modules REVIEW restent tolérés (verdicts de relecture), leur preuve
étant fournie par les captures réelles obligatoires (issue #161). Les
lacunes d'enforcement mTLS CIBA sont corrigées (#147, #149) : le plan ciba
est à 35/35 PASSED (run 38575847610).

## Rejeu local pytest (supprimé)

L'ancien rejeu « sans docker » (`tests/conformance/`, 435 scénarios rejoués
in-process, marker `conformance`, job `conformance-tests.yml`) a été **supprimé** :
le harness local docker (section précédente) rejoue la vraie suite et couvre
les mêmes plans de bout en bout. Le mini-RP client qu'il embarquait vit
maintenant dans `samples/oidc_harness/` (habillé par les smoke tests
`samples/fapi1-client/` et `samples/fapi2-client/`).

## Dépannage

- **`setup.sh` s'arrête sur « entree hosts absente »** : la résolution de
  `localhost.emobix.co.uk` vers `127.0.0.1` est indispensable (callbacks de la
  suite + alias réseau docker). Ajouter `127.0.0.1 localhost.emobix.co.uk` au
  fichier hosts système — sous Windows : `C:\Windows\System32\drivers\etc\hosts`
  ouvert avec le Bloc-notes **en administrateur** (le même fichier que
  `/etc/hosts` vu par git-bash) — puis relancer `setup.sh`.
- **Modules bloqués en `WAITING` après une substitution manuelle du plan** :
  `{SUITEURL}` doit être remplacé **avec** sa slash finale
  (`https://localhost.emobix.co.uk:8443/`), sinon le `match` de callback devient
  `…8443test/…`, ne s'applique jamais et chaque module reste `WAITING` jusqu'au
  timeout. `run-plan.sh` applique la substitution correcte (même valeur que
  l'env `SUITE_URL` du workflow local).
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
- **`git apply` échoue sur un patch `certification/*.patch`** : une nouvelle
  release publiée de la suite a dérivé le contexte des patches (la
  certification joue toujours la dernière release, issue #150) — rafraîchir le
  patch fautif : rejouer ses changements sur
  `$SUITE_DIR/scripts/conformance.py` puis le regénérer avec
  `git diff scripts/conformance.py` (valider la séquence complète des 5
  patches dans l'ordre du workflow).
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
  `results/` vide) — le step Lancement échoue aussi (code non nul propagé).
  Causes vécues (issue #113) : client statique absent de la config
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
  certificat d'émission. **Les 2 clients statiques FAPI1 de
  `config.render.toml` portent le flag** (issue #144) : la suite FAPI1 impose
  le sender-constrain mTLS, alors que les clients FAPI2 restent sans flag
  (DPoP, aucun certificat). L'OP lit le PEM via deux sources : le contexte TLS
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
  modules `ensure-mtls-holder-of-key` / `bare` resteront FAILED sur ce seul
  check derrière CF ; le module `refresh-token` peut devenir 100 % vert.
  Tant que ces deux points ne sont pas levés (CF mTLS + flip des seeds), le
  plan **fapi1 garde ses modules FAILED sur le run hébergé** (actuellement en
  mode witness, exécuté à la demande ; la sortie stricte #130 concerne le
  workflow local, où fapi1 passe).
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
| `config.render.toml` | config de l'instance de certification (registre dynamique ouvert, users de démo, `require_login = true`, `subject_pairwise_seed` pour les modules sector du plan dynamic, 4 clients statiques FAPI `private_key_jwt` + JWKS public pour les plans fapi1/fapi2) |
| `plans/basic|implicit|hybrid|formpost|dynamic|ciba|fapi1|fapi2|fapi2-message-signing|ekyc|federation.json` | configs des plans de la suite (alias **unique par plan**, discovery, règles navigateur login/consent ; fapi1/fapi2/fapi2-message-signing portent aussi `client`/`client2` en clé privée et `resource` ; `ekyc` porte la configuration eKYC `ekyc.verified_claims_request_list` ; `federation` porte l'Entity Identifier de l'OP, l'ancre de confiance `{SUITEURL}test/a/puridentityserver-federation/trust-anchor` et les clés de test RP/ancre du template officiel) |
| `conformance-reuse-plan.patch` | patch du driver : `create_test_plan` idempotent (réutilise le plan existant quand sa config n'a pas changé) |
| `conformance-screenshots.patch` | patch du driver : remplit les placeholders REVIEW « capture d'écran » avec la **capture réelle** du module (`SCREENSHOTS_DIR/<testName>.png`) — avec `SCREENSHOTS_DIR` défini (CI), un fichier absent/vide/trop lourd lève une erreur fatale (captures obligatoires, issue #161) ; sans variable (exécution manuelle), le PNG 1x1 de secours, après une période de tolérance `SCREENSHOT_FILL_GRACE` (60 s) pendant laquelle le module a le droit de se terminer seul, pour que les modules Core se terminent sans intervention humaine (mode hébergé) |
| `capture_screenshots.py` | rejoue les 30 scénarios de relecture (4 Core, 6 dynamic, 16 FAPI1, 4 FAPI2) contre l'OP (Playwright/chromium headless) et dépose les PNG `screenshots/<testName>.png` ensuite téléversés par le driver — `--base-url` = OP, `--suite-url` = base des callbacks de la suite (hébergée par défaut, `https://localhost.emobix.co.uk:8443` en local) |
| `conformance-alias-release.patch` | patch du driver : libère l'alias avant chaque création de module (et à la fin du plan), pour qu'un module encore actif ne soit jamais interrompu par « alias conflict » |
| `conformance-interrupted-diagnostics.patch` | patch du driver : quand un module est interrompu ou dépasse le timeout, affiche dans la CI la cause réelle (statut, résultat + 10 dernières entrées du journal du test) au lieu d'un simple « has moved to INTERRUPTED » / « Timed out waiting » |
| `conformance-stale-plan-recovery.patch` | patch du driver : n'est jamais réessaie le 500 déterministe « test module not found » (1 tentative au lieu de 28) et valide la membership du plan réutilisé contre le catalogue avant le run — recréation automatique du plan stale (membership fraîche dès le premier run), plan le plus récent privilégié à la réutilisation |
| `report.py` | génère la page statique GH Pages à partir des JSON exportés ; recopie les captures réelles dans `_site/screenshots/` (`--screenshots`) et les affiche dans la section du module correspondant |
| `local/setup.sh` | bootstrap du harness **auto-hébergé** : alias réseau, clone + déploiement docker de la suite, cert auto-signé + nginx mTLS `op`, config OP locale (issuer `https://op:9443`), OP uvicorn, attente de disponibilité |
| `local/nginx-mtls.conf` | nginx de terminaison mTLS devant l'OP local : certificat client optionnel (`optional_no_ca`), extraction `$ssl_client_escaped_cert` → `X-SSL-Client-Cert` (pas de newline brute), proxy vers l'OP uvicorn de l'hôte |
| `../.github/workflows/certification.yml` | workflow hébergé à la demande (`workflow_dispatch` uniquement) : `prepare` (deploy + captures, une fois), `plan` (les 11 plans en parallèle — les 9 du programme officiel **plus** `ekyc` (identité assurance) et `federation` (OpenID Federation 1.1), hors programme officiel — un job matrix chacun, mode witness), `report` (fusion des exports en artefact - publication OIDC des résultats à venir) |
| `../.github/workflows/certification-local.yml` | workflow **auto-hébergé strict** : déclenché à chaque merge sur `main`, sur les PR (`certification/**`) et à la demande ; 11 plans en matrix (les 10 de l'hébergé, `ekyc` et `federation` étant hors programme officiel de certification), code non nul du driver = job en échec, job `capture` **bloquant** (Playwright, artefact `certification-local-screenshots`, #158/#161 : captures REVIEW obligatoires), **publication GitHub Pages** (sauf sur les PR) |

## Captures d'écran des modules de relecture (modes hébergé et local)

Certains modules Core s'arrêtent sur un événement **REVIEW** demandant une capture
d'écran : sans intervention, le driver attend jusqu'au timeout
`CONFORMANCE_MODULE_TIMEOUT` puis marque le module en échec. Sur l'instance hébergée,
l'« upload » se fait à la main via la console navigateur — impossible en CI. Les
quatre modules concernés (verdicts `review` du run de référence) captent chacun une
page différente de l'OP :

| Module | Page capturée |
| --- | --- |
| `oidcc-response-type-missing` | erreur 400 « Paramètres requis manquants : `response_type` » (avant login) |
| `oidcc-ensure-registered-redirect-uri` | erreur 400 `invalid_redirect_uri`, servie avant login |
| `oidcc-prompt-login` | second formulaire de connexion (`prompt=login`) |
| `oidcc-max-age-1` | second formulaire de connexion (`max_age=1`, une seconde après le premier) |

Les modules FAPI1 (request object défectueux) et FAPI2 (demande poussée PAR) sont
du même ressort : leurs placeholders REVIEW attendent la page d'erreur réellement
servie par l'OP. Deux étapes couvrent ce besoin :

1. **`capture_screenshots.py`** (étape « Captures d'écran réelles des modules de
   relecture ») : enregistre un client via RFC 7591, rejoue les **30 scénarios de
   relecture** (les 4 modules Core du tableau, les 6 modules du plan dynamic —
   arbitrages de `redirect_uri` absente/supplémentaire/non concordante et pages
   de connexion des clients DCR porteurs d'un `logo_uri`/`policy_uri`/`tos_uri`,
   issue #168 —, les 16 modules FAPI1, les 4 modules
   FAPI2) avec chromium headless contre l'OP (`--base-url`), **contrôle chaque page
   avant export** (statut 400 + marqueur `<code>` du motif — ou extrait « manquants
   : redirect_uri » pour la page sans code de motif, ou titre et
   `form[action="/login"]` ; les erreurs FAPI2, elles, doivent arriver par une
   302 vers le callback de la suite portant `error=<code>` — transport
   RFC 6749 §4.1.2.1, issue #160) puis dépose
   `screenshots/<testName>.png` — PNG sous les 500 Ko imposés par l'ImageAPI de la
   suite. Le callback des clients Core de capture est `https://rp.example.invalid/callback`
   (RFC 2606) : la navigation finale échoue au DNS, erreur que le script absorbe ;
   les clients FAPI statiques utilisent le callback de la suite (`--suite-url` :
   hébergé `https://www.certification.openid.net`, local
   `https://localhost.emobix.co.uk:8443`) et l'`aud` des assertions est lu au
   discovery de l'OP (issuer local `https://op:9443`). L'étape est
   **bloquante** (issue #161) : le script exige les 30 captures et un échec
   (installation du navigateur, OP indisponible, scène invalide…) fait échouer
   le run — plus aucun repli silencieux en CI. Les deux workflows l'exécutent :
   - **mode hébergé** : dans le job `prepare` contre l'instance Render, résultat
     publié en artefact `certification-screenshots` ;
   - **mode local** (#158) : job `capture` de `certification-local.yml` contre
     l'OP local (`https://localhost:9443`, cert auto-signé), **une seule fois par
     run**, artefact `certification-local-screenshots` que les jobs `plan`
     téléchargent (env `SCREENSHOTS_DIR`, substitution du PNG de secours) et que
     le job `report` intègre au rapport.
2. **`conformance-screenshots.patch`** couple deux points du driver :
   - `conformance.py` : `screenshot_data_uri(test_name)` lit
     `SCREENSHOTS_DIR/<testName>.png` (répertoire fourni à l'étape des plans) ;
     `fill_required_screenshots(module_id, test_name)` liste les placeholders en
     attente (`GET api/log/{id}/images`, entrées avec le champ `upload`) puis les
     remplit (`POST api/log/{id}/images/{placeholder}`) avec cette **capture réelle** ;
     avec `SCREENSHOTS_DIR` défini (les deux workflows), un fichier absent, vide
     ou trop volumineux **lève une erreur fatale** et fait échouer le driver
     (captures obligatoires, issue #161) ; sans variable (exécution manuelle
     hors CI), il replonge sur le **PNG 1x1 de secours** (data URI
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
`certification-screenshots` (hébergé) ou `certification-local-screenshots` (local).
Le PNG de secours ne survit qu'à une exécution manuelle sans `SCREENSHOTS_DIR` :
en CI, la capture réelle de chaque module de relecture est exigée et son absence
fait échouer le run (issue #161).

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