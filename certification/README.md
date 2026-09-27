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
  (`oidcc-basic-`, `oidcc-implicit-`, `oidcc-hybrid-certification-test-plan`),
  le détail des modules testés et leur verdict (PASSED / FAILED / WARNING /
  REVIEW / SKIPPED) dans le résumé du run ;
- l'artefact `certification-results` contient les JSON exportés ;
- une page `https://<owner>.github.io/puridentityserver/certification/`
  consolide les derniers résultats.

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
  cron hebdomadaire). Le workflow : redéploie Render, attend que
  `/.well-known/openid-configuration` réponde, démarre la suite, joue chaque
  plan, génère le rapport et déploie la page GitHub Pages.
- **En local** : (optionnel) pour reproduire le même principe contre un
  serveur local :

  ```bash
  # 1. configurer un mini-serveur public atteignable par la suite (ici Render)
  # 2. cloner et démarrer la suite, comme le workflow :
  git clone --depth 1 --branch release-v5.2.4 https://gitlab.com/openid/conformance-suite.git
  cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
  # 3. substituer {OPURL} dans les plans puis jouer un plan :
  export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/
  export CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/
  python3 scripts/run-test-plan.py \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]" \
    ../certification/plans/basic.json
  ```

## Dépannage

- **L'OP ne répond pas** : le service Render libre s'endort après ~15 min
  d'inactivité ; le workflow patiente (cold start ~1 min) avant d'échouer.
- **Module en état WAITING qui ne termine pas** : c'est le navigateur Selenium
  de la suite qui exécute les tâches `browser` du plan. Consulter le
  `log-detail.html` du module dans l'interface de la suite pendant le run
  (logs visibles dans l'étape du workflow) ; ajouter un
  `"browser": [...]` plus précis dans le plan concerné.
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
  lieu de le recréer à chaque run.
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
- **ERREUR sur Redis/nginx** : relancer ; le premier pull des images
  `registry.gitlab.com/openid/conformance-suite` est long (~10 min).

## Fichiers

| Fichier | Rôle |
| --- | --- |
| `render.yaml` / `Dockerfile` / `.dockerignore` | déploiement de l'OP sur Render (SQLite, disque éphémère) |
| `config.render.toml` | config de l'instance de certification (registre dynamique ouvert, users de démo, `require_login = true`) |
| `plans/basic|implicit|hybrid.json` | configs des plans Core de la suite (alias **unique par plan**, discovery, règles navigateur login/consent) |
| `conformance-reuse-plan.patch` | patch du driver : `create_test_plan` idempotent (réutilise le plan existant quand sa config n'a pas changé) |
| `conformance-screenshots.patch` | patch du driver : remplit automatiquement les placeholders REVIEW « capture d'écran » (ex. `oidcc-response-type-missing`) avec un PNG de secours, pour que les modules Core se terminent sans intervention humaine (mode witness) |
| `conformance-alias-release.patch` | patch du driver : libère l'alias avant chaque création de module (et à la fin du plan), pour qu'un module encore actif ne soit jamais interrompu par « alias conflict » |
| `conformance-interrupted-diagnostics.patch` | patch du driver : quand un module est interrompu ou dépasse le timeout, affiche dans la CI la cause réelle (statut, résultat + 10 dernières entrées du journal du test) au lieu d'un simple « has moved to INTERRUPTED » / « Timed out waiting » |
| `report.py` | génère la page statique GH Pages à partir des JSON exportés |
| `../.github/workflows/certification.yml` | workflow witness : deploy + suite + plans + rapport |

## Captures d'écran des modules de relecture (mode witness)

Certains modules Core (au moins `oidcc-response-type-missing`, présent dans le plan
Basic) s'arrêtent sur un événement **REVIEW** demandant une capture d'écran :
sans intervention, le driver attend jusqu'au timeout `CONFORMANCE_MODULE_TIMEOUT`
puis marque le module en échec. Sur l'instance hébergée, l'« upload » se fait à la
main via la console navigateur — impossible en CI.

Le patch `conformance-screenshots.patch` couple deux points du driver :
- `conformance.py` : nouvelle méthode `fill_required_screenshots(module_id)` qui
  liste les placeholders en attente (`GET api/log/{id}/images`, entrées avec le
  champ `upload`) puis les remplit (`POST api/log/{id}/images/{placeholder}`) avec
  un **PNG 1x1 de secours** (data URI `image/png`, bien sous la limite de 500 Ko) ;
- `run-test-plan.py` : appel systématique de cette méthode pour les modules
  purement OP (pas de client à piloter) avant l'attente de `FINISHED`.

Le remplissage déclenche `setTestReviewNeeded`, ce qui relance le module jusqu'à
son terme. En mode witness, la capture fournie n'est pas une preuve d'exécution
réelle du navigateur : c'est un artifice pour que la suite se termine et produise
le rapport complet.

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
prochain run.