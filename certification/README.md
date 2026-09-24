# Certification OIDC (suite officielle OpenID Foundation)

Ce dossier contient tout ce qu'il faut pour faire tourner la suite de
certification OIDC officielle (<https://gitlab.com/openid/conformance-suite>)
contre une instance **publique** de PurIdentityServer, en CI ou en local.

L'OP étant testé **à distance** par la suite (l'OP doit recevoir des
redirections, des posts form_post et des appels du navigateur Selenium de la
suite), il faut que le serveur soit joint de l'extérieur. L'architecture
retenue :

1. l'OP est déployé sur **Render** (service gratuit, `storage_type = "memory"`)
   — configuration committée dans `render.yaml` + `Dockerfile` +
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
- **ERREUR sur Redis/nginx** : relancer ; le premier pull des images
  `registry.gitlab.com/openid/conformance-suite` est long (~10 min).

## Fichiers

| Fichier | Rôle |
| --- | --- |
| `render.yaml` / `Dockerfile` / `.dockerignore` | déploiement de l'OP sur Render (mémoire) |
| `config.render.toml` | config de l'instance de certification (registre dynamique ouvert, users de démo, `require_login = true`) |
| `plans/basic|implicit|hybrid.json` | configs des plans Core de la suite (alias **unique par plan**, discovery, règles navigateur login/consent) |
| `conformance-reuse-plan.patch` | patch du driver : `create_test_plan` idempotent (réutilise le plan existant quand sa config n'a pas changé) |
| `report.py` | génère la page statique GH Pages à partir des JSON exportés |
| `../.github/workflows/certification.yml` | workflow witness : deploy + suite + plans + rapport |

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