# Installation

## Prérequis

- **Python ≥ 3.10** (testé sur 3.13)
- **uv** — gestionnaire de dépendances Python : <https://docs.astral.sh/uv/getting-started/installation/>
- **Git**

## 1. Récupérer le code

```sh
git clone git@github.com:aguacongas/puridentityserver.git
cd PurIdentityServer
```

## 2. Installer les dépendances

```sh
uv sync          # dépendances de production
uv sync --extra dev   # + outils de qualité (ruff, mypy, pytest…) pour le développement
```

## 3. Lancer le serveur

```sh
uv run python -m puridentityserver
```

Le serveur écoute sur `http://127.0.0.1:8000` (surchargeable via `PURIDENTITYSERVER_HOST` / `PURIDENTITYSERVER_PORT`).

Vérification :

```sh
curl http://127.0.0.1:8000/.well-known/openid-configuration
```

Un document JSON contenant l'`issuer` et les endpoints doit être retourné.

## 4. Installer sans source (wheel)

Construire et installer la distribution :

```sh
uv build                     # génère dist/puridentityserver-*.whl et -*.tar.gz
uv pip install dist/puridentityserver-*.whl
```

Démarrage :

```sh
uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

## 5. Déployer en production

Le projet **ne gère pas TLS lui-même** (choix d'architecture : la crypto de transport est
confiée à l'infrastructure). Le déploiement recommandé est donc derrière un reverse proxy
(nginx, Caddy, Traefik) qui termine le TLS :

```text
Client ──HTTPS──> Reverse proxy (TLS) ──HTTP──> PurIdentityServer (127.0.0.1:8000)
```

Points clés :

- Définir `PURIDENTITYSERVER_ISSUER` sur **l'URL publique HTTPS** du serveur (l'un des identifiants
  que la spec exige de publier). Il servira de base aux URL des endpoints.
- L'issuer doit être stable dans le temps : changer d'URL publique invalide les
  `id_token` et access tokens émis précédemment.
- Le stockage est **en mémoire** pour l'instant : un seul processus. Pour plusieurs
  workers de process, attendre la persistance externe (prévue) ou lancer un seul worker.

Exemple minimal derrière nginx :

```sh
export PURIDENTITYSERVER_ISSUER=https://id.example.com
uv run uvicorn puridentityserver.server:app --host 127.0.0.1 --port 8000
```

```nginx
server {
    listen 443 ssl;
    server_name id.example.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Dépannage

| Symptôme | Cause probable |
| --- | --- |
| `No module named puridentityserver` | commande lancée hors du répertoire du projet, ou `uv sync` non exécuté |
| Le CI Sonar échoue | secret `SONAR_SECRET` non défini sur le dépôt GitHub (voir `docs/configuration.md`) |
