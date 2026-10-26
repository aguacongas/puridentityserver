#!/usr/bin/env bash
# Bootstrap du harness LOCAL de certification OIDC (mode auto-hébergé).
#
# Monte de bout en bout la topologie nécessaire pour jouer les plans fapi1/fapi2
# de la suite openid/conformance-suite SANS passer par l'infra hébergée de la
# Fondation :
#
#   [driver run-test-plan.py] --(API)--> suite docker (nginx :8443, alias
#        localhost.emobix.co.uk) --> navigateur HtmlUnit (conteneur)
#        HtmlUnit --(authorize/token)--> OP nginx mTLS (conteneur "op", :9443)
#        --> OP uvicorn (hôte :8000)
#
# - la suite (dernière release publiée) tourne en docker (mongodb + server + nginx) ;
# - l'OP PurIdentityServer tourne sur l'hôte (uvicorn :8000), config locale
#   générée à partir de certification/config.render.toml (issuer = https://op:9443,
#   redirect_uris = callbacks de la suite LOCALE, SQLite éphémère) ;
# - un nginx « op » (conteneur, alias réseau `op` sur le réseau de la suite)
#   termine le mTLS devant l'OP (cert auto-signé, certificat client optionnel)
#   et passe le cert extrait via X-SSL-Client-Cert (voir nginx-mtls.conf).
#
# Réutilisable tel quel en local (DoD) : `bash certification/local/setup.sh`
# puis `bash certification/local/run-plan.sh <plan>` — voir certification/README.md
# (« Démarrage rapide »). Relançable sans dommage (OP résiduel arrêté d'abord).
set -euo pipefail

# --- Configuration (surchargeable par env) ------------------------------------
# Par défaut : dernière release connue. Les workflows la résolvent à
# l'exécution (git ls-remote, cf. issue #150) et exportent SUITE_VERSION.
SUITE_VERSION="${SUITE_VERSION:-release-v5.3.3}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
SUITE_DIR="${SUITE_DIR:-$REPO_ROOT/conformance-suite}"
LOCAL_DIR="${LOCAL_DIR:-$REPO_ROOT/.harness-local}"
OP_HOST="${OP_HOST:-0.0.0.0}"
OP_PORT="${OP_PORT:-8000}"
SUITE_HOSTNAME="localhost.emobix.co.uk"
SUITE_PORT="8443"
MTLS_PORT="9443"
OP_ALIAS="op"

mkdir -p "$LOCAL_DIR"
cd "$REPO_ROOT"
log() { printf '[setup] %s\n' "$*"; }

# Compat git-bash/MSYS (Windows) : openssl et Python natifs ne comprennent
# pas les chemins POSIX (/c/…) — les convertit en forme Windows (no-op
# sous Linux, où cygpath est absent).
winpath() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# Arret d'un processus : taskkill /T (git-bash) tue aussi la descendance
# (le python enfant de « uv run » tient le port et op.db) ; sinon kill.
stop_pid() {
  if command -v taskkill >/dev/null 2>&1; then
    MSYS_NO_PATHCONV=1 taskkill /F /T /PID "$1" >/dev/null 2>&1 || true
  else
    kill "$1" 2>/dev/null || true
  fi
}

# PID du processus qui ecoute encore $OP_PORT (netstat ; le PID est le dernier
# champ sous Windows comme sous Linux ; « LISTEN » couvre LISTENING et LISTEN).
port_listener_pid() {
  netstat -ano 2>/dev/null \
    | awk -v p=":$OP_PORT" '$0 ~ /LISTEN/ && $0 ~ p"[[:space:]]" { print $NF; exit }'
}

# ---0) Prérequis --------------------------------------------------------------
# Echec sec avec message d'aide : sous Windows, tout se lance depuis git-bash
# (fourni par Git for Windows) — les scripts du harness sont en bash.
require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[setup] $1 introuvable — $2" >&2
    exit 1
  }
}
require git "installez Git (https://git-scm.com ; Windows : Git for Windows, qui fournit git-bash)"
require curl "installez curl (Linux/macOS : natif ; Windows : Git for Windows)"
require openssl "installez OpenSSL (Linux : paquet openssl ; macOS/Windows : natif ou Git for Windows)"
require uv "installez uv (https://docs.astral.sh/uv/) : curl -LsSf https://astral.sh/uv/install.sh | sh"
require docker "installez/activez Docker Desktop (Windows/macOS) ou Docker Engine (Linux)"
if ! docker info >/dev/null 2>&1; then
  echo "[setup] daemon docker non joignable — demarrez Docker Desktop (ou le service docker)" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "[setup] plugin « docker compose » absent — mettez a jour Docker" >&2
  exit 1
fi

# ---1) Résolution de localhost.emobix.co.uk -----------------------------------
# La suite génère ses callbacks sur ce nom. Deux sources possibles : le DNS
# public (wildcard OIDF -> 127.0.0.1) ou l'entrée hosts. On teste la
# RÉSOLUTION (curl « could not resolve » = code 6) plutôt que le contenu de
# /etc/hosts : sous git-bash/Windows, /etc/hosts ne reflète pas le fichier
# hosts de Windows alors que le résolveur natif — et le DNS — répondent déjà.
host_resolves() {
  local rc=0
  curl -s --max-time 5 -o /dev/null "http://$SUITE_HOSTNAME:1/" 2>/dev/null || rc=$?
  [ "$rc" -ne 6 ]
}
if host_resolves; then
  log "$SUITE_HOSTNAME resout deja (DNS ou hosts) — aucune modification"
else
  log "ajout de $SUITE_HOSTNAME -> 127.0.0.1 dans /etc/hosts"
  if printf '127.0.0.1 %s\n' "$SUITE_HOSTNAME" >> /etc/hosts 2>/dev/null; then
    log "entree ajoutee"
  elif command -v sudo >/dev/null 2>&1 \
      && printf '127.0.0.1 %s\n' "$SUITE_HOSTNAME" | sudo tee -a /etc/hosts >/dev/null; then
    log "entree ajoutee (sudo)"
  fi
  if host_resolves; then
    log "resolution de $SUITE_HOSTNAME OK"
  else
    cat >&2 <<EOF
[setup] $SUITE_HOSTNAME ne resout pas vers 127.0.0.1 et l'ecriture de
/etc/hosts a echoue. Ajoutez manuellement :

    127.0.0.1 $SUITE_HOSTNAME

- Windows (git-bash) : editez C:\Windows\System32\drivers\etc\hosts avec le
  Bloc-notes LANCE EN TANT QU'ADMINISTRATEUR (c'est le meme fichier que
  /etc/hosts vu par git-bash), puis relancez setup.sh.
- Linux/macOS : echo '127.0.0.1 $SUITE_HOSTNAME' | sudo tee -a /etc/hosts
- Sans entrée hosts : le DNS public OIDF (wildcard -> 127.0.0.1) peut aussi
  faire foi — verifiez la connectivité DNS de la machine.
EOF
    exit 1
  fi
fi

# ---2) Clone de la suite (pinné) si absent ------------------------------------
if [ ! -d "$SUITE_DIR/.git" ]; then
  log "clone de la suite ($SUITE_VERSION)"
  git clone --depth 1 --branch "$SUITE_VERSION" \
    https://gitlab.com/openid/conformance-suite.git "$SUITE_DIR"
fi

# ---3) Déploiement docker de la suite (mongodb + server + nginx) --------------
log "démarrage de la suite docker ($SUITE_VERSION)"
( cd "$SUITE_DIR" && IMAGE_TAG="$SUITE_VERSION" \
    docker compose -f docker-compose-prebuilt.yml up -d )

# Réseau de la suite : op-mtls doit y être rattaché pour que le navigateur
# HtmlUnit (conteneur server) atteigne l'OP via l'alias `op`. On le récupère
# depuis le conteneur nginx de la suite (nom <projet>-nginx-1).
SUITE_NGINX="$(docker ps --filter 'name=nginx' --format '{{.Names}}' \
  | grep -v "$OP_ALIAS-mtls" | head -n1 || true)"
SUITE_NET=""
if [ -n "$SUITE_NGINX" ]; then
  SUITE_NET="$(docker inspect "$SUITE_NGINX" \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
fi
log "réseau de la suite : ${SUITE_NET:-<inconnu>}"

# ---3.5) Certificat TLS SAN du nginx de la suite (fetch request_uri par l'OP) --
# Double blocage issue #152 : (1) la garde anti-SSRF refuse localhost.emobix.co.uk
# tant que l'OP bind 0.0.0.0 (corrigé par PURIDENTITYSERVER_REQUEST_URI_ALLOW_
# LOCAL_TARGETS) ; (2) le cert cuit dans l'image de la suite n'a que CN=localhost
# SANS SAN : le hostname matching OpenSSL/Python refuse de le valider pour
# localhost.emobix.co.uk, même en trusté → échec silencieux du fetch → 400.
# On génère donc un cert SAN, on le substitue dans le conteneur nginx (chemins
# lus dans nginx.conf de la suite) et on recharge nginx. L'OP reçoit le même
# cert via SSL_CERT_FILE (concaténé au bundle système, puisque SSL_CERT_FILE
# remplace le magasin par défaut).
[ -n "$SUITE_NGINX" ] || {
  echo "::error::conteneur nginx de la suite introuvable"
  exit 1
}
SUITE_TLS_CERT="$LOCAL_DIR/suite-tls.crt"
SUITE_TLS_KEY="$LOCAL_DIR/suite-tls.key"
SUITE_TRUST="$LOCAL_DIR/suite-trust.pem"
log "génération du certificat SAN pour $SUITE_HOSTNAME (substitution dans $SUITE_NGINX)"
# MSYS_NO_PATHCONV : sous git-bash, `-subj /CN=…` serait sinon converti en
# chemin Windows (C:/Program Files/Git/CN=…) et openssl refuserait le DN ;
# les chemins de fichiers sont passés déjà convertis via winpath.
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -days 2 -newkey rsa:2048 \
  -keyout "$(winpath "$SUITE_TLS_KEY")" -out "$(winpath "$SUITE_TLS_CERT")" \
  -subj "/CN=$SUITE_HOSTNAME" \
  -addext "subjectAltName=DNS:$SUITE_HOSTNAME,DNS:localhost,IP:127.0.0.1" \
  2>/dev/null
docker cp "$(winpath "$SUITE_TLS_CERT")" "$SUITE_NGINX:/etc/ssl/certs/nginx-selfsigned.crt"
docker cp "$(winpath "$SUITE_TLS_KEY")" "$SUITE_NGINX:/etc/ssl/private/nginx-selfsigned.key"
# MSYS_NO_PATHCONV : les arguments de docker exec sont des chemins CÔTÉ
# conteneur — la conversion git-bash les réécrirait en /c/… Windows.
MSYS_NO_PATHCONV=1 docker exec "$SUITE_NGINX" chmod 600 /etc/ssl/private/nginx-selfsigned.key
log "rechargement du nginx de la suite"
deadline=$((SECONDS + 60))
until docker exec "$SUITE_NGINX" nginx -s reload >/dev/null 2>&1; do
  [ $SECONDS -lt $deadline ] || {
    echo "::error::reload du nginx de la suite impossible"
    exit 1
  }
  sleep 3
done
cp "$SUITE_TLS_CERT" "$SUITE_TRUST"
for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
  if [ -f "$bundle" ]; then
    cat "$bundle" >> "$SUITE_TRUST"
    break
  fi
done
log "confiance OP → suite écrite dans $SUITE_TRUST (SAN $SUITE_HOSTNAME)"

# ---4) Certificat serveur auto-signé pour l'OP nginx --------------------------
if [ ! -f "$LOCAL_DIR/nginx.crt" ]; then
  log "génération du certificat serveur auto-signé (op, localhost, host.docker.internal)"
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$(winpath "$LOCAL_DIR/nginx.key")" -out "$(winpath "$LOCAL_DIR/nginx.crt")" \
    -subj "/CN=$OP_ALIAS" \
    -addext "subjectAltName=DNS:$OP_ALIAS,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1" \
    2>/dev/null
fi

# ---5) Conteneur nginx mTLS « op » (alias réseau op) --------------------------
log "démarrage du nginx mTLS op (:$MTLS_PORT -> OP hôte :$OP_PORT)"
docker rm -f "$OP_ALIAS-mtls" >/dev/null 2>&1 || true
docker run -d --name "$OP_ALIAS-mtls" \
  -p "$MTLS_PORT:$MTLS_PORT" \
  --add-host host.docker.internal:host-gateway \
  ${SUITE_NET:+--network "$SUITE_NET" --network-alias "$OP_ALIAS"} \
  -v "$(winpath "$REPO_ROOT/certification/local/nginx-mtls.conf"):/etc/nginx/nginx.conf:ro" \
  -v "$(winpath "$LOCAL_DIR/nginx.crt"):/etc/nginx/tls/nginx.crt:ro" \
  -v "$(winpath "$LOCAL_DIR/nginx.key"):/etc/nginx/tls/nginx.key:ro" \
  nginx:alpine >/dev/null

# ---6) Config OP locale (issuer op:9443, callbacks suite locale, SQLite) ------
log "génération de la config OP locale"
# Idempotent : la config est régénérée depuis le template à chaque run.
sed \
  -e "s|issuer = \"http://127.0.0.1:8000\"|issuer = \"https://$OP_ALIAS:$MTLS_PORT\"|" \
  -e "s|https://www.certification.openid.net|https://$SUITE_HOSTNAME:$SUITE_PORT|g" \
  -e "s|storage_dsn = \"sqlite:///puridentityserver.db\"|storage_dsn = \"sqlite:///$(winpath "$LOCAL_DIR/op.db")\"|" \
  "$REPO_ROOT/certification/config.render.toml" > "$LOCAL_DIR/op-config.toml"

# ---7) OP uvicorn (hôte) ------------------------------------------------------
log "installation des dépendances OP (uv sync --extra sql)"
( cd "$REPO_ROOT" && uv sync --extra sql --locked >/dev/null )
# Re-run idempotent : un OP résiduel tient le port — uvicorn échouerait à se
# lier et le readiness final tomberait sur un « 502 ou hors service ». Deux
# sources d'OP résiduel : le pidfile (runs précédents de setup.sh) ET un OP
# orphelin (run manuel, pidfile écrasé) — le second est détecté via le
# propriétaire du port 8000. Tuer le listener fait aussi sortir ses parents
# (« uv run » et python intermédiaire attendent leur enfant).
if [ -f "$LOCAL_DIR/op.pid" ]; then
  old_pid="$(cat "$LOCAL_DIR/op.pid" 2>/dev/null || true)"
  if [ -n "$old_pid" ]; then
    log "arrêt de l'OP résiduel (pidfile $old_pid)"
    stop_pid "$old_pid"
  fi
  rm -f "$LOCAL_DIR/op.pid"
fi
listener="$(port_listener_pid || true)"
if [ -n "${listener:-}" ]; then
  log "port $OP_PORT toujours pris (pid $listener) : arrêt de l'écouteur"
  stop_pid "$listener"
fi
deadline=$((SECONDS + 10))
while curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$OP_PORT/" 2>/dev/null; do
  [ $SECONDS -lt $deadline ] || { echo "[setup] port $OP_PORT toujours actif apres arret — verifiez manuellement" >&2; exit 1; }
  sleep 1
done
log "démarrage de l'OP (uvicorn :$OP_PORT, issuer https://$OP_ALIAS:$MTLS_PORT)"
# Secret du client d'administration de la certification : lu dans
# l'environnement (jamais committé - le seed le référence par
# `${CERTIFICATION_ADMIN_CLIENT_SECRET}`). Valeur locale par défaut pour le
# harnais local (instance sur localhost) ; l'instance hébergée fournit la
# sienne via le tableau de bord Render.
export CERTIFICATION_ADMIN_CLIENT_SECRET="${CERTIFICATION_ADMIN_CLIENT_SECRET:-local-certification-admin-secret}"
# PURIDENTITYSERVER_REQUEST_URI_ALLOW_LOCAL_TARGETS : la suite sert le document
# request_uri sur localhost.emobix.co.uk (→127.0.0.1), destination loopback
# refusée par la garde anti-SSRF tant que l'OP bind 0.0.0.0 (issue #152).
# PURIDENTITYSERVER_FEDERATION_ALLOW_LOCAL_TARGETS : même garde pour le fetch
# des entity statements de la fédération — l'ancre de confiance de la suite
# est sur localhost.emobix.co.uk (issue #170).
# SSL_CERT_FILE : certificat SAN de la suite (étape 3.5) + bundle système.
PURIDENTITYSERVER_SETTINGS_FILE="$(winpath "$LOCAL_DIR/op-config.toml")" \
PURIDENTITYSERVER_HOST="$OP_HOST" \
PURIDENTITYSERVER_PORT="$OP_PORT" \
PURIDENTITYSERVER_REQUEST_URI_ALLOW_LOCAL_TARGETS=true \
PURIDENTITYSERVER_FEDERATION_ALLOW_LOCAL_TARGETS=true \
SSL_CERT_FILE="$(winpath "$SUITE_TRUST")" \
  nohup uv run python -m puridentityserver \
    >"$LOCAL_DIR/op.log" 2>&1 & echo $! > "$LOCAL_DIR/op.pid"

# ---8) Attente de la disponibilité --------------------------------------------
log "attente de la suite ($SUITE_HOSTNAME:$SUITE_PORT)…"
deadline=$((SECONDS + 300))
until curl -sk --max-time 10 -o /dev/null \
    "https://$SUITE_HOSTNAME:$SUITE_PORT/api/runner/available"; do
  [ $SECONDS -lt $deadline ] || { echo "::error::suite non joignable"; exit 1; }
  sleep 5
done
log "suite prête"

log "attente de l'OP via le nginx mTLS (localhost:$MTLS_PORT)…"
deadline=$((SECONDS + 120))
# --fail obligatoire : sans lui curl sort en 0 sur le 502 de nginx (OP en
# cours d'amorçage) et la readiness passe à tort — le driver démarre alors
# sur un OP absent et les premiers modules tombent en 502 (abort
# « conformance server appears to be unhealthy » avant tout export).
until curl -skf --max-time 10 -o /dev/null \
    "https://localhost:$MTLS_PORT/.well-known/openid-configuration"; do
  [ $SECONDS -lt $deadline ] || {
    echo "::error::OP non joignable via nginx mTLS (502 ou hors service)"
    echo "--- dernières lignes de op.log ---"
    tail -n 60 "$LOCAL_DIR/op.log" || true
    exit 1
  }
  sleep 3
done
log "OP prêt (issuer https://$OP_ALIAS:$MTLS_PORT)"

log "harness local opérationnel :"
log "  suite   : https://$SUITE_HOSTNAME:$SUITE_PORT/   (CONFORMANCE_SERVER / {SUITEURL})"
log "  OP      : https://$OP_ALIAS:$MTLS_PORT/          ({OPURL}, mTLS terminé)"
log "  logs OP : $LOCAL_DIR/op.log"
