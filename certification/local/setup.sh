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
# - la suite (release-v5.2.4) tourne en docker (mongodb + server + nginx) ;
# - l'OP PurIdentityServer tourne sur l'hôte (uvicorn :8000), config locale
#   générée à partir de certification/config.render.toml (issuer = https://op:9443,
#   redirect_uris = callbacks de la suite LOCALE, SQLite éphémère) ;
# - un nginx « op » (conteneur, alias réseau `op` sur le réseau de la suite)
#   termine le mTLS devant l'OP (cert auto-signé, certificat client optionnel)
#   et passe le cert extrait via X-SSL-Client-Cert (voir nginx-mtls.conf).
#
# Réutilisable tel quel en local (DoD) : `bash certification/local/setup.sh`
# puis lancer un plan (voir certification/README.md, « Rejeu local complet »).
set -euo pipefail

# --- Configuration (surchargeable par env) ------------------------------------
SUITE_VERSION="${SUITE_VERSION:-release-v5.2.4}"
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

# ---1) Alias réseau : la suite génère ses callbacks sur localhost.emobix.co.uk.
# Le driver (hôte) doit y accéder comme le navigateur (conteneur) : on pointe
# l'alias vers127.0.0.1 côté hôte (Docker Desktop le fait déjà, Linux non).
if ! getent hosts "$SUITE_HOSTNAME" >/dev/null 2>&1; then
  log "ajout de $SUITE_HOSTNAME ->127.0.0.1 dans /etc/hosts"
  echo "127.0.0.1 $SUITE_HOSTNAME" | sudo tee -a /etc/hosts >/dev/null
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

# ---4) Certificat serveur auto-signé pour l'OP nginx --------------------------
if [ ! -f "$LOCAL_DIR/nginx.crt" ]; then
  log "génération du certificat serveur auto-signé (op, localhost, host.docker.internal)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$LOCAL_DIR/nginx.key" -out "$LOCAL_DIR/nginx.crt" \
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
  -v "$REPO_ROOT/certification/local/nginx-mtls.conf:/etc/nginx/nginx.conf:ro" \
  -v "$LOCAL_DIR/nginx.crt:/etc/nginx/tls/nginx.crt:ro" \
  -v "$LOCAL_DIR/nginx.key:/etc/nginx/tls/nginx.key:ro" \
  nginx:alpine >/dev/null

# ---6) Config OP locale (issuer op:9443, callbacks suite locale, SQLite) ------
log "génération de la config OP locale"
sed \
  -e "s|issuer = \"http://127.0.0.1:8000\"|issuer = \"https://$OP_ALIAS:$MTLS_PORT\"|" \
  -e "s|https://www.certification.openid.net|https://$SUITE_HOSTNAME:$SUITE_PORT|g" \
  -e "s|storage_dsn = \"sqlite:///puridentityserver.db\"|storage_dsn = \"sqlite:///$LOCAL_DIR/op.db\"|" \
  "$REPO_ROOT/certification/config.render.toml" > "$LOCAL_DIR/op-config.toml"

# ---7) OP uvicorn (hôte) ------------------------------------------------------
log "installation des dépendances OP (uv sync --extra sql)"
( cd "$REPO_ROOT" && uv sync --extra sql --locked >/dev/null )
log "démarrage de l'OP (uvicorn :$OP_PORT, issuer https://$OP_ALIAS:$MTLS_PORT)"
PURIDENTITYSERVER_SETTINGS_FILE="$LOCAL_DIR/op-config.toml" \
PURIDENTITYSERVER_HOST="$OP_HOST" \
PURIDENTITYSERVER_PORT="$OP_PORT" \
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
