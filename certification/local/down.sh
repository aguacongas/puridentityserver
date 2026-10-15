#!/usr/bin/env bash
# Arrete et nettoie le harness local de certification (contrepartie de
# setup.sh, idempotent, sans effet sur les images docker).
#
# Usage : bash certification/local/down.sh [--purge]
#   --purge   supprime aussi $LOCAL_DIR (.harness-local : certs, config OP,
#             logs, plans generes, exports). Le clone de la suite est conserve
#             (reutilise au run suivant).
#
# Arrete, dans l'ordre : l'OP uvicorn (pidfile), le nginx mTLS `op-mtls`, les
# conteneurs de la suite (docker compose down — images conservees).
# Windows : se lancer depuis git-bash (pas PowerShell).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
SUITE_DIR="${SUITE_DIR:-$REPO_ROOT/conformance-suite}"
LOCAL_DIR="${LOCAL_DIR:-$REPO_ROOT/.harness-local}"
OP_ALIAS="op"

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
elif [ -n "${1:-}" ]; then
  echo "Usage : bash certification/local/down.sh [--purge]" >&2
  exit 2
fi

log() { printf '[down] %s\n' "$*"; }

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

# --- 1) OP uvicorn (hôte) -----------------------------------------------------
# Deux sources d'OP résiduel : le pidfile (runs de setup.sh) ET un OP orphelin
# (run manuel, pidfile écrasé) — le second est détecté via le propriétaire du
# port 8000. Le pkill « python -m puridentityserver » reste le dernier repli
# Unix (git-bash ne fournit pas pkill).
OP_PORT="${OP_PORT:-8000}"
op_still_up() {
  curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$OP_PORT/" 2>/dev/null
}
if [ -f "$LOCAL_DIR/op.pid" ]; then
  pid="$(cat "$LOCAL_DIR/op.pid" 2>/dev/null || true)"
  if [ -n "$pid" ]; then
    log "arret de l'OP (pidfile $pid)"
    stop_pid "$pid"
    sleep 1
  fi
  rm -f "$LOCAL_DIR/op.pid"
fi
listener="$(port_listener_pid || true)"
if [ -n "${listener:-}" ]; then
  log "port $OP_PORT toujours pris (pid $listener) : arret de l'ecouteur"
  stop_pid "$listener"
  sleep 1
fi
if op_still_up && command -v pkill >/dev/null 2>&1; then
  log "port $OP_PORT toujours pris : arret force (python -m puridentityserver)"
  pkill -f "python -m puridentityserver" 2>/dev/null || true
fi

# --- 2) nginx mTLS « op » -----------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$OP_ALIAS-mtls"; then
    log "arret du conteneur $OP_ALIAS-mtls"
    docker rm -f "$OP_ALIAS-mtls" >/dev/null
  fi

  # --- 3) Conteneurs de la suite (mongodb + server + nginx) -------------------
  if [ -f "$SUITE_DIR/docker-compose-prebuilt.yml" ]; then
    log "arret des conteneurs de la suite (images conservees)"
    ( cd "$SUITE_DIR" && docker compose -f docker-compose-prebuilt.yml down ) \
      >/dev/null 2>&1 || true
  fi
else
  log "docker indisponible ou daemon arrete : conteneurs non touches"
fi

# --- 4) Purge optionnelle des artefacts du harness ---------------------------
if [ "$PURGE" -eq 1 ]; then
  log "purge de $LOCAL_DIR"
  rm -rf "$LOCAL_DIR"
fi

log "harness local arrete (clone de la suite conserve : $SUITE_DIR)"
