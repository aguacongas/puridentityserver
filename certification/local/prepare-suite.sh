#!/usr/bin/env bash
# Application idempotente des patches du driver de la suite de certification.
#
# Reproduit a l'identique le step « Patch du driver » du workflow CI
# (certification-local.yml) : 4 patches certification/*.patch dans l'ordre
# de reference, puis le timeout de module rendu parametrable via
# CONFORMANCE_MODULE_TIMEOUT. Rejouable sans dommage : chaque patch est detecte
# par sa sentinelle (ligne ajoutee unique, testee par contenu — insensible a
# l'ordre des patches, a leurs chevauchements et aux fins de ligne, contrairement
# a `git apply --reverse --check`).
#
# Variables d'environnement (defauts en accord avec setup.sh) :
#   REPO_ROOT  racine du depot          (defaut : pwd)
#   SUITE_DIR  clone de la suite        (defaut : $REPO_ROOT/conformance-suite)
#   PATCH_DIR  dossier des *.patch      (defaut : $REPO_ROOT/certification)
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(pwd)}"
SUITE_DIR="${SUITE_DIR:-$REPO_ROOT/conformance-suite}"
PATCH_DIR="${PATCH_DIR:-$REPO_ROOT/certification}"

log() { printf '[prepare] %s\n' "$*"; }

if [ ! -d "$SUITE_DIR/.git" ]; then
  echo "[prepare] clone de la suite introuvable : $SUITE_DIR (lancez setup.sh)" >&2
  exit 1
fi

# Sentinelle de chaque patch : ligne ajoutee par le patch, absente du code
# vierge de la suite (verifie release v5.3.3) et unique dans scripts/conformance.py.
sentinel_of() {
  case "$1" in
    conformance-screenshots) printf '%s' "# Donnees (data URI) d'une capture d'ecran de secours" ;;
    conformance-alias-release) printf '%s' 'async def release_alias(self, alias, timeout=180):' ;;
    conformance-interrupted-diagnostics) printf '%s' 'async def describe_interruption(self, module_id):' ;;
    conformance-key-rotation) printf '%s' 'async def rotate_op_signing_keys():' ;;
    *) return 1 ;;
  esac
}

# Fichier cible de chaque patch (relatif a la racine du clone de la suite).
target_of() {
  case "$1" in
    conformance-key-rotation) printf '%s' 'scripts/run-test-plan.py' ;;
    *) printf '%s' 'scripts/conformance.py' ;;
  esac
}

# conformance-reuse-plan et conformance-stale-plan-recovery retires (issue #132) :
# chaque run cree ses plans frais (POST /api/plan). Leur purge en fin de run est
# geree par certification/prune_stale_plans.py (DELETE /api/plan/{id}).
for patch in \
  conformance-screenshots \
  conformance-alias-release \
  conformance-interrupted-diagnostics \
  conformance-key-rotation; do
  target="$SUITE_DIR/$(target_of "$patch")"
  file="$PATCH_DIR/$patch.patch"
  sentinel="$(sentinel_of "$patch")"
  if grep -qF "$sentinel" "$target" 2>/dev/null; then
    log "$patch : deja applique"
  elif git -C "$SUITE_DIR" apply --check "$file" >/dev/null 2>&1; then
    git -C "$SUITE_DIR" apply "$file"
    log "$patch : applique"
  else
    echo "[prepare] $patch ne s'applique pas : contexte derive (nouvelle release" \
      "de la suite ?) ou clone modifie manuellement — voir « Dépannage » dans" \
      "certification/README.md (solution : git -C $SUITE_DIR reset --hard)" >&2
    exit 1
  fi
done

# Timeout de module rendu parametrable. sed portable (sans -i, incompatible
# avec BSD sed/macOS) : ecriture via fichier temporaire. Idempotent : le motif
# `timeout=240` n'existe plus apres la premiere passe.
timeout_target="$SUITE_DIR/scripts/conformance.py"
if grep -q 'timeout=240' "$timeout_target"; then
  sed 's|timeout=240|timeout=int(os.getenv("CONFORMANCE_MODULE_TIMEOUT", "240"))|' \
    "$timeout_target" > "$timeout_target.tmp"
  mv "$timeout_target.tmp" "$timeout_target"
  log "timeout de module parametrable (CONFORMANCE_MODULE_TIMEOUT)"
fi

log "driver de la suite pret ($SUITE_DIR)"
