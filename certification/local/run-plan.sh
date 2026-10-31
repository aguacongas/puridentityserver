#!/usr/bin/env bash
# Rejoue un plan de certification OIDC en local, en une commande.
#
# Reproduit la sequence stricte du workflow CI `certification-local.yml` :
#   1. readiness du harness (suite + OP) ; bootstrap via setup.sh si absent ;
#   2. application idempotente des patches du driver (prepare-suite.sh) ;
#   3. substitution des URLs locales {OPURL}/{SUITEURL} dans une copie generee
#      du clone (plans/<plan>.json, gitignore — le working tree git reste
#      propre ; chemin relatif impose par la grammaire du driver) ;
#   4. lancement du driver officiel en sortie stricte (code retour non nul des
#      qu'un module est FAILED/INTERRUPTED ou un warning inattendu survient) ;
#      les ecarts connus declares dans certification/expected-failures/
#      <plan>.json sont classes « expected » par le driver (mode witness) et
#      ne bloquent pas — idem CI, meme chemin de fichier ;
#   5. bilan PASSED/FAILED/REVIEW lu dans les exports produits par CE run
#      (le dossier d'export local conserve les sessions precedentes : seuls
#      les zip du run courant sont comptes), + chemins log/export.
#
# Usage : bash certification/local/run-plan.sh <plan> [--export-dir <dir>]
#   plans : basic | implicit | hybrid | formpost | dynamic | ciba | fapi1 | fapi2 |
#           fapi2-message-signing | ekyc | federation | oid4vci | oid4vci-mdoc
#
# Variables d'environnement (defauts en accord avec setup.sh) :
#   REPO_ROOT, SUITE_DIR, LOCAL_DIR  chemins racine du depot / clone suite /
#                                    artefacts du harness.
#
# Windows : se lancer depuis git-bash (pas PowerShell).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
SUITE_DIR="${SUITE_DIR:-$REPO_ROOT/conformance-suite}"
LOCAL_DIR="${LOCAL_DIR:-$REPO_ROOT/.harness-local}"

# URLs de substitution — valeurs identiques a l'env du workflow
# certification-local.yml ({OPURL} = point d'entree mTLS joignable par le
# navigateur HtmlUnit via l'alias réseau docker ; {SUITEURL} = API du driver,
# slash finale comprise : sans elle le match de callback du plan devient
# `…8443test/…` et les modules restent WAITING).
OP_URL="https://op:9443"
SUITE_URL="https://localhost.emobix.co.uk:8443/"
SUITE_HOSTNAME="localhost.emobix.co.uk"
SUITE_PORT="8443"
MTLS_PORT="9443"

log() { printf '[run-plan] %s\n' "$*"; }

usage() {
  echo "Usage : bash certification/local/run-plan.sh <plan> [--export-dir <dir>]" >&2
  echo "  plans : basic | implicit | hybrid | formpost | dynamic | ciba | fapi1 | fapi2 |" >&2
  echo "          fapi2-message-signing | ekyc | federation | oid4vci | oid4vci-mdoc" >&2  exit 2
}

if [ $# -lt 1 ]; then usage; fi
plan="$1"
shift
export_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --export-dir) export_dir="${2:-}"; [ -n "$export_dir" ] || usage; shift 2 ;;
    -h|--help) usage ;;
    *) echo "option inconnue : $1" >&2; usage ;;
  esac
done

source "$REPO_ROOT/certification/selectors.sh"
if ! selector="$(selector_for "$plan")"; then
  echo "[run-plan] plan inconnu : $plan (plans : ${CERTIFICATION_PLANS[*]})" >&2
  exit 2
fi

# --- 1) Readiness du harness -------------------------------------------------
suite_ready() {
  curl -skf --max-time 5 -o /dev/null \
    "https://$SUITE_HOSTNAME:$SUITE_PORT/api/runner/available"
}
op_ready() {
  curl -skf --max-time 5 -o /dev/null \
    "https://localhost:$MTLS_PORT/.well-known/openid-configuration"
}
if suite_ready && op_ready; then
  log "harness deja operationnel (suite + OP)"
else
  log "harness non pret — bootstrap via setup.sh"
  bash "$SCRIPT_DIR/setup.sh"
fi

# --- 2) Patches du driver (idempotents) --------------------------------------
bash "$SCRIPT_DIR/prepare-suite.sh"

# --- 2bis) Jeton d'administration (rotation des cles de signature) -----------
# Le module `oidcc-server-rotate-keys` compare le JWKS avant et apres son
# demarrage : la rotation des cles de signature de l'OP doit avoir lieu ENTRE
# les deux releves. Le patch `conformance-key-rotation` du driver appelle
# l'endpoint d'administration `POST /signing-keys/rotate` juste avant de
# demarrer le module - il lui faut donc un jeton d'administration, obtenu ici
# (grant `client_credentials`, client seed `certification-admin`). Le secret
# n'est jamais commite : il est lu dans l'environnement.
export CERTIFICATION_ADMIN_CLIENT_SECRET="${CERTIFICATION_ADMIN_CLIENT_SECRET:-local-certification-admin-secret}"
admin_token="$(bash "$SCRIPT_DIR/admin-token.sh" "http://127.0.0.1:${OP_PORT:-8000}" \
  "$LOCAL_DIR/op-config.toml" || true)"
if [ -n "$admin_token" ]; then
  export KEY_ROTATION_ENDPOINT="http://127.0.0.1:${OP_PORT:-8000}/signing-keys/rotate"
  export KEY_ROTATION_TOKEN="$admin_token"
  log "jeton d'administration obtenu (rotation des cles de signature armee)"
else
  log "jeton d'administration indisponible : rotation des cles non armee"
fi

# --- 3) Substitution des URLs du plan (copie generee, working tree propre) ---
# La copie va dans le clone de la suite (gitignore : conformance-suite/) et le
# driver la recoit en chemin RELATIF (cwd = clone) : la grammaire pyparsing des
# positionnels (path_chars = alphanums + '-_./') refuse ':' et '\' — un chemin
# Windows absolu serait tronque a « C ».
src="$REPO_ROOT/certification/plans/$plan.json"
gen="$SUITE_DIR/plans/$plan.json"
driver_cfg="plans/$plan.json"
mkdir -p "$(dirname "$gen")"
sed -e "s|{OPURL}|$OP_URL|g" -e "s|{SUITEURL}|$SUITE_URL|g" "$src" > "$gen"
if grep -qF -e '{OPURL}' -e '{SUITEURL}' "$gen"; then
  echo "[run-plan] substitution incomplete dans $gen" >&2
  exit 1
fi
log "plan genere : $gen"
grep -h '"match"' "$gen" | sort -u || true

# --- 4) Lancement du driver (sortie stricte, idem CI) -------------------------
# Mode dev OFFICIEL de la suite self-hosted : token vide (aucun header
# Authorization) + verification SSL desactivee (certificat auto-signé).
export CONFORMANCE_DEV_MODE="1"
export CONFORMANCE_TOKEN=""
export DISABLE_SSL_VERIFY="1"
export CONFORMANCE_MODULE_TIMEOUT="600"
export CONFORMANCE_SERVER="$SUITE_URL"
[ -n "$export_dir" ] || export_dir="$LOCAL_DIR/results/$plan"
mkdir -p "$export_dir"
run_log="$LOCAL_DIR/last-$plan.log"

# Snapshot des exports deja presents : le dossier d'export local accumule les
# sessions precedentes et le bilan (etape 5) ne doit porter que sur les
# exports produits par CE run. Les archives anciennes sont conservees : elles
# restent utiles au diagnostic.
#
# Le driver reutilise parfois le NOM d'une archive (identifiant de plan +
# date du jour) et l'ecrase : la detection ne peut donc pas reposer sur le
# seul nom. Un export est attribue a ce run s'il est nouveau (absent du
# snapshot) OU s'il a ete modifie apres le lancement du driver.
export_manifest="$LOCAL_DIR/.exports-before-$plan.txt"
mkdir -p "$LOCAL_DIR"
: > "$export_manifest"
for archive in "$export_dir"/*.zip; do
  if [ -e "$archive" ]; then
    basename "$archive" >> "$export_manifest"
  fi
done
run_started="$(date +%s)"

# Date de modification d'un fichier (secondes), portable GNU/BSD.
mtime_of() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
}

log "lancement du plan $plan (log : $run_log)"
# Temoignage (mode witness) : les ecarts de modules connus et documentes
# (capacites OP absentes, module manuel) sont declares dans
# certification/expected-failures/<plan>.json. Le driver les classe en
# « expected failure » et le plan ne sort en code non nul que pour les
# ecarts INATTENDUS (strictude #130 preservee).
expected_args=()
expected_file="$REPO_ROOT/certification/expected-failures/$plan.json"
if [ -f "$expected_file" ]; then
  expected_args=(--expected-failures-file "$expected_file")
  log "ecarts attendus (witness) : $expected_file"
fi
# Modules sautes attendus (capacite OP absente ou hors perimetre) : meme
# format, fichier dedie <plan>-skips.json — le driver les classe en
# « skipped as expected » au lieu d'« unexpected skip ».
skips_file="$REPO_ROOT/certification/expected-failures/$plan-skips.json"
if [ -f "$skips_file" ]; then
  expected_args+=(--expected-skips-file "$skips_file")
  log "sauts attendus (witness) : $skips_file"
fi
code=0
(
  cd "$SUITE_DIR"
  uv run --no-project --with httpx --with pyparsing \
    python scripts/run-test-plan.py \
    --export-dir "$export_dir" \
    ${expected_args[@]+"${expected_args[@]}"} \
    "$selector" "$driver_cfg"
) 2>&1 | tee "$run_log" || code=$?

# --- 5) Bilan lu dans l'export (meme source que la CI) -----------------------
# Seuls les exports produits par ce run sont comptes (le dossier d'export
# local conserve les sessions precedentes).
run_exports=()
total_exports=0
for archive in "$export_dir"/*.zip; do
  if [ -e "$archive" ]; then
    total_exports=$((total_exports + 1))
    name="$(basename "$archive")"
    modified="$(mtime_of "$archive")"
    if ! grep -qxF "$name" "$export_manifest" || [ "$modified" -ge "$run_started" ]; then
      run_exports+=("$archive")
    fi
  fi
done
log "exports du run : ${#run_exports[@]} / $total_exports dans $export_dir"
bilan_code=0
uv run --no-project python - "$export_dir" ${run_exports[@]+"${run_exports[@]}"} <<'PY' || bilan_code=$?
"""Bilan des resultats module lus dans les exports zip du run courant."""
import collections
import json
import sys
import zipfile

export_dir = sys.argv[1]
paths = sys.argv[2:]
totals: collections.Counter[str] = collections.Counter()
for path in paths:
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            try:
                info = json.loads(archive.read(name)).get("testInfo") or {}
            except (json.JSONDecodeError, zipfile.BadZipFile, UnicodeDecodeError):
                continue
            totals[str(info.get("result") or "INCONNU")] += 1
if not paths:
    print(f"aucun export produit par ce run dans {export_dir} : le harness a crashé avant tout module")
    sys.exit(3)
detail = " / ".join(f"{count} {name}" for name, count in sorted(totals.items()))
print(f"bilan des modules : {detail} (total {sum(totals.values())})")
PY
if [ "$bilan_code" -ne 0 ]; then
  log "bilan indisponible (export absent ou illisible)"
fi
if [ -f "$expected_file" ]; then
  # Le bilan lit les resultats module bruts des exports : les ecarts witness
  # restent visibles en FAILED/INTERRUPTED la, ou le code retour du driver
  # (ci-dessus) les a classes en « expected ».
  log "ecarts attendus (witness) : certification/expected-failures/$plan.json"
fi
if [ -f "$skips_file" ]; then
  log "sauts attendus (witness) : certification/expected-failures/$plan-skips.json"
fi

log "export : $export_dir"
if [ "$code" -ne 0 ]; then
  log "plan $plan en echec (code $code) — dernieres lignes du log :"
  tail -n 20 "$run_log" || true
fi
exit "$code"
