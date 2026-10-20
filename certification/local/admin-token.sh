#!/usr/bin/env bash
# Imprime un access token d'administration pour l'OP de certification.
#
# Le client `certification-admin` (seed de certification/config.render.toml,
# meme configuration pour l'instance Render hebergee) obtient un jeton par le
# grant `client_credentials` ; son claim `client_id` satisfait la regle
# d'autorisation de l'API d'administration (`admin_required_claim`).
#
# Le jeton est utilise par le patch `conformance-key-rotation` du driver de
# la suite : il appelle `POST /signing-keys/rotate` juste avant de demarrer
# le module `oidcc-server-rotate-keys`, pour que la rotation des cles de
# signature de l'OP tombe ENTRE les deux releves du JWKS compares par le
# module.
#
# Usage : bash certification/local/admin-token.sh <url-op> [config]
set -euo pipefail

op_url="${1:?URL de l OP requise (ex. http://127.0.0.1:8000)}"
config="${2:-certification/config.render.toml}"

client_id="$(sed -n 's/^client_id = "\(certification-admin\)"$/\1/p' "$config" | head -n1)"
client_secret="$(sed -n 's/^client_secret = "\(.*\)"$/\1/p' "$config" | head -n1)"
if [ -z "$client_id" ] || [ -z "$client_secret" ]; then
  echo "[admin-token] client d'administration introuvable dans $config" >&2
  exit 1
fi

curl -sk --max-time 20 -X POST "${op_url%/}/token" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${client_id}" \
  --data-urlencode "client_secret=${client_secret}" \
  | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
