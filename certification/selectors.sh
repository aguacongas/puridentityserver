# Selecteurs des plans de certification OIDC — source unique de verite pour la
# CI (workflows herberge `certification.yml` et local `certification-local.yml`)
# et pour le lancement local (`certification/local/run-plan.sh`).
#
# Usage : source certification/selectors.sh puis selector_for <plan>.
# shellcheck shell=bash

# Les six plans joues par defaut (filtre `all` des workflows).
CERTIFICATION_PLANS=(basic implicit hybrid ciba fapi1 fapi2)

# Retourne le selecteur de variante d'un plan sur stdout ; code retour 1 si le
# plan est inconnu (appelant : message d'erreur + sortie securisee).
selector_for() {
  case "$1" in
    basic) echo 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    implicit) echo 'oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    hybrid) echo 'oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    # CIBA : plan FAPI-CIBA-ID1 en mode witness (poll + Basic ne sont
    # pas des variants valides pour ce plan : private_key_jwt exigé,
    # JAR signé hors périmètre — issues dédiées).
    ciba) echo 'fapi-ciba-id1-test-plan[client_registration=dynamic_client][client_auth_type=private_key_jwt][ciba_mode=poll][fapi_ciba_profile=plain_fapi]' ;;
    # FAPI1 Advanced Final (issue #113) : plain_fapi + private_key_jwt,
    # request object by_value (défaut conseillé par la suite — l'OP
    # expose aussi PAR, à valider en certification) + réponse plain.
    fapi1) echo 'fapi1-advanced-final-test-plan[fapi_profile=plain_fapi][client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_response_mode=plain_response]' ;;
    # FAPI2 Security Profile Final : client_auth_type=private_key_jwt
    # OBLIGATOIRE (variante sans défaut : la création du plan échoue
    # sinon — « requires a value for variant client_auth_type »).
    # L'OP supporte DPoP (RFC 9449, sender_constrain=dpop) et n'a pas
    # de grant management ; notApplicableWhen n'exclut que
    # client_attestation avec plain_fapi.
    fapi2) echo 'fapi2-security-profile-final-test-plan[fapi_profile=plain_fapi][client_auth_type=private_key_jwt][authorization_request_type=simple][openid=openid_connect][sender_constrain=dpop]' ;;
    *) return 1 ;;
  esac
}
