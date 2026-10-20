# Selecteurs des plans de certification OIDC — source unique de verite pour la
# CI (workflows herberge `certification.yml` et local `certification-local.yml`)
# et pour le lancement local (`certification/local/run-plan.sh`).
#
# Usage : source certification/selectors.sh puis selector_for <plan>.
# shellcheck shell=bash

# Les neuf plans joues par defaut (filtre `all` des workflows).
CERTIFICATION_PLANS=(basic implicit hybrid formpost dynamic ciba fapi1 fapi2 fapi2-message-signing)

# Retourne le selecteur de variante d'un plan sur stdout ; code retour 1 si le
# plan est inconnu (appelant : message d'erreur + sortie securisee).
selector_for() {
  case "$1" in
    basic) echo 'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    implicit) echo 'oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    hybrid) echo 'oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    # Form Post (issue #165) : meme socle que basic (38 modules) avec la
    # variante ResponseMode forcee a form_post par la suite — reponses ET
    # erreurs d'autorisation livrees en POST auto-soumis vers la callback.
    formpost) echo 'oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client]' ;;
    # Dynamic (issue #168) : plan OIDF dedie au Dynamic Client Registration —
    # meme socle que basic avec en plus les modules de registration (dont
    # oidcc-registration-sector-uri / oidcc-registration-sector-bad pour
    # subject_type=pairwise et sector_identifier_uri).
    dynamic) echo 'oidcc-dynamic-certification-test-plan[response_type=code]' ;;
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
    # FAPI2 Message Signing Final (issue #164) : meme socle que fapi2 +
    # fapi_response_mode=jarm (response_mode=jwt sur /authorize, reponses
    # d'autorisation enveloppees en JWT signe — reussites ET erreurs).
    # fapi_request_method=unsigned est explicite : la variante n'a pas de
    # defaultValue dans la suite (release-v5.3.3) — la creation du plan
    # echoue sans valeur (« requires a value for variant fapi_request_method ») ;
    # le plan fapi2 ne l'expose que via la reutilisation d'un plan anterieur.
    fapi2-message-signing) echo 'fapi2-message-signing-final-test-plan[fapi_profile=plain_fapi][client_auth_type=private_key_jwt][fapi_request_method=unsigned][authorization_request_type=simple][openid=openid_connect][sender_constrain=dpop][fapi_response_mode=jarm]' ;;
    *) return 1 ;;
  esac
}
