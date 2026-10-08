# Traçabilité des checks rejoués (PR 1/4 — #69, PR 2/4 — #70, PR 3/4 — #71, PR 4/4 — #72, FAPI-CIBA-ID1 — #109, FAPI1 Advanced Final — #110)

Ce dossier rejoue localement les checks de la suite officielle
[`openid/conformance-suite`](https://github.com/openid/conformance-suite),
**tag `release-v5.2.4`** (celui du run de référence de la certification).

Le clone de la suite sert uniquement à **extraire** les définitions des checks
(liste `class_definition.xml` + classes Java des modules cibles). Il n'est pas
versionné ni committé ici : on le clone à la demande en lecture seule,

```powershell
git clone --depth 1 --branch release-v5.2.4 https://github.com/openid/conformance-suite $env:TEMP\opencode\conformance-suite
```

et on relit les fichiers cités ci-dessous à chaque nouvelle PR.

## Comment exécuter

```powershell
# rejeu (exclu du gate : addopts porte -m "not conformance")
uv run --no-sync --no-build --locked python -m pytest -m conformance --no-cov -p no:cacheprovider
# contre un OP réel démarré localement (le harness bascule sur httpx)
$env:PURIDENTITYSERVER_CONFORMANCE_URL = "http://127.0.0.1:8000"
# ou smoke complet : serveur uvicorn + rejeu des 328 scénarios (PR 4 + #109 + #110)
uv run python samples/conformance-smoke/smoke_test.py
```

`--no-cov` est requis : le sous-ensemble ne couvre pas le seuil de
80 % du gate (94 % sur la suite complète). Pas de `-q` non plus : le résumé
`164 passed, 9 skipped, 737 deselected` (PR 3) est la preuve, dans les logs du
job comme en local, que le rejeu a bien eu lieu — le rapport détaillé est aussi
publié dans la PR (`scripts/conformance_report.py`).

## Matrice module → test (PR 1)

| Module de la suite | Check Java lu dans le clone | Test Python | Assertion |
| --- | --- | --- | --- |
| `oidcc-ensure-registered-redirect-uri` | `condition/client/CreateBadRedirectUriByAppending.java` (base + `/callback/` + aléatoire), `condition/common/ExpectRedirectUriErrorPage.java` (« Show redirect URI error page », OIDCC-3.1.2.1) | `test_redirect_reauth.py::test_ensure_registered_redirect_uri_displays_error_page` | `checks.expect_redirect_uri_error_page` |
| `oidcc-prompt-login` | `condition/client/WaitForOneSecond.java`, `condition/client/ExpectSecondLoginPage.java` (« server must ask the user to login for a second time », match `{OPURL}/login*`), `condition/client/CheckSecondIdTokenAuthTimeIsLaterIfPresent.java` (égalité ou antérieur = erreur) | `test_redirect_reauth.py::test_prompt_login_forces_second_authentication` | `checks.expect_second_login_page`, `checks.check_second_auth_time_is_later` |
| `oidcc-max-age-1` | `condition/client/WaitFor2Seconds.java`, `ExpectSecondLoginPage`, `condition/client/CheckIdTokenAuthTimeClaimPresentDueToMaxAge.java`, `CheckSecondIdTokenAuthTimeIsLaterIfPresent.java`, `CheckIdTokenAuthTimeIsRecentIfPresent.java` (< 5 min de skew) | `test_redirect_reauth.py::test_max_age_1_reprompts_authentication` | les 4 checks associés |

Les 3 tests sont marqués `conformance` (marker déclaré dans `pyproject.toml`).

## Matrice module → test (PR 2 — issue #70)

`testModulesWithVariants()` d'`OIDCCBasicTestPlan.java` : 38 modules. Les 3
ci-dessus (PR 1) + les 35 ci-dessous couvrent l'intégralité du plan.
Les blocs de conditions hérités sont notés `[BASE]` (flux nominal complet :
callback + `PerformStandardIdTokenChecks` + échange du code, voir
`AbstractOIDCCServerTest`), `[RC]` (userinfo via `AbstractOIDCCReturnedClaimsServerTest`),
`[UI]` (`AbstractOIDCCUserInfoTest`), `[CR]` (`AbstractOIDCCAuthCodeReuse` :
400 + `invalid_grant`),
`[SAT]` (`AbstractOIDCCSameAuthTwiceServerTest` : `CheckIdTokenAuthTimeClaimsSameIfPresent`
+ `CheckIdTokenSubConsistentForSecondAuthorization`),
`[GEN-ERR]` (`performGenericAuthorizationEndpointErrorResponseValidation`).

### Paramètres d'autorisation (8 modules — test paramétré `test_authorize_parameter_is_accepted`)

| Module | Check Java lu dans le clone | Assertion |
| --- | --- | --- |
| `oidcc-display-page` | `OIDCCDisplayPage.java` → `AddDisplayPageToAuthorizationEndpointRequest`, [BASE] | `checks.expect_callback_success` + `checks.validate_id_token` |
| `oidcc-display-popup` | `OIDCCDisplayPopup.java` → `AddDisplayPopupToAuthorizationEndpointRequest`, [BASE] | idem |
| `oidcc-login-hint` | `OIDCCLoginHint.java` → `AddLoginHintFromConfigurationToAuthorizationEndpointRequest`, [BASE] | idem |
| `oidcc-ui-locales` | `OIDCCUiLocales.java` → `AddUiLocalesFromConfigurationToAuthorizationEndpointRequest`, [BASE] | idem |
| `oidcc-claims-locales` | `OIDCCClaimsLocales.java` → `AddClaimsLocalesSeToAuthorizationEndpointRequest`, [BASE] | idem |
| `oidcc-ensure-request-with-unknown-parameter-succeeds` | `OIDCCEnsureRequestWithUnknownParameterSucceeds.java` → `AddExtraFoobarToAuthorizationEndpointRequest`, [BASE] | idem |
| `oidcc-ensure-request-with-acr-values-succeeds` | `OIDCCEnsureRequestWithAcrValuesSucceeds.java` → `OIDCCAddAcrValuesToAuthorizationEndpointRequest`, `ValidateIdTokenACRClaimAgainstAcrValuesRequest` **(WARNING si `acr` absent)**, [BASE] | `checks.check_acr_claim` — `acr_values=1 2` et `scope=openid` repris des logs de certification, `acr` ∈ valeurs demandées dans l'id_token du token endpoint (#80) |
| `oidcc-claims-essential` | `OIDCCClaimsEssential.java` → `AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest`, `EnsureUserInfoContainsName` **(WARNING)**, `EnsureIdTokenDoesNotContainName` **(WARNING)**, `[RC]` | `name` présent du userinfo + absent de l'id_token (`scope=openid` seul, fidèle aux logs) (#80) |

### Scopes (5 modules — test paramétré `test_scope_claims_returned_in_userinfo`)

| Module | Check Java lu dans le clone | Assertion |
| --- | --- | --- |
| `oidcc-scope-profile` / `-email` / `-address` / `-phone` / `-all` | `OIDCCScope*.java` → `SetScopeInClientConfigurationToOpenIdX` + `skipTestIfScopesNotSupported` (**skip** si le scope est absent du discovery), `[RC]` (`CallUserInfoEndpoint`, `EnsureHttpStatusCodeIs200`, `ValidateUserInfoStandardClaims`, `EnsureUserInfoContainsSub`, `VerifyScopesReturnedInUserInfoClaims` **(WARNING)**) ; `OIDCCScopeEmail` ajoute `EnsureIdTokenDoesNotContainEmailForScopeEmail` | `checks.check_scope_claims_returned` (userinfo 200 + claims du scope) ; pour `-email`, `checks.check_scope_claims_absent_from_id_token` (#80) |

### Endpoint userinfo (3 modules — test paramétré `test_userinfo_endpoint_method`)

| Module | Check Java lu dans le clone | Assertion |
| --- | --- | --- |
| `oidcc-userinfo-get` | `OIDCCUserInfoGet.java` (classe vide) → `[UI]` | `checks.check_userinfo_response` (200 + `content-type` JSON + `sub`) |
| `oidcc-userinfo-post-header` | `OIDCCUserInfoPostHeader.java` → `SetResourceMethodToPost`, `[UI]` | idem (POST Bearer) |
| `oidcc-userinfo-post-body` | `OIDCCUserInfoPostBody.java` → `CallUserInfoEndpointWithBearerTokenInBody`, `UserInfoEndpointWithAccessTokenInBodyNotSupported` **(WARNING évité)** | `checks.check_userinfo_response` — token en corps form accepté par l'OP (RFC 6750 §2.1.2, #83) |

### Double autorisation (3 modules)

| Module | Check Java lu dans le clone | Test Python | Assertion |
| --- | --- | --- | --- |
| `oidcc-prompt-none-logged-in` | `OIDCCPromptNoneLoggedIn.java` → `AddPromptNoneToAuthorizationEndpointRequest` (2ᵉ autorisation), `[SAT]` | `test_prompt_none_logged_in_issues_code` | `checks.check_second_id_token_consistent` |
| `oidcc-id-token-hint` | `OIDCCIdTokenHint.java` → `AddIdTokenHintFromFirstLoginToAuthorizationEndpointRequest` + `AddPromptNoneToAuthorizationEndpointRequest`, `[SAT]` | `test_id_token_hint_keeps_session` | idem |
| `oidcc-max-age-10000` | `OIDCCMaxAge10000.java` → `AddMaxAge15000…` (1ʳᵉ) / `AddMaxAge10000…` (2ᵉ) + `CheckIdTokenAuthTimeClaimPresentDueToMaxAge` ×2, `[SAT]` | `test_max_age_10000_keeps_session_and_returns_auth_time` | idem |

### Flux et sécurité (14 lignes — 16 modules)

| Module | Check Java lu dans le clone | Test Python | Assertion |
| --- | --- | --- | --- |
| `oidcc-prompt-none-not-logged-in` | `OIDCCPromptNoneNotLoggedIn.java` → `AddPromptNoneToAuthorizationEndpointRequest`, `CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface`, `[GEN-ERR]` | `test_prompt_none_without_session_returns_login_required` | `checks.expect_authorization_error` (`login_required`) |
| `oidcc-response-type-missing` | `OIDCCResponseTypeMissing.java` → `ExpectResponseTypeMissingErrorPage`, `CheckErrorFromAuthorizationEndpointErrorInvalidRequestOrUnsupportedResponseType`, `[GEN-ERR]` | `test_response_type_missing_shows_error_page` | `checks.expect_response_type_missing_error_page` |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | `OIDCCEnsureRequestWithoutNonceSucceedsForCodeFlow.java` → `.skip(AddNonceToAuthorizationEndpointRequest)`, [BASE] | `test_request_without_nonce_succeeds` | `checks.expect_callback_success` + `checks.validate_id_token` |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | `OIDCCEnsureRequestWithValidPkceSucceeds.java` → `SetupPkceAndAddToAuthorizationRequest` (`CreateRandomCodeVerifier`, `CreateS256CodeChallenge`, `AddCodeChallenge…`), `AddCodeVerifierToTokenEndpointRequest`, [BASE] | `test_request_with_valid_pkce_succeeds` | idem |
| `oidcc-ensure-post-request-succeeds` | `OIDCCEnsurePostRequestSucceeds.java` → requête envoyée en **POST**, `ExpectRedirectUriHasBeenCalled` **(WARNING après 30 s sans callback)**, [BASE] | `test_post_authorization_request_succeeds` | `checks.expect_callback_success` — POST **sur session vierge** : l'OP rejoue les paramètres du corps form dans `next` après `/login` (voir note ci-dessous) |
| `oidcc-alternate-happy-flow` | `OIDCCAlternateHappyFlow.java` → `ReverseScopeOrderInAuthorizationEndpointRequest`, `BuildPlainRedirectToAuthorizationEndpointReorderedParams`, hérite `OIDCCScopeEmail` + `[RC]` | `test_alternate_happy_flow_with_reordered_scopes` | `checks.expect_callback_success` + `checks.check_scope_claims_returned` + id_token sans `email` |
| `oidcc-server` | `OIDCCServerTest.java` → `EnsureMinimumAuthorizationCodeLength`, `EnsureMinimumAuthorizationCodeEntropy`, `ExtractAtHash`/`ValidateAtHash`, `ExtractCHash`/`ValidateCHash`, [BASE] | `test_authorization_code_has_minimum_quality` | `checks.check_authorization_code_quality` (≥ 16 caractères) + `checks.validate_id_token` |
| `oidcc-server-client-secret-post` | `OIDCCServerTestClientSecretPost.java` → `AddFormBasedClientSecretToRequest` + configuration `client_secret_post`, [BASE] | `test_client_secret_post_authentication` | `checks.check_token_endpoint_success` (échange en `client_secret_post`) + `checks.validate_id_token` |
| `oidcc-idtoken-signature` | `OIDCCIdTokenSignature.java` → `EnsureIdTokenContainsKid`, `EnsureIdTokenSignatureIsRS256`, `PerformStandardIdTokenChecks` | `test_id_token_signature_is_rs256_with_kid` | `checks.expect_id_token_signature` (header `alg=RS256` + `kid`) |
| `oidcc-idtoken-unsigned` | `OIDCCIdTokenUnsigned.java` → `skipTestIfSigningAlgorithmNotSupported` (levé : `none` annoncé) + `AddIdTokenSigningAlgNoneToDynamicRegistrationRequest` → `CheckIdTokenSignatureAlgorithm` (`header.alg == "none"`), `PlainJWT.serialize()` | `test_id_token_alg_none_is_issued` | `checks.expect_callback_success` + `checks.check_token_endpoint_success`, puis en-tête `alg=none`, segment de signature vide et `checks.validate_id_token` |
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | `skipTestIfNoneUnsupported` (levé : `none` dans `request_object_signing_alg_values_supported`) ; `AbstractAuthorizationCodeTest.buildRedirect` (doublons `response_type`/`client_id`/`scope`/`redirect_uri` en query, `state`/`nonce` dans le JWT), `OIDCCEnsureRequestObjectWithRedirectUri` → `AddInvalidRedirectUriToAuthorizationRequest`, `handleRequestUriRequest` en `Content-Type: application/jwt` | `test_request_object_module_completes[rt-*][<kind>]` (6 `ResponseType` × 3 modules) | `checks.expect_*_callback` + `checks.validate_id_token` : `state`/`nonce` ne venant que du request object, leur présence prouve son traitement ; `redirect_uri` du jeton prioritaire sur celle de la query |
| `oidcc-codereuse` | `OIDCCAuthCodeReuse.java` → `[CR]` (`CheckErrorFromTokenEndpointResponseErrorInvalidGrant`), `ServerAllowedReusingAuthorizationCode` **(WARNING)** | `test_authorization_code_cannot_be_reused` | `checks.expect_invalid_grant` + `checks.expect_access_token_refused` (`CallProtectedResource`, #85) |
| `oidcc-codereuse-30seconds` | `OIDCCAuthCodeReuseAfter30Seconds.java` → `WaitFor30Seconds`, `CallProtectedResource` + `EnsureHttpStatusCodeIs4xx` **(WARNING)**, `[CR]` | `test_authorization_code_reuse_after_30_seconds` | `checks.expect_invalid_grant` + `checks.expect_access_token_refused` + refresh `invalid_grant` (`scope=… offline_access` ajouté pour émettre le refresh, #85) |
| `oidcc-refresh-token` | `OIDCCRefreshToken.java` → séquence `RefreshTokenRequestSteps` (`WaitForOneSecond`, `EnsureAccessTokenValuesAreDifferent` **(INFO)**, `CompareIdTokenClaims` : `iss`/`sub`/`aud` égaux, `iat` différent) + `RefreshTokenRequestExpectingErrorSteps` chez le 2ᵉ client (`AbstractOIDCCMultipleClient`), skip si aucun refresh émis | `test_refresh_token_grant_and_client_binding` | `checks.check_token_endpoint_success` + `checks.check_refreshed_id_token_claims` + `checks.expect_invalid_grant` (jeton d'un autre client) |

### Note sur `oidcc-ensure-post-request-succeeds`

Sur session vierge, l'OP renvoyait vers `/login?next=/authorize` **sans** la
query string (le POST porte ses paramètres dans le corps) : le retour après
connexion arrivait sur `/authorize` sans paramètres → page d'erreur, callback
jamais appelé. La suite n'y voit qu'un WARNING (`ExpectRedirectUriHasBeenCalled`,
OIDCC-3.1.2.1) et conclut le module en succès avec avertissement.

**Corrigé** : `authorize_post` mémorise le corps form traité
(`request.state.form_query`), que `_authorize_url_from_base` utilise pour
reconstruire `next` **et** le hash de réauthentification — le retour après
connexion rejoue les mêmes paramètres. Le rejeu joue désormais le POST sur
session vierge, à l'identique de la suite ; la couverture en gate est dans
`tests/test_authorization.py::test_require_login_post_*`.

Rejeu PR 2 (local) : **33 passed, 5 skipped** (les 5 skips fidèles ci-dessus),
38 modules couverts en ≈ 1 min 45.

## Matrice module → test (PR 3 — issue #71)

Plans `oidcc-implicit-certification-test-plan` (`OIDCCImplicitTestPlan`) et
`oidcc-hybrid-certification-test-plan` (`OIDCCHybridTestPlan`) : **37 classes
de modules** dans l'union des deux plans (les 31 de l'Implicit sont incluses
dans les 37 du Hybrid — l'issue #71 parlait de 39, le décompte réel extrait des
deux `testModulesWithVariants()` est 37), pour **162 exécutions** dans la
suite (58 Implicit : 27 modules × 2 `response_type` + 4 ; 102 Hybrid :
`code id_token` 36, `code token` 33, `code id_token token` 33).

Le rejeu local réduit à 135 tests (49 Implicit + 86 Hybrid) en regroupant les
variantes dont l'observable ne change pas : les nodeids ci-dessous sont réels.
Blocs de conditions hérités identiques à la PR 2 (`[BASE]`, `[RC]`, `[UI]`,
`[CR]`, `[SAT]`, `[GEN-ERR]`).

### Plan Implicit — `test_plan_implicit.py` (31 modules)

| Module | Variante(s) plan | Nodeid pytest | Assertion |
| --- | --- | --- | --- |
| `oidcc-server` | `id_token`, `id_token token` | `test_implicit_happy_flow[rt-*]` | `checks.expect_implicit_callback` + `checks.validate_id_token` + `checks.check_at_hash` (avec `token`) |
| `oidcc-idtoken-signature` | idem | `test_implicit_happy_flow[rt-*]` | `checks.expect_id_token_signature` (RS256 + `kid`) |
| `oidcc-ensure-request-without-nonce-fails` | idem (`@VariantNotApplicable` code/code token) | `test_implicit_without_nonce_is_rejected[rt-*]` | `checks.expect_authorization_error` (`invalid_request` en fragment) |
| `oidcc-display-page`, `-popup`, `oidcc-login-hint`, `oidcc-ui-locales`, `oidcc-claims-locales`, `oidcc-ensure-request-with-unknown-parameter-succeeds`, `oidcc-ensure-request-with-acr-values-succeeds`, `oidcc-claims-essential` | les 2 | `test_implicit_authorize_parameter_is_accepted[rt-*][<alias>]` | `checks.expect_implicit_callback` + `checks.validate_id_token` ; `checks.check_acr_claim` (fragment) ; `claims` → member `id_token` pour `rt-id_token` (`EnsureIdTokenContainsName`), member `userinfo` sinon (`EnsureUserInfoContainsName` + `EnsureIdTokenDoesNotContainName`) (#80) |
| `oidcc-scope-profile`/`-email`/`-address`/`-phone`/`-all` | les 2 | `test_implicit_scope_claims_returned[rt-*][<alias>]` | userinfo (`[RC]`) avec `token` ; pour `id_token` seul, `VerifyScopesReturnedInAuthorizationEndpointIdToken` **(WARNING)** de la suite → assertion `checks.check_scope_claims_in_id_token` (#80) |
| `oidcc-userinfo-get`/`-post-header`/`-post-body` | `id_token token` uniquement (le plan exclut `id_token`) | `test_implicit_userinfo_endpoint_method[<alias>]` | `checks.check_userinfo_response` (post_body : token en corps, #83) |
| `oidcc-prompt-none-logged-in`, `oidcc-id-token-hint`, `oidcc-max-age-10000` | les 2 | `test_implicit_second_authorization[rt-*][<module>]` | `checks.check_second_id_token_consistent` (`[SAT]`) |
| `oidcc-prompt-none-not-logged-in` | les 2 | `test_implicit_prompt_none_without_session[rt-*]` | `checks.expect_authorization_error` (`login_required` en fragment) |
| `oidcc-ensure-registered-redirect-uri` | les 2 | `test_implicit_registered_redirect_uri_is_rejected[rt-*]` | `checks.expect_redirect_uri_error_page` |
| `oidcc-prompt-login`, `oidcc-max-age-1` | les 2 | `test_implicit_second_login_reprompts[rt-*][<module>]` | `checks.expect_second_login_page` + `checks.check_second_auth_time_is_later` |
| `oidcc-alternate-happy-flow` | les 2 | `test_implicit_alternate_happy_flow[rt-*]` | userinfo + `checks.check_scope_claims_returned` (`email`) avec `token` ; pour `id_token` seul, `email`/`email_verified` **présents** dans l'id_token (`checks.check_scope_claims_in_id_token`) (#80) |
| `oidcc-response-type-missing` | `id_token token` | `test_plan_basic.py::test_response_type_missing_shows_error_page` | identique sans `response_type` (page 400) |
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | les 2 | `test_plan_basic.py::test_request_object_module_completes[rt-*][<kind>]` | rejeu réel (les 6 `ResponseType` couvrent les 2 implicites) : `checks.expect_implicit_callback` + `checks.validate_id_token` (#76) |

### Plan Hybrid — `test_plan_hybrid.py` (37 modules)

| Module | Variante(s) plan | Nodeid pytest | Assertion |
| --- | --- | --- | --- |
| `oidcc-server` | les 3 | `test_hybrid_happy_flow[rt-*]` | `checks.expect_hybrid_callback` + `checks.check_c_hash` + `checks.check_at_hash` (avec `token`) + `checks.validate_id_token` + userinfo |
| `oidcc-idtoken-signature` | les 3 | `test_hybrid_happy_flow[rt-*]` | `checks.expect_id_token_signature` |
| `oidcc-ensure-request-without-nonce-fails` | `code id_token`, `code id_token token` | `test_hybrid_without_nonce_is_rejected[rt-*]` | `checks.expect_authorization_error` (`invalid_request`) |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | `code token` | `test_hybrid_code_token_without_nonce_succeeds` | `checks.expect_hybrid_callback` sans `id_token` |
| 8 modules paramètres (ids PR 2) | les 3 | `test_hybrid_authorize_parameter_is_accepted[rt-*][<alias>]` | `checks.expect_hybrid_callback` + `checks.validate_id_token` ; `checks.check_acr_claim` sur l'id_token du fragment **et** celui du token endpoint (2 WARNING pour `code id_token token`) ; `claims` → member `userinfo` : `name` du userinfo, absent des deux id_tokens (#80) |
| `oidcc-scope-*` (5) | les 3 | `test_hybrid_scope_claims_returned[rt-*][<alias>]` | `checks.check_userinfo_response` + `checks.check_scope_claims_returned` (`[RC]`) |
| `oidcc-userinfo-*` (3) | les 3 | `test_hybrid_userinfo_endpoint_method[rt-*][<alias>]` | `checks.check_userinfo_response` (post_body : token en corps × 3, #83) |
| `oidcc-prompt-none-logged-in`, `oidcc-id-token-hint`, `oidcc-max-age-10000` | les 3 | `test_hybrid_second_authorization[rt-*][<module>]` | `checks.check_second_id_token_consistent` |
| `oidcc-prompt-none-not-logged-in` | les 3 | `test_hybrid_prompt_none_without_session[rt-*]` | `checks.expect_authorization_error` |
| `oidcc-ensure-registered-redirect-uri` | les 3 | `test_hybrid_registered_redirect_uri_is_rejected[rt-*]` | `checks.expect_redirect_uri_error_page` |
| `oidcc-prompt-login`, `oidcc-max-age-1` | les 3 | `test_hybrid_second_login_reprompts[rt-*][<module>]` | `checks.expect_second_login_page` + `checks.check_second_auth_time_is_later` |
| `oidcc-alternate-happy-flow` | `code id_token` seulement | `test_hybrid_alternate_happy_flow` | userinfo + id_token sans `email` |
| `oidcc-codereuse` | les 3 | `test_hybrid_authorization_code_cannot_be_reused[rt-*]` | `checks.expect_invalid_grant` (`[CR]`) + `checks.expect_access_token_refused` (#85) |
| `oidcc-codereuse-30seconds` | les 3 → **1 portée** | `test_hybrid_authorization_code_reuse_after_30_seconds` | `checks.expect_invalid_grant` + `checks.expect_access_token_refused` + refresh `invalid_grant` — les 2 autres instances (`code token`, `code id_token token`) ont exactement les mêmes checks (`WaitFor30Seconds` + `[CR]`) : non portées, observables identiques |
| `oidcc-server-client-secret-post` | les 3 | `test_hybrid_client_secret_post_authentication[rt-*]` | `_exchange` en `client_secret_post` + `id_token` présent |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | `code id_token` seulement | `test_hybrid_request_with_valid_pkce_succeeds` | `checks.validate_id_token` après échange PKCE |
| `oidcc-refresh-token` | les 3 → **1 portée** | `test_hybrid_refresh_token_grant_and_client_binding` | `checks.check_refreshed_id_token_claims` + `checks.expect_invalid_grant` croisé — les 2 autres instances diffèrent seulement par le `response_type` du premier flux (mêmes `[RT-seq]`/`[RT-err-seq]`) : non portées |
| (qualité du code, sous-check de `oidcc-server`) | `code id_token` | `test_hybrid_authorization_code_quality` | `checks.check_authorization_code_quality` |
| `oidcc-response-type-missing` | `code id_token` (une seule fois) | `test_plan_basic.py::test_response_type_missing_shows_error_page` | identique sans `response_type` |
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | les 3 | `test_plan_basic.py::test_request_object_module_completes[rt-*][<kind>]` | rejeu réel (les 6 `ResponseType` couvrent les 3 hybrides) : `checks.expect_hybrid_callback` + échange du code + `checks.validate_id_token` (#76) |

Rejeu PR 3 (local) : **164 passed, 9 skipped** au total
(38 Basic + 49 Implicit + 86 Hybrid, dont 4 skips `userinfo-post-body` et
5 skips `none`) en ≈ 6 min 45.

## Matrice module → test (issue #109 — FAPI-CIBA-ID1)

Plan `fapi-ciba-ciba-certification-test-plan` : **66 modules publiés**, dont
**34 applicables** à notre variante (`private_key_jwt` + `poll` +
`plain_fapi`). Exclus : 21 modules ConnectID (identité sociale hors périmètre),
5 ping (hors-variante), 2 modules Brésil (`*br*`), 4 modules mTLS/hors-variante
(`@VariantNotApplicable` / `@VariantSetup`). Les 34 tests de
`test_plan_fapi_ciba.py` correspondent 1:1 aux modules applicables.

Lectures Java dans le clone local (`release-v5.2.4`) : plans
`FAPI.java` / `FAPI-CIBA-ID1.java`, classes sous
`oidf/conformance/.../fapi/ciba/` (bases `AbstractFAPICIBAID1*`, modules
concrets, `FAPICIBAID1DiscoveryEndpointVerification`,
`AbstractFAPIDiscoveryEndpointVerification`).

| Module de la suite | Check Java lu dans le clone | Test Python | Assertion |
| --- | --- | --- | --- |
| `fapi-ciba-id1-discovery` | `FAPICIBAID1DiscoveryEndpointVerification` + `AbstractFAPIDiscoveryEndpointVerification` (issuer/URLs/schema, PS256, private_key_jwt, CIBA : `backchannel_authentication_endpoint`, signing algs ∩ {PS256,ES256}, `backchannel_token_delivery_modes_supported` ⊇ poll, grant ciba, scopes) | `test_ciba_discovery_endpoint_verification` | `checks.check_fapi_ciba_discovery` — écarts documentés non assertés : `tls_client_certificate_bound_access_tokens` et `token_endpoint_auth_signing_alg_values_supported` absents (#110) |
| `fapi-ciba-id1` | `AbstractFAPICIBAID1` (ack → poll pending/slow_down → approve → poll → ressource) + `FAPICIBAID1` (2 clients, `requested_expiry=300` via `AddRequestedExp300SToAuthorizationEndpointRequest`, en-tête `typ` « OautH-auThZ-REQ+jWt » via `SignRequestObjectIncludeMediaType`, réutilisation d'auth req id → `invalid_grant`) | `test_ciba_happy_flow_two_clients` | `checks.check_ciba_id_token_header` (PS256 + kid) + claims id_token + écho `/protected-resource` + 400 `invalid_grant` à la réutilisation ; jetons non contraints par certificat TLS → cross-check clés client1 + jeton client2 écarté (#110) |
| `fapi-ciba-id1-user-rejects` | `FAPICIBAID1UserRejectsAuthentication` (`request_action=deny`) | `test_ciba_user_rejects_authentication` | `checks.check_backchannel_error` : 403 `access_denied` (`CheckBackchannelAuthenticationEndpointErrorHttpStatus`) |
| `fapi-ciba-id1-multiple-call` | `FAPICIBAID1MultipleCallToTokenEndpoint` (20 polls max) | `test_ciba_multiple_calls_to_token_endpoint` | 19 × 400 `slow_down`/`pending` puis 200 |
| `fapi-ciba-id1-auth-req-id-expired` | `FAPICIBAID1AuthReqIdExpired` + `AddRequestedExp10s` + `SleepUntilAuthReqExpires` | `test_ciba_auth_req_id_expired` | 400 `expired_token` (sleep 11 s réel) |
| `fapi-ciba-id1-binding-message` | `FAPICIBAID1EnsureBindingMessageSucceeds` + `AddBindingMessage…` (« 1234 ») | `test_ciba_binding_message_succeeds` | flux complet accepté |
| `fapi-ciba-id1-other-scope-order` | `…ReverseScopeOrderInAuthorizationEndpointRequest` | `test_ciba_other_scope_order_succeeds` | flux complet accepté |
| `fapi-ciba-id1-requested-expiry-as-string` | `…AddRequestedExp30sAsString` (`requested_expiry="30"`) | `test_ciba_requested_expiry_as_string_succeeds` | `ack_expires_in=30` + flux complet |
| `fapi-ciba-id1-potentially-bad-binding` | `…AddPotentiallyBadBindingMessage` (binding ~456 car. > limite OP) | `test_ciba_potentially_bad_binding_message` | 400 `invalid_binding_message` **ou** flux complet accepté (bornes OP : `MAX_BINDING_MESSAGE_LENGTH=512`) |
| 16 modules `fapi-ciba-id1-*` négatifs (suppression/détournement de claims JAR) | `AbstractFAPICIBAID1EnsureSendingInvalidBackchannelAuthorizationRequest` + mutations (`Remove*`, `AddBadAud`, `AddExpiredExp`, `AddExpValueIs70Minutes`, `AddNbf*`, `InvalidateRequestObjectSignature`, `SerializeRequestObjectWithNullAlgorithm`, `ChangeClientJwksAlgToRS256`, signature par autre clé) → tous `invalid_request` (CIBA-13) | `test_ciba_request_object_negative[<case>]` × 16 | 400 `invalid_request` (`CheckBackchannelAuthenticationEndpointErrorHttpStatus`) ; durée de vie JAR bornée à 3600 s (`exp=nbf+300` accepté, ±70 min rejeté) |
| `fapi-ciba-id1-multiple-hints` | `AddMultipleHintsToAuthorizationEndpointRequest` (`join@example.com` + `xxxx…`) | `test_ciba_multiple_hints_fails` | 400 `invalid_request` (OP exige hint unique) |
| `fapi-ciba-id1-wrong-auth-req-id` | `FAPICIBAID1EnsureWrongAuthenticationRequestId…` (client2) | `test_ciba_wrong_auth_req_id_fails` | 400 `invalid_grant` |
| `…without-assertion-in-backchannel…` | `FAPICIBAID1EnsureWithoutClientAssertionInBackchannel…` | `test_ciba_without_client_assertion_fails[backchannel]` | 400/401/403 générique (`invalid_client`) |
| `…without-assertion-in-token…` | idem côté token endpoint | `test_ciba_without_client_assertion_fails[token]` | 400/401 `invalid_client`/`invalid_request` |
| `…backchannel…RS256Fails` | `ChangeClientJwksAlgToRS256` (modifie le JWKS **local de la suite** ; `AbstractSignJWT` signe avec l'`alg` du JWK local → assertion RS256) | `test_ciba_client_assertion_rs256_fails[backchannel]` | 400/401/403 — l'OP refuse (JWK enregistré `alg=PS256` ≠ en-tête `RS256` → `resolve_signing_key` → `invalid_client`) |
| `…token…RS256Fails` | idem côté token endpoint | `test_ciba_client_assertion_rs256_fails[token]` | 400/401 `invalid_client` |
| `…iss-aud` | `UpdateClientAuthenticationAssertionClaimsWithISSAud` (aud = issuer seul) | `test_ciba_client_assertion_iss_aud_accepted` | pending/slow_down **ou** `invalid_client` acceptable (le scénario accepte les deux) |
| `…without-request-object` | `FAPICIBAID1EnsureBackchannelAuthorizationRequestWithoutRequestFails` (client enregistré avec `backchannel_authentication_request_signing_alg` mais sans `request`) | `test_ciba_without_request_object_fails` | 400 `invalid_request` (« request object signé requis ») |
| `fapi-ciba-id1-refresh-token` | `FAPICIBAID1RefreshToken` (`RefreshTokenRequestSteps` / `ExpectingErrorSteps`) | `test_ciba_refresh_token_flow` | refresh + id_token cohérent + `invalid_grant` croisé client2 (sleep 1.1 s : l'OP autorise `iat` identique à la seconde près dans #76) |

Notes de rejeu :

- `PerformStandardIdTokenChecks` saute `acr` quand `acr_values_supported` est
  absent du discovery (notre OP ne le publie pas) → tests avec
  `requested_acr=""` sans assertion `acr` — gap documenté (#111).
- La suite s'enregistre avec `tls_client_certificate_bound_access_tokens=true`
  et `response_types=[]` : nos parsers ignorent les champs inconnus (DCR) ;
  le token endpoint ne contraint pas le jeton au certificat TLS (gap G6 → #110).
- Rejeu local (222 scénarios au total) : **222 passed, 1059 deselected**
  en ≈ 19 min 26.

## Matrice module → test (issue #110 — FAPI1 Advanced Final)

Plan `fapi1-advanced-final-test-plan` (`fapi1advancedfinal/FAPI1AdvancedFinalTestPlan.java`) :
**68 modules publiés**, dont **63 applicables** à notre profil. Exclus :

- #33 `fapi1-advanced-final-ensure-mtls-holder-of-key-required` (profil mTLS
  `@VariantNotApplicable` pour `ClientAuthType=private_key_jwt`) ;
- #45 `…ensure-server-handles-non-matching-intent-id` et #46
  `…test-essential-acr-sca-claim` (`@VariantNotApplicable` pour
  `FAPI1FinalOPProfile=plain_fapi` : écosystèmes OBUK/CDR hors périmètre) ;
- #47 `…brazil-ensure-encryption-required` et #48
  `…brazil-ensure-bad-payment-signature-fails` (profils Brazil/KSA).

Profil retenu (`@VariantParameters`) : `ClientAuthType=private_key_jwt`,
`FAPI1FinalOPProfile=plain_fapi`, `FAPIResponseMode=plain_response`,
`FAPIAuthRequestMethod ∈ {by_value, pushed}`. Les 63 modules donnent
**106 exécutions** (44 `by_value` + 62 `pushed`) : 43 modules lancés dans les
deux variantes, #6 `…ensure-valid-pkce-succeeds` `by_value` seul (NA `pushed`),
19 modules PAR/PKCE `pushed` seuls (NA `by_value` : #49-53 et #55-68).

Lectures Java dans le clone local (`release-v5.2.4`) : mécanique commune
`AbstractFAPI1AdvancedFinalServerTestModule` (JAR obligatoire, claims
`iat`/`nbf`/`exp`/`aud`/`iss` ajoutés puis signés, `by_value` = `request` +
doublons `response_type`/`client_id`/`scope`/`redirect_uri` en query,
`pushed` = `/par` + `request_uri` + PKCE, callback hybride `code id_token`
avec `state`/`s_hash`/`c_hash`, échange + ressource FAPI), modules concrets
cités ci-dessous. Fiches détaillées : `fapi-specs/agent-{a,b,c,d}.md`
(clone lecture seule, hors dépôt).

### Flux nominal, paramètres et id_token (20 modules — 39 exécutions)

| Module de la suite | Nodeid pytest | Assertion |
| --- | --- | --- |
| `fapi1-advanced-final-discovery-end-point-verification` | `test_fapi1_discovery_declares_jar_par_and_pkce[method]` | discovery FAPI1 : algs JAR ∩ {PS256, ES256}, endpoint PAR + `require_pushed_authorization_requests` (variante `pushed`), `code_challenge_methods_supported=S256` |
| `fapi1-advanced-final` | `test_fapi1_advanced_final_happy_flow[method]` | flux complet base : callback hybride PS256 + `kid`, `state`/`nonce`/`s_hash`/`c_hash`, échange (PKCE sous `pushed`) puis ressource 200/201 + `FAPI-Interaction-Id` |
| `…user-rejects-authentication` | `test_fapi1_user_rejects_authentication[method]` | 2ᵉ client avec `requested_state_length=128` ; déni de connexion → erreur sans code |
| `…ensure-valid-pkce-succeeds` | `test_fapi1_valid_pkce_succeeds` (`by_value`) | PKCE hors PAR accepté (NA `pushed`) |
| `…ensure-request-object-with-multiple-aud-succeeds` | `test_fapi1_multiple_aud_succeeds[method]` | `aud` tableau accepté (RFC 7519 §4.1.3) |
| `…ensure-authorization-request-without-state-success` | `test_fapi1_without_state_success[method]` | module SUCCESS : aucun `state` ni en query ni dans le JAR, flux complet |
| `…ensure-other-scope-order-succeeds` | `test_fapi1_other_scope_order_succeeds[method]` | ordre des scopes inversé accepté (RFC 6749 §3.3) |
| `…access-token-type-header-case-sensitivity` | `test_fapi1_access_token_type_header_case_sensitivity[method]` | ressource avec en-tête `Bearer` majuscule/minuscule accepté |
| `…ensure-response-mode-query` | `test_fapi1_response_mode_query[method]` | `response_mode=query` sur `code id_token` → rejet admis (page d'erreur, `400 invalid_request` au `/par` ou callback `invalid_request`) ; jamais de `code` en query (OIDCC-3.3.2.5, OAuth2 RT-5) |
| `…ensure-different-nonce-inside-and-outside-request-object` | `test_fapi1_different_nonce_inside_and_outside[method]` | `nonce` différant hors/dedans le JAR : la valeur du JAR prime |
| `…ensure-registered-redirect-uri` | `test_fapi1_registered_redirect_uri_rejected[method]` | `redirect_uri` altéré (suffixe + aléatoire) → page d'erreur ou `invalid_request` (OIDCC-3.1.2.1) |
| `…ensure-request-object-with-long-nonce` | `test_fapi1_long_nonce_accepted[method]` | nonce 384 caractères accepté (FAPI gitlab #359) |
| `…ensure-request-object-with-64-char-nonce-success` | `test_fapi1_64_char_nonce_success[method]` | nonce 64 caractères écho dans l'id_token |
| `…ensure-request-object-with-long-state` | `test_fapi1_long_state_accepted[method]` | state 1000 caractères accepté (FAPI PR #483) |
| `…ensure-matching-key-in-authorization-request` | `test_fapi1_matching_key_rejected[method]` | JAR signé par la clé du client 2 alors que `iss`/`client_id` = client 1 → rejet (`invalid_request_object`) |
| `…ensure-authorization-request-without-request-object-fails` | `test_fapi1_without_request_object_fails[method]` | paramètres plats sans `request` → rejet (JAR obligatoire FAPI1-ADV-5.2.3) |
| `…ensure-redirect-uri-in-authorization-request` | `test_fapi1_redirect_uri_missing[method]` | `redirect_uri` retirée de la demande → rejet |
| `…attempt-reuse-authorisation-code-after-one-second` | `test_fapi1_attempt_reuse_code_after_one_second[method]` | 2ᵉ échange après 1 s → `invalid_grant` + jetons du 1ᵉr échange révoqués |
| `…ensure-client-assertion-with-iss-aud-succeeds` | `test_fapi1_client_assertion_iss_aud_succeeds[method]` | assertion `iss == sub == client_id` acceptée |
| `…refresh-token` | `test_fapi1_refresh_token[method]` | refresh + id_token cohérent (`iat` diffère) puis `invalid_grant` croisé client 2 |

### PAR et PKCE (20 modules — 21 exécutions)

| Module de la suite | Nodeid pytest | Assertion |
| --- | --- | --- |
| `…par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `test_fapi1_par_reused_request_uri_succeeds` | `request_uri` réutilisée **avant** la fin de l'authentification acceptée (PAR-2.2) |
| `…par-test-pushed-authorization-url-as-audience-for-client-JWT-assertion` | `test_fapi1_par_endpoint_as_assertion_audience` | `aud` = endpoint `/par` acceptée (PAR-2) |
| `…par-token-endpoint-url-as-audience-for-client-JWT-assertion` | `test_fapi1_par_token_endpoint_as_assertion_audience` | `aud` = endpoint `/token` acceptée (RFC 7523 §3) |
| `…test-array-as-audience-for-client-JWT-assertion` | `test_fapi1_array_as_assertion_audience[method]` | `aud` tableau (issuer + endpoint) accepté |
| `…par-without-duplicate-parameters` | `test_fapi1_par_without_duplicate_parameters` | redirect `request_uri` sans doublons en query accepté (PAR-4) |
| `…par-ensure-client-assertion-with-wrong-{aud,iss,sub}-fails` | `test_fapi1_par_client_assertion_wrong_{aud,iss,sub}_fails` | 400 (401 `invalid_client` admis) + `invalid_client` (RFC 7523 §3, PAR-2) |
| `…par-ensure-pkce-required` | `test_fapi1_par_pkce_required` | 400 `invalid_request` sans `code_challenge` (FAPI1-ADV-5.2.2-18) |
| `…par-plain-pkce-rejected` | `test_fapi1_par_plain_pkce_rejected` | 400 `invalid_request` pour `code_challenge_method=plain` (S256 exigé) |
| `…par-attempt-invalid-redirect_uri` | `test_fapi1_par_attempt_invalid_redirect_uri` | 400 `invalid_request` pour `redirect_uri` non enregistré (RFC 6749 §3.1.2.3) |
| `…par-pushed-authorization-url-as-audience-in-request-object` | `test_fapi1_par_url_as_audience_in_request_object` | `aud` = URL du `/par` dans le JAR → 400 `invalid_request_object` (JAR-6.2, PAR-2.3) |
| `…par-attempt-invalid-http-method` | `test_fapi1_par_attempt_invalid_http_method` | `PUT /par` → 4xx (PAR-2.3.3 impose POST) |
| `…incorrect-pkce-code-verifier-rejected` | `test_fapi1_incorrect_pkce_code_verifier_rejected` | 400 `invalid_grant` avec un `code_verifier` neuf (RFC 7636 §4.6) |
| `…ensure-pkce-code-verifier-required` | `test_fapi1_ensure_pkce_code_verifier_required` | 400 `invalid_grant` sans `code_verifier` à l'échange (FAPI1-ADV-5.2.2-18) |
| `…par-authorization-request-containing-request_uri-form-param` | `test_fapi1_par_request_uri_form_param_rejected` | `request_uri` dans le corps form du `/par` → 400 (PAR-2.1) |
| `…par-authorization-request-containing-request_uri` | `test_fapi1_par_request_uri_claim_in_request_object` | claim `request_uri` dans le JAR → rejet (PAR-2, JAR-6.2) |
| `…par-attempt-to-use-expired-request_uri` | `test_fapi1_par_attempt_expired_request_uri` | réutilisation après le TTL → `invalid_request_uri` (PAR-2.2.2, sleep 30 s réel) |
| `…par-attempt-reuse-request_uri` | `test_fapi1_par_attempt_reuse_request_uri` | consommation unique post-succès → `invalid_request_uri` (PAR-2.2.2) |
| `…par-attempt-to-use-request_uri-for-different-client` | `test_fapi1_par_request_uri_bound_to_client` | `request_uri` du client 1 présentée par le client 2 → erreur, jamais de code (PAR-2.2.1) |

### Assertion client au `/token` et `response_type` (6 modules — 12 exécutions)

| Module de la suite | Nodeid pytest | Assertion |
| --- | --- | --- |
| `…ensure-client-assertion-with-wrong-{iss,sub,aud}-fails` | `test_fapi1_client_assertion_wrong_{iss,sub,aud}_fails[method]` | 400 (401 `invalid_client` admis) + `invalid_client` (RFC 7523 §3, OIDCC-9) |
| `…ensure-client-assertion-with-no-sub-fails` | `test_fapi1_client_assertion_no_sub_fails[method]` | idem sans claim `sub` (OIDCC-9) |
| `…ensure-client-assertion-with-exp-is-5-minutes-in-past-fails` | `test_fapi1_client_assertion_exp_in_past_fails[method]` | idem avec `exp` périmé (RFC 7523 §3) |
| `…ensure-response-type-code-fails` | `test_fapi1_response_type_code_fails[method]` | `response_type=code` → rejet (FAPI1-ADV-5.2.2-2) |

### Request objects négatifs (13 modules — 26 exécutions)

| Modules de la suite | Nodeid pytest | Assertion |
| --- | --- | --- |
| `…ensure-request-object-without-{exp,nbf,scope,nonce,redirect-uri}-fails` | `test_fapi1_request_object_without_{exp,nbf,scope,nonce,redirect_uri}_fails[method]` | trifurcation : 400 `/par` (`invalid_request_object`, ou `invalid_request` ⊕ pour `scope`/`nonce`), callback en erreur (bifurcation `pushed`/`by_value` : `invalid_request_uri`/`access_denied` admis hors `by_value` sans `exp`/`nbf`) ou page d'erreur (JAR-6.2, FAPI1-ADV-5.2.2) |
| `…state-only-outside-request-object-not-used` | `test_fapi1_state_only_outside_request_object[method]` | module SUCCESS : `state` ajouté **après** signature → ignoré (aucun `state` ni `s_hash` au callback, FAPI1-ADV-5.2.2-10), puis token + ressource |
| `…ensure-expired-request-object-fails`, `…ensure-request-object-with-bad-aud-fails`, `…-with-exp-over-60-fails`, `…-with-nbf-over-60-fails` | `test_fapi1_expired_request_object_fails[method]`, `test_fapi1_request_object_bad_aud_fails[method]`, `test_fapi1_request_object_{exp,nbf}_over_60_fails[method]` | 400 `invalid_request_object` ; callback `invalid_request_object` strict (expired, by_value) ou `invalid_request_uri` strict (`pushed` pour `bad-aud`/`exp-60`/`nbf-60`) ; page d'erreur admise |
| `…request-object-signature-algorithm-is-not-none`, `…signed-request-object-with-RS256-fails`, `…request-object-with-invalid-signature-fails` | `test_fapi1_request_object_alg_none_fails[method]`, `test_fapi1_request_object_rs256_fails[method]`, `test_fapi1_request_object_invalid_signature_fails[method]` | `invalid_request_object` **strict** partout (FAPI1-ADV-8.6 : PS256/ES256 seuls ; signature corrompue octet par octet) |

### Token endpoint : liaison client (4 modules — 8 exécutions)

| Module de la suite | Nodeid pytest | Assertion |
| --- | --- | --- |
| `…ensure-client-id-in-token-endpoint` | `test_fapi1_client_id_in_token_endpoint[method]` | 400 (401 admis) + `error ∈ {invalid_client, invalid_grant}` — l'ordre entre authentification client et liaison du code n'est pas défini par les specs |
| `…ensure-authorization-code-is-bound-to-client` | `test_fapi1_authorization_code_bound_to_client[method]` | 400 + `invalid_grant` **strict** — fix OP (#110) : `_validate_code_exchange` comparait `auth_code.client_id` au client authentifié (RFC 6749 §4.1.3), au même titre que refresh/device/CIBA |
| `…ensure-client-assertion-in-token-endpoint` | `test_fapi1_client_assertion_missing_in_token_endpoint[method]` | form sans `client_assertion` (uniquement `client_id`) → 400/401 + `error ∈ {invalid_client, invalid_request}` (FAPI1-BASE-5.2.2-19) |
| `…ensure-signed-client-assertion-with-RS256-fails` | `test_fapi1_client_assertion_rs256_fails[method]` | assertion signée RS256 (clé enregistrée PS256) → 400/401 + `invalid_client` **strict** (FAPI1-ADV-8.6) |

### Notes de rejeu (issue #110)

- **Écarts OP G1-G6 levés** dans le working tree : JAR signé vérifié avec algs
  `PS256`/`ES256` + contrôles `exp`/`nbf`/`aud`/`iss` (`application/request_object.py`,
  `invalid_request_object`) ; authentification `client_assertion` au `/par`
  (`application/par.py`) ; PKCE obligatoire pour les clients FAPI1 + `S256`
  seul au `/token` ; `iss == sub` + contrôle de liste d'algos des assertions
  client (`infrastructure/client_assertions.py`) ; discovery
  `request_object_signing_alg_values_supported`, `code_challenge_methods_supported`,
  `token_endpoint_auth_signing_alg_values_supported`,
  `tls_client_certificate_bound_access_tokens` ; mode FAPI sur `/authorize`
  (JAR obligatoire, `response_type=code` rejeté, `response_mode=query` refusé
  en hybride sans code en query) ; liaison du code d'autorisation au client
  (`_validate_code_exchange`).
- **Bornes OP assumées** (issues admises par les tests) : 401 admis pour
  `invalid_client` au `/par` et au `/token`, `invalid_request` ⊕
  `invalid_request_object` sur certains JAR incomplets, TTL PAR borné à 30 s
  dans le harness (`conftest.par_ttl_seconds`), réutilisation de `request_uri`
  ≈ consommation unique post-succès.
- Rejeu local : **106 passed** (44 `by_value` + 62 `pushed`) en ≈ 8 min 30.

## Observeurs du harness

Le harness (`harness.py`) reproduit le rôle du navigateur pilote des plans
(`browser` de la suite) : il enchaîne `/authorize` → `/login` → `/consent` →
callback en **comptant les pages de connexion présentées** — c'est
l'équivalent du match d'URL `{OPURL}/login*` de `ExpectSecondLoginPage`. Il
capture les paramètres du callback en query **et** en fragment, échange le
code (PKCE) et décode les claims de l'id_token pour lire `auth_time`.

## État de référence

**État courant** (run `36753888937`, main @ `d571be8`, `release-v5.2.4`) :
**177 passed / 21 review / 0 failed / 0 skipped / 0 warning** sur 198
modules. Les 19 modules qui sautaient sur `alg=none` rejouent et passent
(#76) ; les 21 `review` correspondent aux 4 modules qui exigent une capture
d'écran (6 occurrences chacun) : depuis #90, le run téléverse la page
réellement servie par l'OP (`certification/capture_screenshots.py`, voir
« Captures d'écran des modules de relecture » dans
`certification/README.md`), le PNG de secours restant le repli.

Run d'origine (main, avant #68) : **130 passed / 18 failed / 29 warning /
2 review / 19 skipped**. Les 18 échecs se répartissent en
3 × 6 variantes des modules ci-dessus (8 redirect-uri + 6 max-age-1 + 6
prompt-login) — #68.

Vérification du « rouge » (PR 1) : avec les 3 modules au comportement `main`
(stash de la branche), les 3 tests échouent sur les assertions ci-dessus
(302 vers l'URI inconnue, code émis sans seconde connexion) ; avec le fix,
ils passent.

## Suites (issues #69 → #72)

- **PR 1 (#69)** : 3 modules Basic défaillants — **livrée** (matrice PR 1
  ci-dessus, fixs de l'OP dans #68).
- **PR 2 (#70)** : 38 modules Basic — **livrée** : matrice complète ci-dessus,
  `test_plan_basic.py` + `checks.py` (signature `id_token`, `userinfo`,
  `refresh`, `invalid_grant`).
- **PR 3 (#71)** : plans Implicit/Hybrid — **livrée** : matrices ci-dessus,
  `test_plan_implicit.py` (49 tests) + `test_plan_hybrid.py` (86 tests),
  fragment, `at_hash`/`c_hash`, nonce obligatoire.
- **PR 3 bis** : modules de compatibilité de navigateur (Login/Consent/callback,
  voir les mêmes plans).
- **PR 4 (#72)** : **livrée** : smoke contre un vrai serveur uvicorn
  (`samples/conformance-smoke/smoke_test.py` : serveur sous-processus aux seeds
  du harness, `PURIDENTITYSERVER_CONFORMANCE_URL` → harness httpx, rejeu des 173
  scénarios — **164 passed, 9 skipped**) + documentation du rejeu
  (`certification/README.md` « Rejeu local sans la suite », `AGENTS.md`,
  `docs/roadmap-certification.md`).
- **Issue #80 (18 warnings « claims OIDC »)** : familles `acr` (paramètre
  `acr_values`, OIDCC-3.1.2.1), paramètre `claims` §5.5 (members
  `userinfo`/`id_token`) et claims des scopes dans l'id_token de
  `response_type=id_token` (OIDCC-5.4) — assertions renforcées :
  `checks.check_acr_claim`, `checks.check_scope_claims_in_id_token`,
  `checks.check_scope_claims_absent_from_id_token`, plus les asserts
  `name` des modules `claims-essential` ; `claims_parameter_supported=true`
  au discovery. Rejeu local **164 passed, 9 skipped** (≈ 5 min 40).
- **Issue #83 (warning « access_token en corps POST `/userinfo` »)** :
  `POST /userinfo` accepte le paramètre `access_token` du corps form
  (RFC 6750 §2.1.2) en plus de l'en-tête `Authorization` (priorité en-tête) ;
  les 5 skips `oidcc-userinfo-post-body` (basic 1, implicit 1, hybride 3)
  redeviennent des rejeux réels → **169 passed, 4 skipped**.
- **Issue #85 (4 warnings `oidcc-codereuse-30seconds`)** : réutilisation d'un
  code d'autorisation → `invalid_grant` **et** révocation des jetons du
  premier échange (RFC 6749 §4.1.2 « SHOULD revoke »). `AuthorizationCode`
  porte les empreintes SHA-256 de l'access/refresh token émis (colonnes
  `access_token_hash`, `access_token_expires_at`, `refresh_token_hash` sur
  `authorization_codes`) ; à la détection du code consommé, `TokenUseCase`
  pose l'access token au denylist (`RevokedToken`) et consomme le refresh
  token dans le store de rotation. Assertions renforcées :
  `checks.expect_access_token_refused` (401 `invalid_token` sur `/userinfo`)
  et `invalid_grant` sur le refresh — rejeu local **169 passed, 4 skipped**.
- **Issue #76 (19 skips « `alg=none` »)** : `id_token` émis sans signature
  (`infrastructure/tokens.py` signe en `none`, `JWTAlgorithm.NONE` accepté par
  `domain/jwks.py`, `at_hash`/`c_hash` vides) et request objects RFC 9101
  (`application/request_object.py` : résolution `request`/`request_uri`,
  `infrastructure/request_object.py` : fetch stdlib sur `Content-Type:
  application/jwt`, cibles locales autorisées seulement si l'OP est en
  loopback). Discovery : `request_object_signing_alg_values_supported=["none"]`,
  `request_parameter_supported`/`request_uri_parameter_supported=true`. Les 4
  skips restants redeviennent des rejeux réels (`test_id_token_alg_none_is_issued`
  + `test_request_object_module_completes` × 18) → **188 passed, 0 skipped**
  en ≈ 14 min 30.
- **Issue #109 (rejeu FAPI-CIBA-ID1)** : plan `fapi-ciba-ciba-certification-
  test-plan`, 34 modules applicables sur 66 — matrice module → test ci-dessus,
  `test_plan_fapi_ciba.py` (34 tests) + `ciba_harness.py` (DCR éphémère, JAR
  RFC 9101, assertion `private_key_jwt`, `/bc-authorize` + `/token` poll,
  `/ciba/approve`, `/protected-resource`, refresh) + checks
  `check_ciba_id_token_header`, `check_backchannel_error`,
  `check_fapi_ciba_discovery`. Écarts OP FAPI1/FAPI2 isolés dans #110/#111 →
  rejeu local **222 passed, 0 skipped** en ≈ 19 min 26.
- **Issue #110 (FAPI1 Advanced Final)** : plan `fapi1-advanced-final-test-plan`,
  63 modules applicables sur 68 (exclus mTLS, OBUK/CDR, Brazil) — matrice
  module → test ci-dessus, `test_plan_fapi1.py` (106 exécutions) +
  `fapi_harness.py` (FAPI client1/client2, JAR PS256, `/par`, `private_key_jwt`,
  `switch` 2ᵉ client) ; écarts OP G1-G6 levés (JAR signé, assertion au `/par`,
  PKCE `S256`, algos d'assertion, discovery FAPI, mode FAPI `/authorize`,
  liaison code↔client) ; smoke étendu aux seeds FAPI1 → rejeu local
  **106 passed** (total conformance 328).

## DPoP (issue #49, RFC 9449) — matrice suite → plans

Relevé sur le clone local de la suite officielle (tag `release-v5.2.4`,
`$TEMP/opencode/conformance-suite`) :

| Plans contenant des checks DPoP | Modules | Dans nos playlists rejouées ? |
| --- | --- | --- |
| `fapi2spfinal` | preuves DPoP sur `/token` (RFC 9449 §5) | **Non** — playlist FAPI2, hors `oidcc-*` |
| `fapi2spid2` | preuve + `dpop_jkt` au `/authorize` (§10) | **Non** — playlist FAPI2 |
| `fapi2msg-signing` | preuves sur messages signés (PAR/request objects) | **Non** — playlist FAPI2 |
| `oidcc-*` (Basic/Implicit/Hybrid/Form Post/Session Mgmt) | **aucun** check DPoP | — |

Conséquence : aucun test `conformance` rejoué par `tests/conformance/`
(`-m conformance`, playlists Core) n'exerce DPoP — le rejeu local n'est donc
**pas impacté** par l'implémentation de #49. La couverture repose sur
`tests/test_dpop.py` (50 tests) + le smoke `samples/dpop-client/smoke_test.py`
(8 étapes de bout en bout). Points d'implémentation alignés sur la suite
(lecture des modules FAPI2) :

- **Mismatch `dpop_jkt`** : la suite accepte `invalid_request`,
  `invalid_grant` **ou** `invalid_dpop_proof` (HTTP 400, DPOP-10.1) →
  l'implémentation répond `invalid_grant` au `/token` (§10) et
  `invalid_dpop_proof` au `/par` (§10.1) ;
- **`iat`** : tolérance ±5 minutes (`DPOP_IAT_SKEW_SECONDS`, §11.1) ;
- **`ath`** : absent exigé au token/PAR (DPOP-4.3), requis au `/userinfo`
  (§7.1) ; **`jti`** anti-replay persistant (memory/SQL) ;
- **nonce** : la suite émet un `WWW-Authenticate: DPoP error="use_nonce"`
  (WARNING seulement) → pas d'émission de nonce côté serveur en v1 ;
- **Algorithmes** : FAPI2 publie `PS256, ES256, EdDSA, Ed25519` mais
  `JWTAlgorithm` n'a pas d'EdDSA → `dpop_signing_alg_values_supported` porte
  les 9 algos asymétriques RS/PS/ES et rejette `none`/HS*.

### Note — flows à jeton direct (implicit/hybrid) : jetons porteurs

Les `response_type` sans code (`token`, `id_token token`, hybrides) émettent
l'access token **directement au fragment d'`/authorize`** : aucune passe par
`/token` n'a donc lieu, DPoP ne peut pas lier ce jeton — il reste porteur
(`Bearer`). Seuls les codes d'autorisation (et les refresh tokens) sont liés,
via le paramètre `dpop_jkt` d'`/authorize`/`/par` ou la preuve présentée à
l'échange. Comportement documenté dans `samples/dpop-client/README.md`.
