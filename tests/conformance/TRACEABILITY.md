# Traçabilité des checks rejoués (PR 1/4 — #69, PR 2/4 — #70, PR 3/4 — #71, PR 4/4 — #72)

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
# ou smoke complet : serveur uvicorn + rejeu des 173 scénarios (PR 4)
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
| `oidcc-idtoken-unsigned` | `OIDCCIdTokenUnsigned.java` → `skipTestIfSigningAlgorithmNotSupported` (**skip** si `none` absent du discovery) | `test_id_token_alg_none_not_supported_skips` | `pytest.skip` fidèle (notre OP : RS256 seul) |
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | `OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.java` → `skipTestIfNoneUnsupported` (`none` absent de `request_object_signing_alg_values_supported`), idem pour `OIDCCUnsignedRequestObject…` (`CheckDiscEndpointRequestParameterSupported` **(WARNING)**) et `OIDCCEnsureRequestObjectWithRedirectUri.java` | `test_request_object_modules_skip_without_none_support[<alias>]` | `pytest.skip` fidèle (discovery : `request_parameter_supported=false`) |
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
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | les 2 | `test_plan_basic.py::test_request_object_modules_skip_without_none_support[<alias>]` | skip identique (`skipTestIfNoneUnsupported`, discovery inchangé) |

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
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | les 3 | `test_plan_basic.py::test_request_object_modules_skip_without_none_support[<alias>]` | skip identique (`skipTestIfNoneUnsupported`) |

Rejeu PR 3 (local) : **164 passed, 9 skipped** au total
(38 Basic + 49 Implicit + 86 Hybrid, dont 4 skips `userinfo-post-body` et
5 skips `none`) en ≈ 6 min 45.

## Observeurs du harness

Le harness (`harness.py`) reproduit le rôle du navigateur pilote des plans
(`browser` de la suite) : il enchaîne `/authorize` → `/login` → `/consent` →
callback en **comptant les pages de connexion présentées** — c'est
l'équivalent du match d'URL `{OPURL}/login*` de `ExpectSecondLoginPage`. Il
capture les paramètres du callback en query **et** en fragment, échange le
code (PKCE) et décode les claims de l'id_token pour lire `auth_time`.

## État de référence

Run de certification (main, `release-v5.2.4`) : **130 passed / 18 failed /
29 warning / 2 review / 19 skipped**. Les 18 échecs se répartissent en
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
