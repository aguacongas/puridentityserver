# Traçabilité des checks rejoués (PR 1/4 — #69, PR 2/4 — #70)

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
```

`--no-cov` est requis : le sous-ensemble ne couvre pas le seuil de
80 % du gate (94 % sur la suite complète). Pas de `-q` non plus : le résumé
`38 passed, 5 skipped, 737 deselected` (PR 2) est la preuve, dans les logs du
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
| `oidcc-ensure-request-with-acr-values-succeeds` | `OIDCCEnsureRequestWithAcrValuesSucceeds.java` → `OIDCCAddAcrValuesToAuthorizationEndpointRequest`, `ValidateIdTokenACRClaimAgainstAcrValuesRequest` **(WARNING si `acr` absent)**, [BASE] | idem |
| `oidcc-claims-essential` | `OIDCCClaimsEssential.java` → `AddUserInfoEssentialNameClaimToAuthorizationEndpointRequest`, `EnsureUserInfoContainsName` **(WARNING)**, `[RC]` | idem |

### Scopes (5 modules — test paramétré `test_scope_claims_returned_in_userinfo`)

| Module | Check Java lu dans le clone | Assertion |
| --- | --- | --- |
| `oidcc-scope-profile` / `-email` / `-address` / `-phone` / `-all` | `OIDCCScope*.java` → `SetScopeInClientConfigurationToOpenIdX` + `skipTestIfScopesNotSupported` (**skip** si le scope est absent du discovery), `[RC]` (`CallUserInfoEndpoint`, `EnsureHttpStatusCodeIs200`, `ValidateUserInfoStandardClaims`, `EnsureUserInfoContainsSub`, `VerifyScopesReturnedInUserInfoClaims` **(WARNING)**) | `checks.check_scope_claims_returned` (userinfo 200 + claims du scope) |

### Endpoint userinfo (3 modules — test paramétré `test_userinfo_endpoint_method`)

| Module | Check Java lu dans le clone | Assertion |
| --- | --- | --- |
| `oidcc-userinfo-get` | `OIDCCUserInfoGet.java` (classe vide) → `[UI]` | `checks.check_userinfo_response` (200 + `content-type` JSON + `sub`) |
| `oidcc-userinfo-post-header` | `OIDCCUserInfoPostHeader.java` → `SetResourceMethodToPost`, `[UI]` | idem (POST Bearer) |
| `oidcc-userinfo-post-body` | `OIDCCUserInfoPostBody.java` → `CallUserInfoEndpointWithBearerTokenInBody`, `UserInfoEndpointWithAccessTokenInBodyNotSupported` **(WARNING → skip)** | skip fidèle (401 sur notre OP, mode non exigé) |

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
| `oidcc-ensure-post-request-succeeds` | `OIDCCEnsurePostRequestSucceeds.java` → requête envoyée en **POST**, `ExpectRedirectUriHasBeenCalled` **(WARNING après 30 s sans callback)**, [BASE] | `test_post_authorization_request_succeeds` | `checks.expect_callback_success` — session établie au préalable (`harness.login()`) : sur session vierge l'OP renvoie vers `/login` avec un `next` sans la query string, ce que la suite n'a qu'en WARNING (voir note ci-dessous) |
| `oidcc-alternate-happy-flow` | `OIDCCAlternateHappyFlow.java` → `ReverseScopeOrderInAuthorizationEndpointRequest`, `BuildPlainRedirectToAuthorizationEndpointReorderedParams`, hérite `OIDCCScopeEmail` + `[RC]` | `test_alternate_happy_flow_with_reordered_scopes` | `checks.expect_callback_success` + `checks.check_scope_claims_returned` + id_token sans `email` |
| `oidcc-server` | `OIDCCServerTest.java` → `EnsureMinimumAuthorizationCodeLength`, `EnsureMinimumAuthorizationCodeEntropy`, `ExtractAtHash`/`ValidateAtHash`, `ExtractCHash`/`ValidateCHash`, [BASE] | `test_authorization_code_has_minimum_quality` | `checks.check_authorization_code_quality` (≥ 16 caractères) + `checks.validate_id_token` |
| `oidcc-server-client-secret-post` | `OIDCCServerTestClientSecretPost.java` → `AddFormBasedClientSecretToRequest` + configuration `client_secret_post`, [BASE] | `test_client_secret_post_authentication` | `checks.check_token_endpoint_success` (échange en `client_secret_post`) + `checks.validate_id_token` |
| `oidcc-idtoken-signature` | `OIDCCIdTokenSignature.java` → `EnsureIdTokenContainsKid`, `EnsureIdTokenSignatureIsRS256`, `PerformStandardIdTokenChecks` | `test_id_token_signature_is_rs256_with_kid` | `checks.expect_id_token_signature` (header `alg=RS256` + `kid`) |
| `oidcc-idtoken-unsigned` | `OIDCCIdTokenUnsigned.java` → `skipTestIfSigningAlgorithmNotSupported` (**skip** si `none` absent du discovery) | `test_id_token_alg_none_not_supported_skips` | `pytest.skip` fidèle (notre OP : RS256 seul) |
| `oidcc-request-uri-unsigned-…`, `oidcc-unsigned-request-object-…`, `oidcc-ensure-request-object-with-redirect-uri` | `OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported.java` → `skipTestIfNoneUnsupported` (`none` absent de `request_object_signing_alg_values_supported`), idem pour `OIDCCUnsignedRequestObject…` (`CheckDiscEndpointRequestParameterSupported` **(WARNING)**) et `OIDCCEnsureRequestObjectWithRedirectUri.java` | `test_request_object_modules_skip_without_none_support[<alias>]` | `pytest.skip` fidèle (discovery : `request_parameter_supported=false`) |
| `oidcc-codereuse` | `OIDCCAuthCodeReuse.java` → `[CR]` (`CheckErrorFromTokenEndpointResponseErrorInvalidGrant`), `ServerAllowedReusingAuthorizationCode` **(WARNING)** | `test_authorization_code_cannot_be_reused` | `checks.expect_invalid_grant` |
| `oidcc-codereuse-30seconds` | `OIDCCAuthCodeReuseAfter30Seconds.java` → `WaitFor30Seconds`, `CallProtectedResource` + `EnsureHttpStatusCodeIs4xx` **(WARNING)**, `[CR]` | `test_authorization_code_reuse_after_30_seconds` | `checks.expect_invalid_grant` |
| `oidcc-refresh-token` | `OIDCCRefreshToken.java` → séquence `RefreshTokenRequestSteps` (`WaitForOneSecond`, `EnsureAccessTokenValuesAreDifferent` **(INFO)**, `CompareIdTokenClaims` : `iss`/`sub`/`aud` égaux, `iat` différent) + `RefreshTokenRequestExpectingErrorSteps` chez le 2ᵉ client (`AbstractOIDCCMultipleClient`), skip si aucun refresh émis | `test_refresh_token_grant_and_client_binding` | `checks.check_token_endpoint_success` + `checks.check_refreshed_id_token_claims` + `checks.expect_invalid_grant` (jeton d'un autre client) |

### Note sur `oidcc-ensure-post-request-succeeds`

Sur session vierge, notre OP renvoie vers `/login?next=/authorize` **sans** la
query string (le POST porte ses paramètres dans le corps) : le retour après
connexion arrive sur `/authorize` sans paramètres → page d'erreur, callback
jamais appelé. La suite n'y voit qu'un WARNING (`ExpectRedirectUriHasBeenCalled`,
OIDCC-3.1.2.1) et conclut le module en succès avec avertissement ; le rejeu
préfère établir la session au préalable (`harness.login()`) pour vérifier que
l'OP accepte effectivement le POST.

Rejeu PR 2 (local) : **33 passed, 5 skipped** (les 5 skips fidèles ci-dessus),
38 modules couverts en ≈ 1 min 45.

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

## Suites (issues #70 → #72)

- **PR 2 (#70)** : 38 modules Basic — **livrée** : matrice complète ci-dessus,
  `test_plan_basic.py` + `checks.py` (signature `id_token`, `userinfo`,
  `refresh`, `invalid_grant`).


- **PR 3 (#71)** : modules Implicit/Hybrid (`certification/plans/implicit.json`,
  `hybrid.json`) — capture du fragment, `response_type` multiples.
- **PR 3 bis** : modules de compatibilité de navigateur (Login/Consent/callback,
  voir les mêmes plans).
- **PR 4 (#72)** : smoke du serveur réel (`samples/smoke_common.run_server`) +
  documentation du rejeu dans `AGENTS.md`.
