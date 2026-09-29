# Traçabilité des checks rejoués (PR 1/4 — issue #69)

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

`--no-cov` est requis : les 3 tests ne couvrent évidemment pas le seuil de
80 % du gate (94 % sur la suite complète). Pas de `-q` non plus : le résumé
`3 passed, 737 deselected` est la preuve, dans les logs du job comme en local,
que le rejeu a bien eu lieu.

## Matrice module → test (PR 1)

| Module de la suite | Check Java lu dans le clone | Test Python | Assertion |
| --- | --- | --- | --- |
| `oidcc-ensure-registered-redirect-uri` | `condition/client/CreateBadRedirectUriByAppending.java` (base + `/callback/` + aléatoire), `condition/common/ExpectRedirectUriErrorPage.java` (« Show redirect URI error page », OIDCC-3.1.2.1) | `test_redirect_reauth.py::test_ensure_registered_redirect_uri_displays_error_page` | `checks.expect_redirect_uri_error_page` |
| `oidcc-prompt-login` | `condition/client/WaitForOneSecond.java`, `condition/client/ExpectSecondLoginPage.java` (« server must ask the user to login for a second time », match `{OPURL}/login*`), `condition/client/CheckSecondIdTokenAuthTimeIsLaterIfPresent.java` (égalité ou antérieur = erreur) | `test_redirect_reauth.py::test_prompt_login_forces_second_authentication` | `checks.expect_second_login_page`, `checks.check_second_auth_time_is_later` |
| `oidcc-max-age-1` | `condition/client/WaitFor2Seconds.java`, `ExpectSecondLoginPage`, `condition/client/CheckIdTokenAuthTimeClaimPresentDueToMaxAge.java`, `CheckSecondIdTokenAuthTimeIsLaterIfPresent.java`, `CheckIdTokenAuthTimeIsRecentIfPresent.java` (< 5 min de skew) | `test_redirect_reauth.py::test_max_age_1_reprompts_authentication` | les 4 checks associés |

Les 3 tests sont marqués `conformance` (marker déclaré dans `pyproject.toml`).

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

- **PR 2 (#70)** : 38 modules Basic — matrice détaillée dans
  `certification/plans/basic.json` ; ajoutera `checks.py` (signatures
  `id_token`, `userinfo`, registration dynamique, …).
- **PR 3 (#71)** : modules Implicit/Hybrid (`certification/plans/implicit.json`,
  `hybrid.json`) — capture du fragment, `response_type` multiples.
- **PR 3 bis** : modules de compatibilité de navigateur (Login/Consent/callback,
  voir les mêmes plans).
- **PR 4 (#72)** : smoke du serveur réel (`samples/smoke_common.run_server`) +
  documentation du rejeu dans `AGENTS.md`.
