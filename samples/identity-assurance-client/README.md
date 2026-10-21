# Test manuel : identité assurance (OpenID Identity Assurance 1.0)

Script de démonstration du claim **`verified_claims`** de la spec « OpenID
Identity Assurance Schema Definition 1.0 » (version finale) dans
PurIdentityServer. Il lance un serveur en sous-processus avec une configuration
**spécifique à ce test** (générée par `smoke_common.py` : port `8125`, un
client public, un profil utilisateur porteur de `verified_claims`) puis joue
le parcours.

Le scénario vérifie :

1. le discovery publie la metadata eKYC (`trust_frameworks_supported`,
   `claims_in_verified_claims_supported`, `evidence_supported`,
   `documents_supported`, `documents_check_methods_supported`) ;
2. une demande `claims` portant `verified_claims` dans le member `id_token`
   produit un `id_token` conforme (membre racine `verified_claims`,
   `verification.trust_framework` renseigné, claims filtrés par la demande) ;
3. la même demande dans le member `userinfo` produit un `/userinfo` porteur du
   membre, et **rien** ne fuit dans l'autre localisation ;
4. sans demande, le membre est absent de l'`id_token` comme du `/userinfo` ;
5. un claim demandé avec une `value` non satisfaite est **omis** (le membre
   `verified_claims` reste présent, avec un élément `claims` vide) ;
6. un claim demandé mais inconnu de l'OP est omis, sans erreur.

## Lancement

```bash
uv run python samples/identity-assurance-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/6] metadata eKYC publiee dans le discovery
  [2/6] id_token : verified_claims rendu (trust_framework + claims)
  [3/6] userinfo : verified_claims rendu dans la seule localisation
  [4/6] sans demande : aucun verified_claims rendu
  [5/6] valeur non satisfaite : le claim est omis (IA-5.7.4)
  [6/6] claim inconnu : omis sans erreur

=== SCENARIO OK ===
```

## Comment ça marche ?

La spec « OpenID Identity Assurance Schema Definition 1.0 » (version finale)
définit le claim `verified_claims` : un conteneur qui porte les claims
**vérifiés** d'un utilisateur et les métadonnées du processus de vérification
(`trust_framework`, `assurance_level`, `evidence`…), afin qu'un RP ne puisse
pas confondre un claim vérifié et un claim ordinaire.

Côté OP :

- les claims vérifiés sont un **membre du profil utilisateur** (store
  `users`, colonne JSON) : aucun réglage n'est à activer, la feature est
  **data-driven** ;
- le membre n'est rendu **que sur demande** (paramètre OIDC `claims` §5.5) et
  **que dans la localisation demandée** (`id_token` ou `userinfo`) ;
- la demande est **appliquée** : un claim inconnu est omis, un claim demandé
  avec une `value` non satisfaite est omis (IA-5.7.4), un `trust_framework`
  non satisfait conduit à l'omission complète du membre ;
- la metadata eKYC du discovery est **dérivée** des profils vérifiés connus :
  sans profil, elle est absente.

Le parcours détaillé (et les limites) est documenté dans
`docs/identity-assurance.md` ; le plan de certification `ekyc` de la suite
OIDF est rejoué par le harnais local (`certification/local/run-plan.sh ekyc`).
