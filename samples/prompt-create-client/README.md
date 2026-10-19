# Test manuel : prompt=create (Initiating User Registration via OIDC 1.0)

Script de démonstration du **`prompt=create`** de PurIdentityServer. Il
lance un serveur en sous-processus avec une configuration **spécifique à
ce test** (générée par `smoke_common.py` : port `8123`, client seed public
`sample-prompt-create-client`) puis joue le flow d'autorisation demandant
la création d'un compte à la volée. Aucun serveur RP n'est nécessaire : la
redirection sortante est lue côté `Location` (flow query, PKCE). Le client
déclare une **surcharge de politique de mots de passe**
(`password_policy = { min_length = 16 }`), plus stricte que le défaut
serveur (12 caractères), pour démontrer la résolution par client.

Le scénario vérifie :

1. le discovery publie `create` dans `prompt_values_supported` ;
2. `/authorize` avec `prompt=create` (sans session) → **302** vers la page
   d'inscription `/signup` (pas de redirection d'erreur — c'est le point
   central de la spec : l'OP affiche son formulaire, il ne renvoie pas
   d'erreur au client) ;
3. `GET /signup` → formulaire email / mot de passe affichant les exigences
   de la politique du client (16 caractères), `next` en champ caché et lien
   d'annulation (`register=cancelled`) ;
4. `POST /signup` avec un mot de passe valide pour le défaut serveur
   (14 caractères) mais sous le seuil du client → **erreur inline** sur le
   formulaire (détail + nouvelle tentative possible) ; seconde tentative
   avec 17 caractères → session fraîche, retour sur la demande → **302**
   callback avec `code` ;
5. l'`id_token` échangé porte le `sub` (UUID) du compte créé et
   `/userinfo` le confirme ;
6. `prompt=create none` → `login_required` redirigeable (spec §3 : aucune
   interaction n'est possible avec `none`) ;
7. création refusée (email déjà inscrit) → erreur inline sur le formulaire ;
8. annulation via le lien de la page → `access_denied` redirigeable.

## Lancement

```bash
uv run python samples/prompt-create-client/smoke_test.py
```

Résultat attendu : les 8 étapes s'affichent avec `OK`, puis
`=== SCÉNARIO OK en <n>s ===`.

## À quoi sert prompt=create ?

Initiating User Registration via OpenID Connect 1.0 (OpenID Foundation,
Final) permet à un RP de demander à l'OP de **créer un compte** pendant un
flow d'authentification, sans quitter le flux :

- `prompt=create` sur `/authorize` conduit l'utilisateur sur la page
  d'inscription de l'OP (`/signup` ici — composants `identity/`). À la
  création, le compte ouvre une session **fraîche** (cookie `sid` +
  empreinte `reauth` de la demande) et le flow reprend : l'`id_token`
  émis porte le `sub` du compte nouvellement créé ;
- la création fonde l'authentification : `prompt=create login` est
  satisfait par l'inscription elle-même (spec §2 — pas d'écran de
  connexion supplémentaire après la création) ;
- `prompt=create none` renvoie `login_required` redirigeable (spec §3) :
  `none` interdit toute interaction, or la création en demande une ;
- un utilisateur **déjà connecté** qui envoie `prompt=create` est conduit
  à la création directe d'un second compte (comportement §2 documenté) ;
- `prompt_values_supported` du discovery publie les valeurs honorées
  (`none`, `login`, `consent`, `create`) — champ de convention, non
  mandate par Core (CA 4 de l'issue #166).

## Politique de mots de passe configurable

Les mots de passe soumis sur `/signup` (et lors d'une réinitialisation)
sont validés par une `PasswordPolicy` (domain) :

- longueur **min/max** (défaut 12 / 128), exigences de **classes**
  (majuscules, minuscules, chiffres, caractères spéciaux) ;
- **denylist** de mots courants intégrée (~90 entrées des listes de
  fuites connues) ;
- interdiction de **contenir l'adresse email** ou son local-part ;
- détection de **séquences** (`123456`, `abcdef`) et de **runs clavier**
  (`qwerty`, `azerty`, 4+ caractères consécutifs) ;
- **historique de réemploi** : les `history_depth` derniers mots de passe
  (empreintes dans `User.password_history`) ne peuvent pas être réutilisés
  lors d'une réinitialisation.

Configuration (hiérarchie `config.toml` → `PURIDENTITYSERVER_*` → `.env`) :

- `[settings.password_policy]` : valeurs par défaut du serveur ;
- table **partielle** `password_policy = { … }` sur un client de
  `clients_seed` : seules les clés présentes écrasent la défaut pour les
  flows de ce client (le smoke ci-dessus impose `min_length = 16` à son
  client) ; une clé inconnue ou un type erroné casse le chargement au
  démarrage.

Toute création refusée (politique, email existant ou malformé) est rendue
**en erreur inline sur le formulaire** avec le détail des violations :
l'utilisateur corrige et retente. Seul le lien « Refuser l'inscription »
conduit à `access_denied` redirigeable vers le RP.

Le marqueur OP `register=` (`cancelled` / `refused`) circule dans l'URL de
retour d'inscription ; sans `prompt=create`, il est ignoré comme tout
paramètre inconnu (RFC 6749 §3.1).

## Vérification CSRF (issue #184)

Les POST des formulaires HTML (`/login`, `/signup`, `/consent`,
`/device`) refusent les requêtes de site tiers via les en-têtes de
navigation `Sec-Fetch-Site` / `Origin`. Depuis un serveur de dev local
(`uv run python -m puridentityserver`, port 8000) :

```bash
# refusé : initiateur cross-site -> 403 « protection CSRF »
curl -i -X POST http://127.0.0.1:8000/login \
  -H "Sec-Fetch-Site: cross-site" \
  --data "username=alice@example.com&password=whatever&next=/"

# refusé : Origin divergent (sans Sec-Fetch-Site) -> 403
curl -i -X POST http://127.0.0.1:8000/login \
  -H "Origin: https://evil.example" \
  --data "username=alice@example.com&password=whatever&next=/"

# accepté : aucun en-tête de navigation (client machine) -> traitement normal
curl -i -X POST http://127.0.0.1:8000/login \
  --data "username=alice@example.com&password=wrong&next=/" \
  -o /dev/null -w "%{http_code}\n"
```

Résultat attendu : `403` (corps `Requête refusée (protection CSRF) : …`)
pour les deux premiers ; `302` vers `/login` (identifiants inconnus) pour
le troisième. Tout navigateur moderne envoie au moins `Origin` sur un
POST : la couverture est complète côté navigateur, les clients machine
(non navigateurs) restent autorisés.
