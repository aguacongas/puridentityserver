# Test manuel : prompt=create (Initiating User Registration via OIDC 1.0)

Script de démonstration du **`prompt=create`** de PurIdentityServer. Il
lance un serveur en sous-processus avec une configuration **spécifique à
ce test** (générée par `smoke_common.py` : port `8123`, client seed public
`sample-prompt-create-client`) puis joue le flow d'autorisation demandant
la création d'un compte à la volée. Aucun serveur RP n'est nécessaire : la
redirection sortante est lue côté `Location` (flow query, PKCE).

Le scénario vérifie :

1. le discovery publie `create` dans `prompt_values_supported` ;
2. `/authorize` avec `prompt=create` (sans session) → **302** vers la page
   d'inscription `/signup` (pas de redirection d'erreur — c'est le point
   central de la spec : l'OP affiche son formulaire, il ne renvoie pas
   d'erreur au client) ;
3. `GET /signup` → formulaire email / mot de passe, `next` en champ caché
   et lien d'annulation (`register=cancelled`) ;
4. `POST /signup` (nouveau compte) → session fraîche, retour sur la
   demande → **302** callback avec `code` ; l'`id_token` échangé porte le
   `sub` (UUID) du compte créé et `/userinfo` le confirme ;
5. `prompt=create none` → `login_required` redirigeable (spec §3 : aucune
   interaction n'est possible avec `none`) ;
6. création refusée (email déjà inscrit) → `access_denied` redirigeable
   avec `state` réfléchi ;
7. annulation via le lien de la page → `access_denied` redirigeable.

## Lancement

```bash
uv run python samples/prompt-create-client/smoke_test.py
```

Résultat attendu : les 7 étapes s'affichent avec `OK`, puis
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
- création refusée (email déjà existant, politique de mot de passe serveur
  8 caractères min.) ou annulée par l'utilisateur → `access_denied`
  redirigeable, transporté selon le `response_mode` résolu ;
- un utilisateur **déjà connecté** qui envoie `prompt=create` est conduit
  à la création directe d'un second compte (comportement §2 documenté) ;
- `prompt_values_supported` du discovery publie les valeurs honorées
  (`none`, `login`, `consent`, `create`) — champ de convention, non
  mandate par Core (CA 4 de l'issue #166).

Le marqueur OP `register=` (`cancelled` / `refused`) circule dans l'URL de
retour d'inscription ; sans `prompt=create`, il est ignoré comme tout
paramètre inconnu (RFC 6749 §3.1).
