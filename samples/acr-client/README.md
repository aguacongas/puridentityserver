# ACR Values Sample Client

Exerce le paramètre `acr_values` défini par le fix #177 :

- Publication de `acr_values_supported` dans `/.well-known/openid-configuration`
- Choix de la **première valeur ACRAchúsqueda** satisfiable
- Validation `unmet_authentication_requirements` (RFC 9470)

## Configuration

1. Serveur `PurIdentityServer` avec cette setting (par défaut suffisant) :
   ```toml
   # config.toml
   acr_values_supported = ["puridentityserver:pwd"]
   ```
2. Client seed (public) déjà dans `config.toml` :
   ```toml
   [[settings.clients_seed]]
   client_id="sample-pkce-client"
   redirect_uris=["http://127.0.0.1:5173/callback"]
   scopes="openid profile email"
   client_type="public"
   ```

## Usage

```bash
# Terminal 1 : OP
uv run python -m puridentityserver

# Terminal 2 : smoke-test (découverte + invite pas-à-pas)
python samples/acr-client/smoke_test.py --base-url http://127.0.0.1:8000
```

Le script :
1. récupère la discovery, affiche `acr_values_supported`
2. construit l’URL `/authorize?…&acr_values=puridentityserver:pwd`
3. ouvre le navigateur pour que vous vous connectiez (alice/password)
4. affiche comment échanger le `code` au `/token` et inspecter l’`acr` du `id_token`

## Résultat attendu

L’`id_token` contient **`acr: "puridentityserver:pwd"`** si la valeur est atteignable.
Une valeur hors `acr_values_supported` (ex. `urn:inconnu:loa2`) déclenche
`unmet_authentication_requirements` (RFC 9470).
