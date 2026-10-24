# Runbook — reverse proxy TLS mTLS gratuit devant Render (Oracle Cloud Always Free + OCI)

> Procédure de mise en place du proxy **nginx** avec `ssl_verify_client optional_no_ca` devant l'instance Render de certification (`puridentityserver-certification`), pour terminer la liaison mTLS (#127) sans casser les flux navigateur (`/authorize` sans cert) et sans toucher au pipeline de déploiement Render. Cible : **Oracle Cloud Infrastructure (OCI) — palier Always Free**.

**Automatisation** : `certification/proxy/provision-oci.ps1` (+ `provision_oci.py`) crée VCN, IGW, subnet, IP réservée, instance A1.Flex et injecte la clé SSH via l'API OCI (SDK Python, bypass du bug `oci.exe`). À lancer une fois la session OCI renouvelée (`oci session authenticate`).

## Pourquoi Oracle Cloud Always Free

OCI Always Free offre un palier gratuit pérenne (VMs Ampere A1, IP publique réservée, stockage) suffisant pour héberger un reverse proxy nginx de terminaison mTLS devant Render. Compte à créer sur <https://cloud.oracle.com>.

- **Compute** : `VM.Standard.A1.Flex` (Ampere ARM) — jusqu'à 4 OCPU / 24 GB RAM en gratuit, ou `VM.Standard.E2.1.Micro` (AMD, 1 OCPU / 1 GB) ;
- **Réseau** : VCN + subnet public + **IP publique réservée** (gratuite tant qu'attachée) ;
- **Stockage** : volume de démarrage 50 GB gratuit.
- **OCID** : identifiants OCI (`ocid1.tenancy...`, `ocid1.user...`) disponibles dans le tableau de bord.

Stack cible : **Oracle Linux 9** (ou Ubuntu 22.04) + nginx + certbot (RSA) + DuckDNS.

## 0. Provisionnement avec la CLI OCI (optionnel, reproductible)

La CLI OCI (module Python, version ≥ 3.0) permet d'automatiser toute la mise en place ci-dessous. Une fois authentifié (`oci session authenticate --profile-name DEFAULT`), les commandes suivantes créent le VCN, le subnet public, l'IP réservée et la VM. Adapter la région (`--region eu-marseille-1` mis par défaut dans `~/.oci/config`) et le compartment racine (`TENANCY_OCID`).

```bash
# Variables d'environnement à positionner une fois pour toute la session
export TENANCY_OCID="ocid1.tenancy.oc1..aaaa..."   # console OCI -> Profile -> Tenancy
export REGION="eu-marseille-1"
export DISPLAY_NAME="puridentity-mtls-proxy"
export AVAILABILITY_DOMAIN="kWVD:EU-MARSEILLE-1-AD-1"   # oci iam availability-domain list

# 0. Authentification (session token, valide ~1h)
oci session authenticate --profile-name DEFAULT --region "${REGION}"

# 1. VCN
VCN_OCID=$(oci network vcn create \
    --compartment-id "${TENANCY_OCID}" \
    --display-name "puridentity-proxy-vcn" \
    --cidr-blocks '["10.0.0.0/16"]' \
    --query 'data.id' --raw-output)

# 2. Internet Gateway
IGW_OCID=$(oci network internet-gateway create \
    --compartment-id "${TENANCY_OCID}" \
    --vcn-id "${VCN_OCID}" \
    --display-name "puridentity-igw" \
    --is-enabled true \
    --query 'data.id' --raw-output)

# 3. Route table (route default -> IGW)
oci network route-table update --rt-id $(oci network route-table list \
    --compartment-id "${TENANCY_OCID}" --vcn-id "${VCN_OCID}" \
    --query 'data[0].id' --raw-output) \
    --route-rules "[{\"cidrBlock\":\"0.0.0.0/0\",\"networkEntityId\":\"${IGW_OCID}\"}]"

# 4. Security list (22 depuis l'admin, 443 depuis partout)
SL_OCID=$(oci network security-list list \
    --compartment-id "${TENANCY_OCID}" --vcn-id "${VCN_OCID}" \
    --query 'data[0].id' --raw-output)
oci network security-list update --security-list-id "${SL_OCID}" \
    --ingress-security-rules '[
      {"protocol":"6","source":"0.0.0.0/0","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}},
      {"protocol":"6","source":"0.0.0.0/0","tcpOptions":{"destinationPortRange":{"min":22,"max":22}}}
    ]' \
    --egress-security-rules '[{"protocol":"all","destination":"0.0.0.0/0"}]'

# 5. Subnet public
SUBNET_OCID=$(oci network subnet create \
    --compartment-id "${TENANCY_OCID}" \
    --vcn-id "${VCN_OCID}" \
    --display-name "puridentity-proxy-subnet" \
    --cidr-block "10.0.0.0/24" \
    --route-table-id $(oci network route-table list \
        --compartment-id "${TENANCY_OCID}" --vcn-id "${VCN_OCID}" \
        --query 'data[0].id' --raw-output) \
    --security-list-ids "[\"${SL_OCID}\"]" \
    --query 'data.id' --raw-output)

# 6. IP publique réservée (gratuite tant qu'attachée)
RESERVED_IP_OCID=$(oci network public-ip create \
    --compartment-id "${TENANCY_OCID}" \
    --lifetime RESERVED \
    --display-name "puridentity-proxy-ip" \
    --query 'data.id' --raw-output)
PUBLIC_IP=$(oci network public-ip get --public-ip-id "${RESERVED_IP_OCID}" \
    --query 'data.ip-address' --raw-output)
echo "IP publique : ${PUBLIC_IP}"

# 7. Clé SSH (si pas déjà présente)
test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519

# 8. Image Oracle Linux 9 la plus récente
IMAGE_OCID=$(oci compute image list \
    --compartment-id "${TENANCY_OCID}" \
    --operating-system "Oracle Linux" \
    --operating-system-version "9" \
    --shape "VM.Standard.A1.Flex" \
    --sort-by TIMECREATED --sort-order DESC \
    --limit 1 --query 'data[0].id' --raw-output)

# 9. Instance
INSTANCE_OCID=$(oci compute instance launch \
    --compartment-id "${TENANCY_OCID}" \
    --availability-domain "${AVAILABILITY_DOMAIN}" \
    --display-name "${DISPLAY_NAME}" \
    --shape "VM.Standard.A1.Flex" \
    --shape-config '{"ocpus":1.0,"memoryInGBs":6.0}' \
    --image-id "${IMAGE_OCID}" \
    --subnet-id "${SUBNET_OCID}" \
    --assign-public-ip false \
    --metadata "{\"ssh_authorized_keys\":\"$(cat ~/.ssh/id_ed25519.pub)\"}" \
    --query 'data.id' --raw-output)

# Attacher l'IP réservée (l'attachement se fait via une VNIC, commande simplifiée ci-dessous)
oci compute instance attach-vnic --instance-id "${INSTANCE_OCID}" \
    --subnet-id "${SUBNET_OCID}" --assign-public-ip false >/dev/null 2>&1 || true
echo "Instance ${INSTANCE_OCID} créée — IP publique réservée : ${PUBLIC_IP}"

# 10. Attendre que l'instance soit RUNNING
oci compute instance get --instance-id "${INSTANCE_OCID}" \
    --query 'data."lifecycle-state"' --raw-output
```

> Note : l'attachement d'une IP réservée à une VNIC déjà existante se fait via `oci network vnic assign-private-ip` + `oci network public-ip update --public-ip-id ... --private-ip-id ...`. Si la commande automatique ci-dessus ne suffit pas, attacher manuellement via la console (Compute → Instance → Attached VNICs → Edit → Reserved Public IP). L'objectif est qu'en fin d'étapes 1-10 la VM réponde sur `${PUBLIC_IP}`.

Une fois la VM accessible (`ssh opc@${PUBLIC_IP}`), poursuivre avec les étapes **3 à 7** du runbook (DuckDNS, nginx + certbot RSA, injection de `certification/proxy/nginx-oracle.conf`, tests). Le cloud-init correspondant (pour automatiser DuckDNS + nginx + certbot au premier boot) peut être ajouté via `--user-data-file` à l'étape 9 ; exemple minimal dans `certification/proxy/cloud-init.yaml` (à créer au besoin).

Le palier Always Free limite la somme des shapes Ampere A1 à 4 OCPU / 24 GB : rester sur `1.0` OCPU / `6.0` GB pour cette VM si d'autres ressources Always Free sont déjà en service.

## 1. Compte OCI et réseau (une fois)

1. Créer le compte sur <https://cloud.oracle.com> (compte gratuit, palier Always Free).
2. Console → **Networking → Virtual Cloud Networks → Create VCN** :
   - nom `puridentity-proxy-vcn`, CIDR `10.0.0.0/16` ;
   - créer un **subnet public** `10.0.0.0/24` avec **Route Table** → Internet Gateway ;
   - **Security List** (ou NSG) : ingress TCP 22 (admin, IP source restreinte) + TCP 443 (0.0.0.0/0) ; egress tout autorisé.
3. Réserver une IP publique : **Networking → IP Management → Reserved Public IPs → Create** (free), l'attacher à l'instance ci-dessous.

## 2. VM (une fois)

1. **Compute → Instances → Create Instance** :
   - nom `puridentity-mtls-proxy` ;
   - image **Oracle Linux 9** (ou Ubuntu 22.04) ;
   - shape `VM.Standard.A1.Flex` (1 OCPU / 6 GB) — à adapter, rester dans le palier Always Free (somme des A1 ≤ 4 OCPU / 24 GB) ;
   - VCN/subnet public choisis, IP publique réservée attachée ;
   - clé SSH (générer ou coller la vôtre).
2. Se connecter : `ssh opc@<IP>` (utilisateur par défaut `opc` sur Oracle Linux ; `ubuntu` sur Ubuntu).

## 3. DNS — DuckDNS (gratuit, dynamique)

1. Compte <https://www.duckdns.org>, sous-domaine ex. `puridentity-op-cert.duckdns.org`.
2. Sur la VM, installer le client de mise à jour (cron) :
   ```bash
   mkdir -p ~/duckdns && cd ~/duckdns
   cat > duck.sh <<'EOF'
   #!/bin/bash
   TOKEN="VOTRE_TOKEN_DUCKDNS"
   DOMAIN="puridentity-op-cert"
   echo url="https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=" | curl -k -o ~/duckdns/duck.log -K -
   EOF
   chmod 700 duck.sh
   (crontab -l 2>/dev/null; echo "*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1") | crontab -
   ~/duckdns/duck.sh && cat ~/duckdns/duck.log
   ```
3. Vérifier : `dig +short puridentity-op-cert.duckdns.org` → IP de la VM.

> Si l'IP est réservée (recommandé), DuckDNS reste utile comme alias DNS stable et comme filet de sécurité.

## 4. nginx + certbot (RSA obligatoire)

```bash
sudo dnf install -y nginx certbot python3-certbot-nginx   # Oracle Linux
# ou : sudo apt install -y nginx certbot python3-certbot-nginx  (Ubuntu)
sudo systemctl enable --now nginx

# Certificat Let's Encrypt RSA (la suite FAPI1 ne négocie que des suites
# TLS 1.2 RSA ; un cert ECDSA reproduirait le plafond DisallowInsecureCipher)
sudo certbot certonly --standalone --key-type rsa \
    -d puridentity-op-cert.duckdns.org \
    --agree-tos -m votre@email.example -n
```

## 5. nginx.conf (prêt à coller)

Fichier complet : [`certification/proxy/nginx-oracle.conf`](../certification/proxy/nginx-oracle.conf). À copier dans `/etc/nginx/conf.d/puridentity.conf` (ou `/etc/nginx/sites-available/` + symlink selon la distro), en remplaçant `{HOSTNAME}` par le sous-domaine DuckDNS.

Points clés (identiques au proxy local de certification) :
- `ssl_verify_client optional_no_ca` : demande le cert au handshake **sans bloquer** les navigateurs de la suite (`/authorize` sans cert) ; accepte les certs auto-signés de la suite.
- Transfert du PEM via `X-SSL-Client-Cert` (URL-encodé, `%0A`) — l'OP normalise dans `infrastructure/client_tls.py` (`_normalize_header_value`).
- TLS 1.2 RSA au edge (`ssl_ciphers` incluant `RSA-AES128-GCM-SHA256`) pour éviter `DisallowInsecureCipher`.
- `trust_proxy_headers = true` côté OP (déjà activé dans `config.render.toml`) pour reconstruire l'URL publique (claim `htu` DPoP, RFC 9449 §4.3).

```bash
sudo cp certification/proxy/nginx-oracle.conf /etc/nginx/conf.d/puridentity.conf
sudo sed -i 's/{HOSTNAME}/puridentity-op-cert.duckdns.org/g' /etc/nginx/conf.d/puridentity.conf
sudo nginx -t && sudo systemctl reload nginx
```

## 6. Tests de bout en bout

```bash
HOST=puridentity-op-cert.duckdns.org
# sans cert -> 200
curl -fsS "https://${HOST}/.well-known/openid-configuration" >/dev/null && echo "OK sans cert"
# handshake mTLS actif (cert demande)
openssl s_client -connect "${HOST}:443" -cipher AES128-SHA256 </dev/null 2>&1 | grep -E "Protocol|Cipher|Verify"
# cert auto-signe -> 200
openssl req -x509 -newkey rsa:2048 -keyout /tmp/client.key -out /tmp/client.pem -days 1 -nodes -subj "/CN=test"
curl --cert /tmp/client.pem --key /tmp/client.key -fsS "https://${HOST}/.well-known/openid-configuration" >/dev/null && echo "OK avec cert"
```

## 7. Côté repo (PR dédiée, ordre)

1. Variable GitHub `CERTIFICATION_OP_URL` = `https://puridentity-op-cert.duckdns.org` (le workflow, les captures Playwright et la suite passent par le proxy ; le deploy hook Render reste direct).
2. PR flip seeds : `certification/config.render.toml` — `tls_client_certificate_bound_access_tokens = true` sur les 2 clients FAPI1 statiques **uniquement après** le proxy live (sinon tout `/token` fapi1 casse). FAPI2 reste sans flag (DPoP).
3. Rejeu `certification.yml` (plan=all) : objectif 6 plans verts. Si `DisallowInsecureCipher` échoue encore, déclarer les blocs résiduels en `--expected-failures-file` (issue dédiée).
4. Follow-up #132 (rejeu des plans à chaque run) une fois le vert obtenu.

## Critères d'acceptation

- Discovery public joignable sans cert ; handshake mTLS actif (cert demandé) ;
- Suite de certification : modules `fapi1-holder-of-key` / `refresh-token` verts (cert transféré, flag actif) ;
- 6 plans de certification en succès (ou résidus couverts par `expected_failures` documentés) ;
- Rien à changer au pipeline Render (deploy hook inchangé).

## Sécurité

- Le certificat client n'est **jamais vérifié contre une CA** (`optional_no_ca`) : la suite présente des certs auto-signés que l'OP accepte tels quels (transfert via `X-SSL-Client-Cert`, RFC 8705).
- Le secret admin (`CERTIFICATION_ADMIN_CLIENT_SECRET`) reste géré côté Render et GitHub Actions — jamais dans la VM.
- Renouvellement Let's Encrypt : cron `certbot renew` (installé par défaut par certbot sur Oracle Linux/Ubuntu).
- Port 22 restreint à l'IP d'administration.
