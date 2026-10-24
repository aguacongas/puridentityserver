#!/usr/bin/env python3
# flake8: noqa
r"""provision_oci.py — provision d'une VM Oracle Cloud Always Free (OCI) + reseau.

Utilise le SDK Python OCI (bypass du bug de démarrage de oci.exe). À lancer
depuis un shell où la session OCI est valide :

    $env:USERPROFILE\\lib\\oracle-cli\\Scripts\\python.exe certification\\proxy\\provision_oci.py

Variables d'environnement optionnelles :
    TENANCY_OCID            (défaut : lu depuis ~/.oci/config)
    REGION                  (défaut : lu depuis ~/.oci/config, ex. eu-marseille-1)
    DISPLAY_NAME            (défaut : puridentity-mtls-proxy)
    AVAILABILITY_DOMAIN     (défaut : premier AD de la région)
    COMPARTMENT_OCID        (défaut : tenancy root)
    OCI_KEY                 (chemin de la clé SSH, défaut : ~/.ssh/id_ed25519)
    OCI_PUBKEY              (chemin de la clé publique SSH, défaut : ~/.ssh/id_ed25519.pub)

Sortie : imprime INSTANCE_OCID, PUBLIC_IP, VCN_OCID etc. (à capturer pour la
suite DuckDNS / certbot / nginx).
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

import oci


def _p(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


HOME = Path.home()
CONFIG_PATH = HOME / ".oci" / "config"
PROFILE = "DEFAULT"

print("== Chargement de la config OCI ==")
config = oci.config.from_file(str(CONFIG_PATH), PROFILE)
region = _p("REGION", config.get("region", "eu-marseille-1"))
config["region"] = region
tenancy = _p("TENANCY_OCID", config["tenancy"])
compartment = _p("COMPARTMENT_OCID", tenancy)

# Signer security token (session fédérée, ~1h)
token_path = config.get("security_token_file") or str(
    HOME / ".oci" / "sessions" / "DEFAULT" / "token"
)
private_key_path = config.get("key_file") or str(
    HOME / ".oci" / "sessions" / "DEFAULT" / "oci_api_key.pem"
)

token = Path(token_path).read_text(encoding="utf-8").strip()
private_key = oci.signer.load_private_key_from_file(private_key_path)
signer = oci.auth.signers.SecurityTokenSigner(token, private_key)


def _client(cls, **kw) -> object:
    # retourne des clients OCI de types variés
    return cls(config, signer=signer, **kw)


# --------------------------------------------------------------------------- #
# 1. Réseau
# --------------------------------------------------------------------------- #
print("\n== [1/9] VCN ==")
vcn_client = _client(oci.core.VirtualNetworkClient)
vcn_name = "puridentity-proxy-vcn"
vcn = vcn_client.create_vcn(
    oci.core.models.CreateVcnDetails(
        compartment_id=compartment,
        display_name=vcn_name,
        cidr_blocks=["10.0.0.0/16"],
        dns_label="purproxyvcn",
    )
).data
VCN_OCID = vcn.id
print("VCN :", VCN_OCID)
# attendre AVAILABLE
for _ in range(60):
    st = vcn_client.get_vcn(VCN_OCID).data.lifecycle_state
    if st == "AVAILABLE":
        break
    time.sleep(2)

print("== [2/9] Internet Gateway ==")
igw = vcn_client.create_internet_gateway(
    oci.core.models.CreateInternetGatewayDetails(
        compartment_id=compartment,
        vcn_id=VCN_OCID,
        display_name="puridentity-igw",
        is_enabled=True,
    )
).data
IGW_OCID = igw.id
print("IGW :", IGW_OCID)

print("== [3/9] Route table (default -> IGW) ==")
rts = vcn_client.list_route_tables(compartment_id=compartment, vcn_id=VCN_OCID).data
rt = rts[0]
vcn_client.update_route_table(
    rt.id,
    oci.core.models.UpdateRouteTableDetails(
        route_rules=[
            oci.core.models.RouteRule(
                destination="0.0.0.0/0",
                destination_type="CIDR_BLOCK",
                network_entity_id=IGW_OCID,
            )
        ],
    ),
)
print("Route table :", rt.id)

print("== [4/9] Security list (22 admin / 443 partout) ==")
sls = vcn_client.list_security_lists(compartment_id=compartment, vcn_id=VCN_OCID).data
sl = sls[0]
vcn_client.update_security_list(
    sl.id,
    oci.core.models.UpdateSecurityListDetails(
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(
                protocol="6",
                source="0.0.0.0/0",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(min=443, max=443)
                ),
                is_stateless=False,
            ),
            oci.core.models.IngressSecurityRule(
                protocol="6",
                source="0.0.0.0/0",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(min=22, max=22)
                ),
                is_stateless=False,
            ),
        ],
        egress_security_rules=[
            oci.core.models.EgressSecurityRule(
                protocol="all", destination="0.0.0.0/0", is_stateless=False
            ),
        ],
    ),
)
SL_OCID = sl.id
print("Security list :", SL_OCID)

print("== [5/9] Subnet public ==")
subnet = vcn_client.create_subnet(
    oci.core.models.CreateSubnetDetails(
        compartment_id=compartment,
        vcn_id=VCN_OCID,
        display_name="puridentity-proxy-subnet",
        cidr_block="10.0.0.0/24",
        route_table_id=rt.id,
        security_list_ids=[SL_OCID],
        dns_label="purproxysub",
    )
).data
SUBNET_OCID = subnet.id
print("Subnet :", SUBNET_OCID)
for _ in range(60):
    st = vcn_client.get_subnet(SUBNET_OCID).data.lifecycle_state
    if st == "AVAILABLE":
        break
    time.sleep(2)

print("== [6/9] IP publique reservee ==")
rip = vcn_client.create_public_ip(
    oci.core.models.CreatePublicIpDetails(
        compartment_id=compartment,
        lifetime="RESERVED",
        display_name="puridentity-proxy-ip",
    )
).data
RESERVED_IP_OCID = rip.id
PUBLIC_IP = rip.ip_address
print("Reserved IP :", RESERVED_IP_OCID, "->", PUBLIC_IP)

# --------------------------------------------------------------------------- #
# 2. Cle SSH
# --------------------------------------------------------------------------- #
key_path = Path(_p("OCI_KEY", str(HOME / ".ssh" / "id_ed25519")))
pub_path = Path(_p("OCI_PUBKEY", str(HOME / ".ssh" / "id_ed25519.pub")))
if not pub_path.exists():
    print("== Generation d'une paire de cles SSH ed25519 ==")
    import subprocess

    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True)
pub_key = pub_path.read_text(encoding="utf-8").strip()

# --------------------------------------------------------------------------- #
# 3. Image Oracle Linux 9 (la plus recente pour A1.Flex)
# --------------------------------------------------------------------------- #
print("== [7/9] Recherche de l'image Oracle Linux 9 (A1.Flex) ==")
identity = _client(oci.identity.IdentityClient)
display_name = _p("DISPLAY_NAME", "puridentity-mtls-proxy")

ads = identity.list_availability_domains(compartment_id=tenancy).data
ad_name = _p("AVAILABILITY_DOMAIN", ads[0].name)
print("AD choisi :", ad_name)

compute = _client(oci.core.ComputeClient)
images = compute.list_images(
    compartment_id=compartment,
    operating_system="Oracle Linux",
    operating_system_version="9",
    shape="VM.Standard.A1.Flex",
    sort_by="TIMECREATED",
    sort_order="DESC",
    limit=1,
).data
if not images:
    print("ERREUR : aucune image Oracle Linux 9 pour A1.Flex")
    sys.exit(1)
IMAGE_OCID = images[0].id
print("Image :", IMAGE_OCID, images[0].display_name)

# --------------------------------------------------------------------------- #
# 4. Instance
# --------------------------------------------------------------------------- #
print("== [8/9] Lancement de l'instance ==")
cloud_init = """#cloud-config
packages:
  - nginx
  - python3
  - python3-pip
runcmd:
  - systemctl enable nginx
  - systemctl start nginx
"""
launch = compute.launch_instance(
    oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment,
        display_name=display_name,
        shape="VM.Standard.A1.Flex",
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
            ocpus=1.0,
            memory_in_gbs=6.0,
        ),
        availability_domain=ad_name,
        source_details=oci.core.models.InstanceSourceViaImageDetails(
            source_type="image",
            image_id=IMAGE_OCID,
            boot_volume_size_in_gbs=50,
        ),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=SUBNET_OCID,
            assign_public_ip=False,  # IP reservee attachée a posteriori
            display_name="puridentity-proxy-vnic",
        ),
        metadata={
            "ssh_authorized_keys": pub_key,
            "user_data": base64.b64encode(cloud_init.encode()).decode(),
        },
    )
).data
INSTANCE_OCID = launch.id
print("Instance :", INSTANCE_OCID)
# attendre RUNNING
for _ in range(120):
    st = compute.get_instance(INSTANCE_OCID).data.lifecycle_state
    if st in ("RUNNING", "TERMINATED", "TERMINATING"):
        break
    time.sleep(5)
print("Etat :", compute.get_instance(INSTANCE_OCID).data.lifecycle_state)

# --------------------------------------------------------------------------- #
# 5. Attacher l'IP reservee a la VNIC principale
# --------------------------------------------------------------------------- #
print("== [9/9] Attachement de l'IP publique reservee ==")
vnic_list = compute.list_vnic_attachments(
    compartment_id=compartment, instance_id=INSTANCE_OCID
).data
if not vnic_list:
    print("ATTENTION : pas de VNIC attachee, attachez l'IP manuellement depuis la console.")
else:
    vnic_id = vnic_list[0].vnic_id
    vnic = vcn_client.get_vnic(vnic_id).data
    # supprimer l'IP publique ephemere si presente (assign_public_ip=false => aucune)
    try:
        vcn_client.update_public_ip(
            rip.id,
            oci.core.models.UpdatePublicIpDetails(
                private_ip_id=vnic.private_ip_id,
            ),
        )
        print("OK - IP", PUBLIC_IP, "attachée a la VNIC", vnic_id)
    except Exception as e:
        print("ATTENTION : attachement automatique echoue :", e)
        print(
            "Attachez l'IP manuellement : Compute -> Instance -> Attached VNICs -> Edit -> Reserved Public IP."
        )

# --------------------------------------------------------------------------- #
# Recap
# --------------------------------------------------------------------------- #
print("\n" + "=" * 70)
print("PROVISION TERMINEE")
print("=" * 70)
print("VCN_OCID        :", VCN_OCID)
print("SUBNET_OCID     :", SUBNET_OCID)
print("INSTANCE_OCID   :", INSTANCE_OCID)
print("RESERVED_IP_OCID:", RESERVED_IP_OCID)
print("PUBLIC_IP       :", PUBLIC_IP)
print("AVAILABILITY_DOMAIN:", ad_name)
print("\nProchaines etapes (manuelles) :")
print("  1. ssh opc@%s" % PUBLIC_IP)
print("  2. DuckDNS : ~/duckdns/duck.sh (cf. runbook section 3)")
print("  3. certbot --key-type rsa -d <sous-domaine-duckdns>")
print("  4. cp certification/proxy/nginx-oracle.conf /etc/nginx/conf.d/puridentity.conf")
print("     sed -i 's/{HOSTNAME}/<sous-domaine>/g' /etc/nginx/conf.d/puridentity.conf")
print("  5. nginx -t && systemctl reload nginx")
print("  6. curl https://<sous-domaine>/.well-known/openid-configuration")
print("\nConserver les OCID ci-dessus pour le cleanup (instance terminate, IP release, etc.).")
