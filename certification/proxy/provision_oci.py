#!/usr/bin/env python3
r"""provision_oci.py — provision d'une VM Oracle Cloud Always Free (OCI) + reseau.

Idempotent : les ressources existantes (VCN, IGW, subnet, IP, instance) sont
reutilisees si presentes (recherche par display_name), ce qui permet de
reprendre apres un echec partiel.

Utilise le SDK Python OCI (bypass du bug de demarrage de oci.exe). A lancer
depuis un shell ou la session OCI est valide :

    $env:USERPROFILE\lib\oracle-cli\Scripts\python.exe certification\proxy\provision_oci.py

Variables d'environnement optionnelles :
    TENANCY_OCID            (defaut : lu depuis ~/.oci/config)
    REGION                  (defaut : lu depuis ~/.oci/config, ex. eu-marseille-1)
    DISPLAY_NAME            (defaut : puridentity-mtls-proxy)
    AVAILABILITY_DOMAIN     (defaut : premier AD de la region)
    COMPARTMENT_OCID        (defaut : tenancy root)
    OCI_KEY / OCI_PUBKEY    (defaut : ~/.ssh/id_ed25519[.pub])
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
import time
from pathlib import Path

import oci


def _p(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


HOME = Path.home()
CONFIG_PATH = HOME / ".oci" / "config"
PROFILE = "DEFAULT"
SSH_DIR = HOME / ".ssh"
VCN_NAME = "puridentity-proxy-vcn"
SUBNET_NAME = "puridentity-proxy-subnet"
IGW_NAME = "puridentity-igw"
IP_NAME = "puridentity-proxy-ip"
SL_NAME = "puridentity-proxy-sl"
INSTANCE_NAME_DEFAULT = "puridentity-mtls-proxy"


def _find(items: list, name: str, key: str = "display_name"):
    for it in items:
        if getattr(it, key, None) == name:
            return it
    return None


# --------------------------------------------------------------------------- #
# 0. Config + signer
# --------------------------------------------------------------------------- #
print("== Chargement de la config OCI ==")
config = oci.config.from_file(str(CONFIG_PATH), PROFILE)
region = _p("REGION", config.get("region", "eu-marseille-1"))
config["region"] = region
tenancy = _p("TENANCY_OCID", config["tenancy"])
compartment = _p("COMPARTMENT_OCID", tenancy)

token_path = config.get("security_token_file") or str(HOME / ".oci" / "sessions" / "DEFAULT" / "token")
private_key_path = config.get("key_file") or str(HOME / ".oci" / "sessions" / "DEFAULT" / "oci_api_key.pem")

token = Path(token_path).read_text(encoding="utf-8").strip()
private_key = oci.signer.load_private_key_from_file(private_key_path)
signer = oci.auth.signers.SecurityTokenSigner(token, private_key)


def C(cls, **kw):
    return cls(config, signer=signer, **kw)


vcn_client = C(oci.core.VirtualNetworkClient)
identity = C(oci.identity.IdentityClient)
compute = C(oci.core.ComputeClient)

# --------------------------------------------------------------------------- #
# 1. Cle SSH
# --------------------------------------------------------------------------- #
key_path = Path(_p("OCI_KEY", str(HOME / ".ssh" / "id_ed25519")))
pub_path = Path(_p("OCI_PUBKEY", str(HOME / ".ssh" / "id_ed25519.pub")))
SSH_DIR.mkdir(parents=True, exist_ok=True)
if not pub_path.exists():
    print("== Generation d'une paire de cles SSH ed25519 ==")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True)
pub_key = pub_path.read_text(encoding="utf-8").strip()

# --------------------------------------------------------------------------- #
# 2. Reseau (idempotent)
# --------------------------------------------------------------------------- #
print("\n== [1/9] VCN ==")
vcns = vcn_client.list_vcns(compartment_id=compartment).data
vcn = _find(vcns, VCN_NAME)
if vcn is None:
    vcn = vcn_client.create_vcn(oci.core.models.CreateVcnDetails(
        compartment_id=compartment, display_name=VCN_NAME,
        cidr_blocks=["10.0.0.0/16"], dns_label="purproxyvcn",
    )).data
    print("  cree :", vcn.id)
    for _ in range(60):
        if vcn_client.get_vcn(vcn.id).data.lifecycle_state == "AVAILABLE":
            break
        time.sleep(2)
else:
    print("  reutilise :", vcn.id)
VCN_OCID = vcn.id

print("== [2/9] Internet Gateway ==")
igws = vcn_client.list_internet_gateways(compartment_id=compartment, vcn_id=VCN_OCID).data
igw = _find(igws, IGW_NAME)
if igw is None:
    igw = vcn_client.create_internet_gateway(oci.core.models.CreateInternetGatewayDetails(
        compartment_id=compartment, vcn_id=VCN_OCID, display_name=IGW_NAME, is_enabled=True,
    )).data
    print("  cree :", igw.id)
else:
    print("  reutilise :", igw.id)
IGW_OCID = igw.id

print("== [3/9] Route table (default -> IGW) ==")
rts = vcn_client.list_route_tables(compartment_id=compartment, vcn_id=VCN_OCID).data
rt = rts[0]
vcn_client.update_route_table(rt.id, oci.core.models.UpdateRouteTableDetails(
    route_rules=[oci.core.models.RouteRule(
        destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id=IGW_OCID,
    )],
))
print("  route table :", rt.id)

print("== [4/9] Security list (22 / 443) ==")
sls = vcn_client.list_security_lists(compartment_id=compartment, vcn_id=VCN_OCID).data
sl = _find(sls, SL_NAME)
if sl is None:
    # creer une nouvelle security list (la default reste inchangee)
    sl = vcn_client.create_security_list(oci.core.models.CreateSecurityListDetails(
        compartment_id=compartment, vcn_id=VCN_OCID, display_name=SL_NAME,
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(protocol="6", source="0.0.0.0/0",
                tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=443, max=443)),
                is_stateless=False),
            oci.core.models.IngressSecurityRule(protocol="6", source="0.0.0.0/0",
                tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=22, max=22)),
                is_stateless=False),
        ],
        egress_security_rules=[oci.core.models.EgressSecurityRule(protocol="all", destination="0.0.0.0/0", is_stateless=False)],
    )).data
    print("  creee :", sl.id)
else:
    print("  reutilisee :", sl.id)
SL_OCID = sl.id

print("== [5/9] Subnet public ==")
subnets = vcn_client.list_subnets(compartment_id=compartment, vcn_id=VCN_OCID).data
subnet = _find(subnets, SUBNET_NAME)
if subnet is None:
    subnet = vcn_client.create_subnet(oci.core.models.CreateSubnetDetails(
        compartment_id=compartment, vcn_id=VCN_OCID, display_name=SUBNET_NAME,
        cidr_block="10.0.0.0/24", route_table_id=rt.id, security_list_ids=[SL_OCID],
        dns_label="purproxysub",
    )).data
    print("  cree :", subnet.id)
    for _ in range(60):
        if vcn_client.get_subnet(subnet.id).data.lifecycle_state == "AVAILABLE":
            break
        time.sleep(2)
else:
    print("  reutilise :", subnet.id)
SUBNET_OCID = subnet.id

print("== [6/9] IP publique reservee ==")
ips = vcn_client.list_public_ips(compartment_id=compartment, scope="REGION").data
rip = None
for ip in ips:
    if getattr(ip, "display_name", None) == IP_NAME:
        rip = ip
        break
if rip is None:
    rip = vcn_client.create_public_ip(oci.core.models.CreatePublicIpDetails(
        compartment_id=compartment, lifetime="RESERVED", display_name=IP_NAME,
    )).data
    print("  creee :", rip.id)
else:
    print("  reutilisee :", rip.id)
RESERVED_IP_OCID = rip.id
PUBLIC_IP = rip.ip_address
print("  IP :", PUBLIC_IP)

# --------------------------------------------------------------------------- #
# 3. Image + instance
# --------------------------------------------------------------------------- #
ads = identity.list_availability_domains(compartment_id=tenancy).data
ad_name = _p("AVAILABILITY_DOMAIN", ads[0].name)
print("\n[info] AD choisi :", ad_name)

display_name = _p("DISPLAY_NAME", INSTANCE_NAME_DEFAULT)

print("== [7/9] Recherche de l'image Oracle Linux 9 (A1.Flex) ==")
images = compute.list_images(
    compartment_id=compartment, operating_system="Oracle Linux",
    operating_system_version="9", shape="VM.Standard.A1.Flex",
    sort_by="TIMECREATED", sort_order="DESC", limit=1,
).data
if not images:
    print("ERREUR : aucune image Oracle Linux 9 pour A1.Flex")
    sys.exit(1)
IMAGE_OCID = images[0].id
print("  image :", IMAGE_OCID)

# Instance existante ?
existing_instances = compute.list_instances(compartment_id=compartment, display_name=display_name).data
instance = None
for inst in existing_instances:
    if inst.lifecycle_state not in ("TERMINATED", "TERMINATING"):
        instance = inst
        break

if instance is None:
    print("== [8/9] Lancement de l'instance ==")
    cloud_init = """#cloud-config
packages:
  - nginx
  - python3
  - python3-pip
runcmd:
  - firewall-cmd --permanent --add-service=http
  - firewall-cmd --permanent --add-service=https
  - firewall-cmd --reload
  - setsebool -P httpd_can_network_connect on
  - python3 -m pip install certbot
  - systemctl enable nginx
  - systemctl start nginx
"""
    launch = compute.launch_instance(oci.core.models.LaunchInstanceDetails(
        compartment_id=compartment, display_name=display_name,
        shape="VM.Standard.A1.Flex",
        shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=1.0, memory_in_gbs=6.0),
        availability_domain=ad_name,
        source_details=oci.core.models.InstanceSourceViaImageDetails(
            source_type="image", image_id=IMAGE_OCID, boot_volume_size_in_gbs=50,
        ),
        create_vnic_details=oci.core.models.CreateVnicDetails(
            subnet_id=SUBNET_OCID, assign_public_ip=False, display_name="puridentity-proxy-vnic",
        ),
        metadata={"ssh_authorized_keys": pub_key, "user_data": base64.b64encode(cloud_init.encode()).decode()},
    )).data
    instance = launch
    print("  lancee :", instance.id)
    for _ in range(120):
        st = compute.get_instance(instance.id).data.lifecycle_state
        if st in ("RUNNING", "TERMINATED", "TERMINATING"):
            break
        time.sleep(5)
else:
    print("  instance existante reutilisee :", instance.id)
INSTANCE_OCID = instance.id
print("  etat :", compute.get_instance(INSTANCE_OCID).data.lifecycle_state)

print("== [9/9] Attachement de l'IP publique reservee ==")
# Trouver la VNIC principale
vnic_attachments = compute.list_vnic_attachments(compartment_id=compartment, instance_id=INSTANCE_OCID).data
if not vnic_attachments:
    print("  ATTENTION : pas de VNIC, attachez l'IP manuellement depuis la console.")
else:
    vnic_id = vnic_attachments[0].vnic_id
    private_ips = vcn_client.list_private_ips(vnic_id=vnic_id).data
    if not private_ips:
        print("  ATTENTION : aucune private IP sur la VNIC ; attachement manuel requis.")
    else:
        private_ip_id = private_ips[0].id
        try:
            vcn_client.update_public_ip(RESERVED_IP_OCID, oci.core.models.UpdatePublicIpDetails(
                private_ip_id=private_ip_id,
            ))
            print("  OK - IP", PUBLIC_IP, "attachée a la private IP", private_ip_id)
        except oci.exceptions.ServiceError as e:
            print("  info : attachement deja fait ou erreur mineure :", e.message)

# --------------------------------------------------------------------------- #
# Recap
# --------------------------------------------------------------------------- #
print("\n" + "=" * 70)
print("PROVISION TERMINEE")
print("=" * 70)
print("VCN_OCID         :", VCN_OCID)
print("SUBNET_OCID      :", SUBNET_OCID)
print("INSTANCE_OCID    :", INSTANCE_OCID)
print("RESERVED_IP_OCID :", RESERVED_IP_OCID)
print("PUBLIC_IP        :", PUBLIC_IP)
print("AVAILABILITY_DOMAIN:", ad_name)
print("\nProchaines etapes :")
print("  1. ssh opc@%s" % PUBLIC_IP)
print("  2. DuckDNS : voir runbook section 3 (~/duckdns/duck.sh)")
print("  3. certbot --key-type rsa -d <sous-domaine-duckdns>")
print("  4. cp certification/proxy/nginx-oracle.conf /etc/nginx/conf.d/puridentity.conf")
print("     sed -i 's/{HOSTNAME}/<sous-domaine>/g' /etc/nginx/conf.d/puridentity.conf")
print("  5. nginx -t && systemctl reload nginx")
print("  6. curl https://<sous-domaine>/.well-known/openid-configuration")
print("\nConserver les OCID ci-dessus pour le cleanup si besoin.")
