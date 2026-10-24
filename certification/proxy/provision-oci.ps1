# provision-oci.ps1 — orchestrateur PowerShell pour la provision Oracle Cloud (Always Free)
#
# Prerequis :
#   - Python de la CLI OCI installe a %USERPROFILE%\lib\oracle-cli (fourni par
#     "oci setup config" ou l'installateur officiel). venv avec le module `oci`.
#   - Session OCI valide : %USERPROFILE%\.oci\sessions\DEFAULT\token non expire.
#     Renouveler si besoin : %USERPROFILE%\lib\oracle-cli\Scripts\python.exe -m oci_cli session authenticate
#   - Variables d'environnement optionnelles :
#       $env:TENANCY_OCID   (defaut : lu depuis ~/.oci/config)
#       $env:REGION         (defaut : eu-marseille-1)
#       $env:DISPLAY_NAME   (defaut : puridentity-mtls-proxy)
#       $env:AVAILABILITY_DOMAIN (defaut : auto-selection AD-1)
#
# Usage :
#   pwsh -NoProfile -File certification\proxy\provision-oci.ps1
#   # ou, depuis PowerShell standard :
#   .\certification\proxy\provision-oci.ps1
#
# Le script delegue le travail a provision_oci.py (SDK Python OCI), qui
# contourne le bug de lancement de oci.exe (module Microsoft.PowerShell.Security)
# dans les environnements restreints.

$ErrorActionPreference = "Stop"

# chemin du venv OCI
$OciPython = "$env:USERPROFILE\lib\oracle-cli\Scripts\python.exe"
if (-not (Test-Path $OciPython)) {
    Write-Error "Python OCI introuvable : $OciPython. Installez la CLI OCI (python3 + module oci)."
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript  = Join-Path $ScriptDir "provision_oci.py"
if (-not (Test-Path $PyScript)) {
    Write-Error "Script Python introuvable : $PyScript"
    exit 1
}

# verification de session
$tokenFile = "$env:USERPROFILE\.oci\sessions\DEFAULT\token"
if (-not (Test-Path $tokenFile)) {
    Write-Host "Session OCI absente. Authentification interactive..." -ForegroundColor Yellow
    & $OciPython -m oci_cli session authenticate --profile-name DEFAULT 2>&1 | Out-Null
}

Write-Host "Demarrage de la provision OCI (region / tenancy lus depuis ~/.oci/config)..." -ForegroundColor Cyan
& $OciPython $PyScript
$rc = $LASTEXITCODE
if ($rc -ne 0) {
    Write-Host "Echec (code $rc). Voir la sortie ci-dessus." -ForegroundColor Red
    exit $rc
}
Write-Host "Provision terminee. Lisez les sorties PUBLIC_IP/INSTANCE_OCID pour la suite (DuckDNS, certbot, nginx)." -ForegroundColor Green
