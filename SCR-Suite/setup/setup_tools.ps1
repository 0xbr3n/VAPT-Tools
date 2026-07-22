# ============================================================================
# SCR Automater — ONE-TIME tool download (run this on a machine WITH internet).
# NO client code is involved at this stage. Afterwards, copy the entire
# "SCR Automater" folder to the offline laptop and run setup\setup_offline.cmd
# there once (it recreates the Python venv from the downloaded wheels).
#
# Usage (from the SCR Automater folder):
#   powershell -ExecutionPolicy Bypass -File setup\setup_tools.ps1
#   powershell -ExecutionPolicy Bypass -File setup\setup_tools.ps1 -NvdApiKey "xxxx"
#
# -NvdApiKey is OPTIONAL: it only speeds up the one-time NVD database download
# for OWASP Dependency-Check (free key: https://nvd.nist.gov/developers/request-an-api-key).
# Without it the download still works, just slower (can take 30-60+ min).
# ============================================================================
param(
    [string]$NvdApiKey = "",
    [switch]$SkipDepCheckDb,   # skip the slow NVD download (you can rerun later)
    [switch]$SkipJre,
    [switch]$SkipSonar         # skip the optional sonar-scanner CLI download
)

$ErrorActionPreference = "Stop"
$Base  = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Base "tools"
# fall back to the saved key file if -NvdApiKey wasn't passed
if (-not $NvdApiKey) {
    $keyFile = Join-Path $PSScriptRoot "nvd_api_key.txt"
    if (Test-Path $keyFile) { $NvdApiKey = (Get-Content $keyFile -Raw).Trim() }
}
New-Item -ItemType Directory -Force $Tools | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

function Get-LatestAsset($repo, $pattern) {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
    $asset = $rel.assets | Where-Object { $_.name -like $pattern } | Select-Object -First 1
    if ($null -eq $asset) { throw "no asset matching '$pattern' in $repo latest release" }
    return $asset
}

function Download($url, $dest) {
    Write-Host "  downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

# ---------------------------------------------------------------- opengrep --
Step "Opengrep (Semgrep fork with native Windows binary) - main SAST engine"
try {
    $asset = Get-LatestAsset "opengrep/opengrep" "*windows*x86*.exe"
    Download $asset.browser_download_url (Join-Path $Tools "opengrep.exe")
} catch {
    Write-Warning "opengrep download failed: $_`nGet it manually from https://github.com/opengrep/opengrep/releases and save as tools\opengrep.exe"
}

# ------------------------------------------------------------- rules pack --
Step "Semgrep community rules pack (used by opengrep, fully local)"
$rulesZip = Join-Path $Tools "semgrep-rules.zip"
$rulesDir = Join-Path $Tools "semgrep-rules"
try {
    $repoInfo = Invoke-RestMethod "https://api.github.com/repos/semgrep/semgrep-rules" -UseBasicParsing
    $branch = $repoInfo.default_branch
    Download "https://github.com/semgrep/semgrep-rules/archive/refs/heads/$branch.zip" $rulesZip
    if (Test-Path $rulesDir) { Remove-Item -Recurse -Force $rulesDir }
    Expand-Archive $rulesZip -DestinationPath $rulesDir -Force
    Remove-Item $rulesZip
    # strip non-rule folders that only add scan time
    Get-ChildItem $rulesDir -Recurse -Directory | Where-Object { $_.Name -in @("stats", "scripts", ".github", "trusted_python") } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    # prune to actual rule files (opengrep aborts on non-rule YAMLs in the pack)
    $pyClean = Get-Command python -ErrorAction SilentlyContinue
    if ($pyClean) { & $pyClean.Source (Join-Path $PSScriptRoot "clean_rules.py") $rulesDir }
} catch {
    Write-Warning "rules download failed: $_"
}

# ---------------------------------------------------------------- gitleaks --
Step "Gitleaks (secrets scanner)"
try {
    $asset = Get-LatestAsset "gitleaks/gitleaks" "*windows*x64*.zip"
    $z = Join-Path $Tools "gitleaks.zip"
    Download $asset.browser_download_url $z
    Expand-Archive $z -DestinationPath (Join-Path $Tools "gitleaks-tmp") -Force
    Get-ChildItem (Join-Path $Tools "gitleaks-tmp") -Recurse -Filter "gitleaks.exe" |
        Select-Object -First 1 | Move-Item -Destination (Join-Path $Tools "gitleaks.exe") -Force
    Remove-Item $z; Remove-Item -Recurse -Force (Join-Path $Tools "gitleaks-tmp")
} catch { Write-Warning "gitleaks download failed: $_" }

# ------------------------------------------------------------------- trivy --
Step "Trivy (dependency/secret/misconfig scanner) + offline vulnerability DB"
try {
    $asset = Get-LatestAsset "aquasecurity/trivy" "*windows-64bit.zip"
    $z = Join-Path $Tools "trivy.zip"
    Download $asset.browser_download_url $z
    Expand-Archive $z -DestinationPath (Join-Path $Tools "trivy-tmp") -Force
    Get-ChildItem (Join-Path $Tools "trivy-tmp") -Recurse -Filter "trivy.exe" |
        Select-Object -First 1 | Move-Item -Destination (Join-Path $Tools "trivy.exe") -Force
    Remove-Item $z; Remove-Item -Recurse -Force (Join-Path $Tools "trivy-tmp")
    Write-Host "  downloading trivy vulnerability DB (offline cache)..."
    & (Join-Path $Tools "trivy.exe") image --download-db-only --cache-dir (Join-Path $Tools "trivy-cache")
    & (Join-Path $Tools "trivy.exe") image --download-java-db-only --cache-dir (Join-Path $Tools "trivy-cache")
} catch { Write-Warning "trivy setup failed: $_" }

# ------------------------------------------------------------------- grype --
Step "Grype (dependency / library CVE scanner) + its vulnerability DB"
try {
    $asset = Get-LatestAsset "anchore/grype" "*windows_amd64.zip"
    $z = Join-Path $Tools "grype.zip"
    Download $asset.browser_download_url $z
    Expand-Archive $z -DestinationPath (Join-Path $Tools "grype-tmp") -Force
    Get-ChildItem (Join-Path $Tools "grype-tmp") -Recurse -Filter "grype.exe" |
        Select-Object -First 1 | Move-Item -Destination (Join-Path $Tools "grype.exe") -Force
    Remove-Item $z; Remove-Item -Recurse -Force (Join-Path $Tools "grype-tmp")
    Write-Host "  downloading grype vulnerability DB (single archive, ~1.5 GB)..."
    # PowerShell passes a proper Windows path (no MSYS mangling), so the DB
    # lands in tools\grype-db where the scanner looks for it.
    $env:GRYPE_DB_CACHE_DIR = (Join-Path $Tools "grype-db")
    $env:GRYPE_DB_AUTO_UPDATE = "true"
    & (Join-Path $Tools "grype.exe") db update
    Write-Host "  grype ready (dependency-check is left OFF by default; grype is the primary SCA tool)"
} catch { Write-Warning "grype setup failed: $_" }

# --------------------------------------------------------------------- JRE --
if (-not $SkipJre) {
    Step "Portable JRE 17 (needed by OWASP Dependency-Check)"
    try {
        $jreZip = Join-Path $Tools "jre.zip"
        Download "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse" $jreZip
        Expand-Archive $jreZip -DestinationPath $Tools -Force
        Remove-Item $jreZip
        $jreDir = Get-ChildItem $Tools -Directory | Where-Object { $_.Name -like "jdk*jre*" -or $_.Name -like "jre*" } | Select-Object -First 1
        if ($jreDir -and $jreDir.Name -ne "jre17") { Rename-Item $jreDir.FullName (Join-Path $Tools "jre17") -Force }
    } catch { Write-Warning "JRE download failed: $_ (Dependency-Check will need system Java)" }
}

# -------------------------------------------------------- dependency-check --
Step "OWASP Dependency-Check"
try {
    $asset = Get-LatestAsset "dependency-check/DependencyCheck" "*release.zip"
    $z = Join-Path $Tools "depcheck.zip"
    Download $asset.browser_download_url $z
    Expand-Archive $z -DestinationPath $Tools -Force   # unpacks to tools\dependency-check
    Remove-Item $z
} catch {
    try {
        $asset = Get-LatestAsset "jeremylong/DependencyCheck" "*release.zip"
        $z = Join-Path $Tools "depcheck.zip"
        Download $asset.browser_download_url $z
        Expand-Archive $z -DestinationPath $Tools -Force
        Remove-Item $z
    } catch { Write-Warning "dependency-check download failed: $_" }
}

if (-not $SkipDepCheckDb) {
    Step "Dependency-Check NVD database (one-time; this is the slow part)"
    $dc = Join-Path $Tools "dependency-check\bin\dependency-check.bat"
    if (Test-Path $dc) {
        $jre = Join-Path $Tools "jre17"
        if (Test-Path $jre) { $env:JAVA_HOME = $jre }
        $args = @("--updateonly")
        if ($NvdApiKey) { $args += @("--nvdApiKey", $NvdApiKey) }
        else { Write-Host "  (no NVD API key supplied - download will be slow but works)" -ForegroundColor Yellow }
        & $dc @args
    } else { Write-Warning "dependency-check.bat not found - skipping DB update" }
}

# --------------------------------------------------------- sonar-scanner ----
if (-not $SkipSonar) {
    Step "sonar-scanner CLI (for the OPTIONAL local SonarQube adapter)"
    try {
        $api = Invoke-RestMethod "https://api.github.com/repos/SonarSource/sonar-scanner-cli/releases/latest" -UseBasicParsing
        $ver = $api.tag_name.TrimStart("v")
        $url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$ver-windows-x64.zip"
        $zip = Join-Path $Tools "sonar-scanner.zip"
        try { Invoke-WebRequest $url -OutFile $zip -UseBasicParsing }
        catch { Invoke-WebRequest ("https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$ver-windows.zip") -OutFile $zip -UseBasicParsing }
        Expand-Archive $zip -DestinationPath $Tools -Force
        Remove-Item $zip
        $sd = Get-ChildItem $Tools -Directory -Filter "sonar-scanner-*" | Select-Object -First 1
        if ($sd) {
            if (Test-Path (Join-Path $Tools "sonar-scanner")) { Remove-Item -Recurse -Force (Join-Path $Tools "sonar-scanner") }
            Rename-Item $sd.FullName (Join-Path $Tools "sonar-scanner") -Force
        }
        Write-Host "  sonar-scanner $ver installed (SonarQube itself is off by default; see run_sonarqube.cmd)"
    } catch { Write-Warning "sonar-scanner download failed: $_ (optional - SonarQube adapter stays off)" }
}

# ------------------------------------------------------------ python wheels --
Step "Python tool wheels (bandit + checkov) for offline install"
$Wheels = Join-Path $Tools "wheels"
New-Item -ItemType Directory -Force $Wheels | Out-Null
$py = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if ($py) {
    & $py.Source -m pip download bandit checkov pip setuptools wheel -d $Wheels
    Write-Host "  wheels saved to tools\wheels (installed on the offline machine by setup_offline.cmd)"
    # also install locally so this machine can run scans immediately
    & $py.Source -m venv (Join-Path $Base ".venv")
    & (Join-Path $Base ".venv\Scripts\python.exe") -m pip install --no-index --find-links $Wheels bandit checkov
} else {
    Write-Warning "Python not found on PATH - install Python 3.9+ then rerun this script"
}

Step "DONE"
Write-Host @"
Setup complete. Contents of tools\:
$((Get-ChildItem $Tools | Select-Object -ExpandProperty Name) -join "`n")

NEXT STEPS
 1. Copy the ENTIRE 'SCR Automater' folder to the offline machine (USB etc.)
 2. On the offline machine run:  setup\setup_offline.cmd   (once)
 3. Scan with:                   run_scan.cmd "C:\path\to\client\source"
No internet is needed ever again. Re-run this setup script every few months
(on the online machine) to refresh vulnerability databases and rules.
"@ -ForegroundColor Green
