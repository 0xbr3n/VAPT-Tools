# ============================================================================
# SCR Automater — refresh all vulnerability databases / rules to the LATEST.
# Run this on a machine WITH internet every few weeks, then re-copy the tools\
# folder to the offline laptop. NO client code is involved.
#
#   powershell -ExecutionPolicy Bypass -File setup\update_databases.ps1
#   powershell -ExecutionPolicy Bypass -File setup\update_databases.ps1 -NvdApiKey "xxxx"
#   powershell -ExecutionPolicy Bypass -File setup\update_databases.ps1 -Only trivy,rules
#
# Updates: Trivy vuln DB, Semgrep rules pack, OWASP Dependency-Check NVD DB,
#          sonar-scanner CLI, and (optionally) the SonarQube Docker image.
# ============================================================================
param(
    [string]$NvdApiKey = "",
    [string[]]$Only = @(),            # subset: trivy, rules, nvd, sonar, sonardocker
    [switch]$SonarDocker              # also `docker pull sonarqube:community`
)

$ErrorActionPreference = "Stop"
$Base  = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Base "tools"
# fall back to the saved key file if -NvdApiKey wasn't passed
if (-not $NvdApiKey) {
    $keyFile = Join-Path $PSScriptRoot "nvd_api_key.txt"
    if (Test-Path $keyFile) { $NvdApiKey = (Get-Content $keyFile -Raw).Trim() }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Want($name) { return ($Only.Count -eq 0) -or ($Only -contains $name) }

# ------------------------------------------------------------- Trivy DB -----
if (Want "trivy") {
    Step "Trivy vulnerability DB -> latest"
    $trivy = Join-Path $Tools "trivy.exe"
    if (Test-Path $trivy) {
        & $trivy image --download-db-only --cache-dir (Join-Path $Tools "trivy-cache")
        & $trivy image --download-java-db-only --cache-dir (Join-Path $Tools "trivy-cache")
        Write-Host "  trivy DB refreshed" -ForegroundColor Green
    } else { Write-Warning "trivy.exe not found - run setup_tools.ps1 first" }
}

# -------------------------------------------------------------- Grype DB ----
if (Want "grype") {
    Step "Grype vulnerability DB -> latest"
    $grype = Join-Path $Tools "grype.exe"
    if (Test-Path $grype) {
        $env:GRYPE_DB_CACHE_DIR = (Join-Path $Tools "grype-db")
        $env:GRYPE_DB_AUTO_UPDATE = "true"
        & $grype db update
        Write-Host "  grype DB refreshed" -ForegroundColor Green
    } else { Write-Warning "grype.exe not found - run setup_tools.ps1 first" }
}

# --------------------------------------------------------- Semgrep rules ----
if (Want "rules") {
    Step "Semgrep rules pack -> latest"
    try {
        $repoInfo = Invoke-RestMethod "https://api.github.com/repos/semgrep/semgrep-rules" -UseBasicParsing
        $branch = $repoInfo.default_branch
        $zip = Join-Path $Tools "semgrep-rules.zip"
        $dir = Join-Path $Tools "semgrep-rules"
        Invoke-WebRequest "https://github.com/semgrep/semgrep-rules/archive/refs/heads/$branch.zip" -OutFile $zip -UseBasicParsing
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
        Expand-Archive $zip -DestinationPath $dir -Force
        Remove-Item $zip
        $py = Get-Command python -ErrorAction SilentlyContinue
        if ($py) { & $py.Source (Join-Path $PSScriptRoot "clean_rules.py") $dir }
        Write-Host "  rules refreshed" -ForegroundColor Green
    } catch { Write-Warning "rules update failed: $_" }
}

# ------------------------------------------------------ Dependency-Check ----
if (Want "nvd") {
    Step "OWASP Dependency-Check NVD database -> latest"
    $dc = Join-Path $Tools "dependency-check\bin\dependency-check.bat"
    if (Test-Path $dc) {
        $jre = Join-Path $Tools "jre17"
        if (Test-Path $jre) { $env:JAVA_HOME = $jre }
        $a = @("--updateonly")
        if ($NvdApiKey) { $a += @("--nvdApiKey", $NvdApiKey); Write-Host "  using NVD API key (fast path)" -ForegroundColor Green }
        else { Write-Host "  no NVD API key - this can take 20-60+ min. Get a free key at" -ForegroundColor Yellow
               Write-Host "  https://nvd.nist.gov/developers/request-an-api-key and pass -NvdApiKey" -ForegroundColor Yellow }
        & $dc @a
        Write-Host "  NVD DB refreshed" -ForegroundColor Green
    } else { Write-Warning "dependency-check not found - run setup_tools.ps1 first" }
}

# ---------------------------------------------------------- sonar-scanner ---
if (Want "sonar") {
    Step "sonar-scanner CLI -> latest"
    try {
        $api = Invoke-RestMethod "https://api.github.com/repos/SonarSource/sonar-scanner-cli/releases/latest" -UseBasicParsing
        $ver = $api.tag_name.TrimStart("v")
        $url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$ver-windows-x64.zip"
        $zip = Join-Path $Tools "sonar-scanner.zip"
        try { Invoke-WebRequest $url -OutFile $zip -UseBasicParsing }
        catch {
            # older releases used a non -x64 artifact name
            $url = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$ver-windows.zip"
            Invoke-WebRequest $url -OutFile $zip -UseBasicParsing
        }
        Get-ChildItem $Tools -Directory -Filter "sonar-scanner-*" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Expand-Archive $zip -DestinationPath $Tools -Force
        Remove-Item $zip
        $sd = Get-ChildItem $Tools -Directory -Filter "sonar-scanner-*" | Select-Object -First 1
        if ($sd) {
            if (Test-Path (Join-Path $Tools "sonar-scanner")) { Remove-Item -Recurse -Force (Join-Path $Tools "sonar-scanner") }
            Rename-Item $sd.FullName (Join-Path $Tools "sonar-scanner") -Force
        }
        Write-Host "  sonar-scanner $ver installed to tools\sonar-scanner" -ForegroundColor Green
    } catch { Write-Warning "sonar-scanner update failed: $_" }
}

# -------------------------------------------------- SonarQube Docker image --
if ($SonarDocker -or ($Only -contains "sonardocker")) {
    Step "SonarQube Community Docker image -> latest"
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        & docker pull sonarqube:community
        # save an offline copy so it can be loaded on the air-gapped machine
        $tar = Join-Path $Tools "sonarqube-community.tar"
        & docker save sonarqube:community -o $tar
        Write-Host "  saved offline image to tools\sonarqube-community.tar" -ForegroundColor Green
        Write-Host "  on the offline machine:  docker load -i tools\sonarqube-community.tar" -ForegroundColor Green
    } else { Write-Warning "docker not found - skipping SonarQube image (install Docker Desktop)" }
}

Step "Update complete"
Write-Host "Re-copy the tools\ folder to the offline machine to deploy the refreshed data." -ForegroundColor Green
