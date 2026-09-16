# NothingDNS Windows Installation Script
# Downloads latest release, creates config, and sets up the server

param(
    [string]$InstallPath = "$env:ProgramFiles\NothingDNS",
    # Canonical config name (matches the server default nothingdns.yaml)
    [string]$ConfigPath = "$env:ProgramData\NothingDNS\nothingdns.yaml"
)

$ErrorActionPreference = "Stop"

# Backward compatibility: legacy installs (pre-v1.0.0) used config.yaml. If only
# the legacy file exists, keep using it; new installs get nothingdns.yaml.
$LEGACY_CONFIG_PATH = "$env:ProgramData\NothingDNS\config.yaml"
if (!$PSBoundParameters.ContainsKey('ConfigPath') -and
    !(Test-Path $ConfigPath) -and (Test-Path $LEGACY_CONFIG_PATH)) {
    $ConfigPath = $LEGACY_CONFIG_PATH
}

$REPO = "NothingDNS/NothingDNS"
$BINARY_NAME = "nothingdns"
$DNSCTL_NAME = "dnsctl"

# Release assets are verified against the published SHA256SUMS by default. This
# is the integrity control that stops a hijacked/MITM'd release from achieving
# code execution (the binaries are installed and run with admin rights).
# Override only in trusted/offline environments: $env:NOTHINGDNS_SKIP_CHECKSUM = '1'.
$SKIP_CHECKSUM = ($env:NOTHINGDNS_SKIP_CHECKSUM -eq '1')
$CHECKSUMS_PATH = $null

# Colors
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Green }
function Write-Warn($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Err($message) { Write-Host "[ERROR] $message" -ForegroundColor Red; exit 1 }

# Download the release SHA256SUMS once. Fails closed unless the operator
# explicitly opted out via NOTHINGDNS_SKIP_CHECKSUM=1 (mirrors install.sh).
function Fetch-Checksums {
    param($Assets)

    if ($script:SKIP_CHECKSUM) {
        Write-Warn "=========================================================="
        Write-Warn " NOTHINGDNS_SKIP_CHECKSUM=1"
        Write-Warn " Release integrity verification is DISABLED."
        Write-Warn " Downloaded binaries will NOT be checked against SHA256SUMS."
        Write-Warn "=========================================================="
        return
    }

    $url = $Assets | Where-Object { $_.name -eq "SHA256SUMS" } | Select-Object -First 1 -ExpandProperty browser_download_url
    if (!$url) {
        Write-Err "SHA256SUMS not found in the release assets. Refusing to install unverified binaries; set `$env:NOTHINGDNS_SKIP_CHECKSUM = '1' to bypass (NOT recommended)."
    }

    $script:CHECKSUMS_PATH = Join-Path $env:TEMP "nothingdns-SHA256SUMS-$PID.txt"
    try {
        Invoke-WebRequest -Uri $url -OutFile $script:CHECKSUMS_PATH -UseBasicParsing | Out-Null
    } catch {
        Write-Err "Could not download release checksums ($url): $_. Refusing to install unverified binaries; set `$env:NOTHINGDNS_SKIP_CHECKSUM = '1' to bypass (NOT recommended)."
    }
}

# Verify a downloaded file against the published checksum for the given asset
# name. Aborts on mismatch or a missing entry (fail-closed).
function Verify-Checksum {
    param([string]$File, [string]$Asset)

    if ($script:SKIP_CHECKSUM) { return }

    $pattern = "\s\*?" + [regex]::Escape($Asset) + "$"
    $entry = Select-String -Path $script:CHECKSUMS_PATH -Pattern $pattern | Select-Object -First 1
    if (!$entry) {
        Write-Err "No checksum entry for $Asset in SHA256SUMS - refusing to install."
    }
    $expected = ($entry.Line.Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Write-Err "Checksum mismatch for ${Asset}: expected $expected, got $actual. Aborting - the download may be corrupt or tampered with."
    }
    Write-Info "Verified $Asset (sha256 $actual)"
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  NothingDNS Install Script v1.1" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Detect architecture
$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "arm64" }
$PLATFORM = "windows-$ARCH"

Write-Info "Platform: $PLATFORM"

# Get latest release
Write-Info "Fetching latest release info..."
$RELEASE_URL = "https://api.github.com/repos/$REPO/releases/latest"
try {
    $RELEASE = Invoke-RestMethod -Uri $RELEASE_URL -UseBasicParsing
    $VERSION = $RELEASE.tag_name
    $ASSETS = $RELEASE.assets
} catch {
    Write-Err "Could not fetch latest release: $_"
}
Write-Info "Latest version: $VERSION"

# Create install directory
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}
Write-Info "Install directory: $InstallPath"

# Fetch the release checksums before downloading any binary (fail-closed)
Fetch-Checksums -Assets $ASSETS

# Download binary
$BINARY_URL = $ASSETS | Where-Object { $_.name -eq "$BINARY_NAME-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if (!$BINARY_URL) {
    Write-Err "Binary not found for $PLATFORM"
}

Write-Info "Downloading nothingdns..."
$BINARY_PATH = "$InstallPath\$BINARY_NAME.exe"
$BINARY_TEMP = Join-Path $env:TEMP "$BINARY_NAME-$PLATFORM-$PID.exe"
Invoke-WebRequest -Uri $BINARY_URL -OutFile $BINARY_TEMP -UseBasicParsing | Out-Null
Verify-Checksum -File $BINARY_TEMP -Asset "$BINARY_NAME-$PLATFORM.exe"
Move-Item -Path $BINARY_TEMP -Destination $BINARY_PATH -Force
Write-Info "Downloaded to $BINARY_PATH"

# Download dnsctl
$DNSCTL_URL = $ASSETS | Where-Object { $_.name -eq "$DNSCTL_NAME-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if ($DNSCTL_URL) {
    Write-Info "Downloading dnsctl..."
    $DNSCTL_PATH = "$InstallPath\$DNSCTL_NAME.exe"
    $DNSCTL_TEMP = Join-Path $env:TEMP "$DNSCTL_NAME-$PLATFORM-$PID.exe"
    Invoke-WebRequest -Uri $DNSCTL_URL -OutFile $DNSCTL_TEMP -UseBasicParsing | Out-Null
    Verify-Checksum -File $DNSCTL_TEMP -Asset "$DNSCTL_NAME-$PLATFORM.exe"
    Move-Item -Path $DNSCTL_TEMP -Destination $DNSCTL_PATH -Force
    Write-Info "Downloaded to $DNSCTL_PATH"
}

# Clean up the downloaded checksums file
if ($CHECKSUMS_PATH -and (Test-Path $CHECKSUMS_PATH)) {
    Remove-Item -Path $CHECKSUMS_PATH -Force -ErrorAction SilentlyContinue
}

# Create default config
function Create-DefaultConfig {
    param([string]$Path)

    $CONFIG_DIR = Split-Path $Path -Parent
    if (!(Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
    }

    if (Test-Path $Path) {
        Write-Warn "Config already exists at $Path"
        $overwrite = Read-Host "Overwrite? (y/N)"
        if ($overwrite -ne "y" -and $overwrite -ne "Y") {
            Write-Info "Keeping existing config"
            return
        }
    }

    Write-Info "Creating default config at $Path..."

    # Generate a random auth secret
    # RandomNumberGenerator.GetBytes(int) is .NET 6+ only; Windows PowerShell 5.1
    # runs on .NET Framework, so fill a buffer through an RNG instance instead.
    $secretBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($secretBytes)
    $rng.Dispose()
    $AUTH_SECRET = [System.Convert]::ToBase64String($secretBytes)
    $DATA_DIR_YAML = ("$env:ProgramData\NothingDNS\data" -replace '\\', '/')

    $CONFIG = @"
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")

server:
  port: 53
  bind:
    - 0.0.0.0
    - "::"
  # Web dashboard and REST API on every interface. Restrict it with the
  # Windows firewall or a TLS reverse proxy on untrusted networks.
  http:
    enabled: true
    bind: "0.0.0.0:8080"
    auth_secret: "${AUTH_SECRET}"

upstream:
  strategy: round_robin
  servers:
    - 1.1.1.1:53
    - 8.8.8.8:53
    - 8.8.4.4:53
  health_check: 30s

cache:
  enabled: true
  size: 10000
  default_ttl: 3600
  max_ttl: 86400
  min_ttl: 300
  negative_ttl: 60
  prefetch: true
  prefetch_threshold: 60
  serve_stale: true
  stale_grace_secs: 86400

dnssec:
  enabled: true

logging:
  level: info
  format: text
  output: stdout
  query_log: false

# Prometheus metrics. Without auth_token the endpoint may only listen on
# loopback; set auth_token before binding it to a reachable address.
metrics:
  enabled: true
  bind: "127.0.0.1:9153"
  path: /metrics

# Zone database, IXFR journals and dashboard users (users.json).
storage:
  data_dir: "${DATA_DIR_YAML}"

# Answer only loopback and private networks, so the server is not an open
# resolver. Add your public client ranges here if needed.
acl:
  - name: allow-local-networks
    action: allow
    networks:
      - 127.0.0.0/8
      - ::1/128
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - fc00::/7

rrl:
  enabled: true
  rate: 100
  burst: 200

cookie:
  enabled: true

zones: []
transfer:
  allow_list: []
  require_tsig: false
cluster:
  enabled: false
"@

    # UTF-8 without a byte order mark (Out-File -Encoding UTF8 adds one in
    # Windows PowerShell 5.1).
    [System.IO.File]::WriteAllText($Path, $CONFIG, (New-Object System.Text.UTF8Encoding $false))
    Write-Info "Config created at $Path"
    # Persist the API auth secret to an Administrators-only file rather than
    # echoing it to stdout, which can leak into terminal scrollback or logs
    # (mirrors install.sh's root-only credentials file).
    $CREDENTIALS_PATH = Join-Path $CONFIG_DIR "credentials"
    "api_auth_secret: $AUTH_SECRET" | Out-File -FilePath $CREDENTIALS_PATH -Encoding UTF8
    Protect-CredentialsFile -Path $CREDENTIALS_PATH
    Write-Info "API auth secret saved to $CREDENTIALS_PATH (Administrators only)."
    Write-Info "Retrieve with: Get-Content $CREDENTIALS_PATH (as Administrator)"
}

# Restrict a file to Administrators + SYSTEM only (no inherited ACEs), the
# Windows equivalent of install.sh's chmod 600 root-only credentials file.
function Protect-CredentialsFile {
    param([string]$Path)

    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)  # drop inherited ACEs
    foreach ($rule in @($acl.Access)) {
        $acl.RemoveAccessRule($rule) | Out-Null
    }
    $admins = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $system = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    foreach ($sid in @($admins, $system)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

# Create data directory
$DATA_DIR = "$env:ProgramData\NothingDNS\data"
if (!(Test-Path $DATA_DIR)) {
    New-Item -ItemType Directory -Path $DATA_DIR -Force | Out-Null
}

Create-DefaultConfig -Path $ConfigPath

# Check the config with the installed binary before telling the user to start it.
& $BINARY_PATH -config $ConfigPath -validate-config
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Config validation failed - fix $ConfigPath before starting the server"
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit config: notepad $ConfigPath"
Write-Host "  2. Start server:"
Write-Host "       & '$BINARY_PATH' -config '$ConfigPath'"
Write-Host "  3. Create the dashboard admin (on this machine):"
Write-Host "       Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/auth/bootstrap -ContentType 'application/json' -Body '{`"username`":`"admin`",`"password`":`"<strong-password>`"}'"
Write-Host ""
Write-Host "Dashboard: http://<this-host>:8080"
Write-Host ""
Write-Host "To run as Windows Service, install NSSM:"
Write-Host "  choco install nssm"
Write-Host "  nssm install NothingDNS `"$BINARY_PATH`" -config `"$ConfigPath`""
Write-Host "  nssm set NothingDNS AppDirectory `"$DATA_DIR`""
Write-Host "  nssm start NothingDNS"
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
