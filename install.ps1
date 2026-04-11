# NothingDNS Windows Installation Script
# Downloads latest release, creates config, and sets up the server

param(
    [string]$InstallPath = "$env:ProgramFiles\NothingDNS",
    [string]$ConfigPath = "$env:ProgramData\NothingDNS\config.yaml"
)

$ErrorActionPreference = "Stop"

$REPO = "NothingDNS/NothingDNS"
$BINARY_NAME = "nothingdns"

# Colors
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Green }
function Write-Warn($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Err($message) { Write-Host "[ERROR] $message" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  NothingDNS Install Script v1.0" -ForegroundColor Cyan
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

# Download binary
$BINARY_URL = $ASSETS | Where-Object { $_.name -eq "$BINARY_NAME-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if (!$BINARY_URL) {
    Write-Err "Binary not found for $PLATFORM"
}

Write-Info "Downloading nothingdns..."
$BINARY_PATH = "$InstallPath\$BINARY_NAME.exe"
Invoke-WebRequest -Uri $BINARY_URL -OutFile $BINARY_PATH -UseBasicParsing | Out-Null
Write-Info "Downloaded to $BINARY_PATH"

# Download dnsctl
$DNSCTL_URL = $ASSETS | Where-Object { $_.name -eq "dnsctl-$PLATFORM.exe" } | Select-Object -First 1 -ExpandProperty browser_download_url
if ($DNSCTL_URL) {
    Write-Info "Downloading dnsctl..."
    $DNSCTL_PATH = "$InstallPath\dnsctl.exe"
    Invoke-WebRequest -Uri $DNSCTL_URL -OutFile $DNSCTL_PATH -UseBasicParsing | Out-Null
    Write-Info "Downloaded to $DNSCTL_PATH"
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

    $CONFIG = @"
# NothingDNS Configuration
# https://github.com/NothingDNS/NothingDNS

# Server listen address (UDP/TCP DNS)
listen: "0.0.0.0:53"

# HTTP API/Dashboard address
http_addr: "0.0.0.0:8080"

# Data directory
data_dir: "./data"

# Authentication secret (change this!)
# Generate with: [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32) | ForEach-Object { [System.Convert]::ToBase64String($_) }
auth_secret: "CHANGE_ME_generate_with_openssl_rand_base64_32"

# Zones (authoritative)
zones: []

# Upstream resolvers (for recursion)
upstream:
  - "8.8.8.8:53"
  - "8.8.4.4:53"
  - "1.1.1.1:53"

# DNSSEC validation
dnssec:
  enabled: true
  validation: "strict"

# Log level (debug, info, warn, error)
log_level: "info"

# Cache settings
cache:
  size: 10000
  ttl: 300
"@

    $CONFIG | Out-File -FilePath $Path -Encoding UTF8
    Write-Info "Config created at $Path"
    Write-Warn "Please edit $Path and set auth_secret!"
}

Create-DefaultConfig -Path $ConfigPath

# Create data directory
$DATA_DIR = "$env:ProgramData\NothingDNS\data"
if (!(Test-Path $DATA_DIR)) {
    New-Item -ItemType Directory -Path $DATA_DIR -Force | Out-Null
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit config: notepad $ConfigPath"
Write-Host "  2. Start server:"
Write-Host "       $BINARY_PATH --config $ConfigPath"
Write-Host ""
Write-Host "Dashboard: http://localhost:8080"
Write-Host ""
Write-Host "To run as Windows Service, install NSSM:"
Write-Host "  choco install nssm"
Write-Host "  nssm install NothingDNS $BINARY_PATH '--config $ConfigPath'"
Write-Host "  nssm start NothingDNS"
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
