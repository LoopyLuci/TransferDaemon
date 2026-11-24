#Requires -Version 7
<#
.SYNOPSIS
  Build the TransferDaemon Windows MSI installer.

.DESCRIPTION
  1. Builds all Rust binaries in release mode.
  2. Runs WiX 4 to produce dist\TransferDaemon-1.0.0.msi.

  Requires:
    - Rust toolchain (cargo on PATH)
    - WiX 4 dotnet global tool  (`dotnet tool install -g wix`)

.EXAMPLE
  cd installer\windows
  .\build.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$VERSION  = "1.0.0"
$ROOT     = Resolve-Path "$PSScriptRoot\..\.."   # workspace root
$DIST     = "$ROOT\dist"
$MSI_OUT  = "$DIST\TransferDaemon-$VERSION.msi"

# ── Ensure dist directory exists ─────────────────────────────────────────────
New-Item -ItemType Directory -Force $DIST | Out-Null

# ── Locate tools ─────────────────────────────────────────────────────────────
$cargo = (Get-Command cargo -ErrorAction SilentlyContinue)?.Source
if (-not $cargo) {
    # Rust is installed per-user; try the default location.
    $cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
    if (-not (Test-Path $cargo)) {
        throw "cargo not found. Install Rust from https://rustup.rs"
    }
}

$wix = (Get-Command wix -ErrorAction SilentlyContinue)?.Source
if (-not $wix) {
    $wix = "$env:USERPROFILE\.dotnet\tools\wix.exe"
    if (-not (Test-Path $wix)) {
        throw "WiX 4 not found. Run: dotnet tool install -g wix"
    }
}

Write-Host "cargo : $cargo"
Write-Host "wix   : $wix"
Write-Host "output: $MSI_OUT"
Write-Host ""

# ── Build release binaries ────────────────────────────────────────────────────
Write-Host "==> Building release binaries..." -ForegroundColor Cyan
Push-Location $ROOT
try {
    & $cargo build --release `
        -p transferd `
        -p transferd-ui `
        -p transferd-tui `
        -p launcher
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# ── Verify all binaries exist ─────────────────────────────────────────────────
$binaries = @(
    "$ROOT\target\release\transferd.exe",
    "$ROOT\target\release\transferd-ui.exe",
    "$ROOT\target\release\transferd-tui.exe",
    "$ROOT\target\release\launcher.exe"
)
foreach ($b in $binaries) {
    if (-not (Test-Path $b)) { throw "Expected binary not found: $b" }
    $sz = [math]::Round((Get-Item $b).Length / 1MB, 1)
    Write-Host "  OK  $([IO.Path]::GetFileName($b))  ($sz MB)"
}
Write-Host ""

# ── Build MSI ────────────────────────────────────────────────────────────────
Write-Host "==> Building MSI..." -ForegroundColor Cyan
Push-Location $PSScriptRoot
try {
    # Accept the WiX 7 OSMF EULA (idempotent — safe to run every build).
    & $wix eula accept wix7 | Out-Null
    & $wix build TransferDaemon.wxs -o $MSI_OUT
    if ($LASTEXITCODE -ne 0) { throw "wix build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# ── Report ────────────────────────────────────────────────────────────────────
$msiSize = [math]::Round((Get-Item $MSI_OUT).Length / 1MB, 1)
Write-Host ""
Write-Host "==> SUCCESS" -ForegroundColor Green
Write-Host "    $MSI_OUT  ($msiSize MB)"
Write-Host ""
Write-Host "To install (requires admin):"
Write-Host "    msiexec /i `"$MSI_OUT`" /qb"
Write-Host ""
Write-Host "To sign (requires a code-signing cert):"
Write-Host "    signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 `"$MSI_OUT`""
