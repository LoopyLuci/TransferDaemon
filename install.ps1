# TransferDaemon all-in-one installer for Windows.
# Run from an elevated PowerShell prompt:
#   Set-ExecutionPolicy Bypass -Scope Process -Force; .\install.ps1
# Idempotent — safe to run multiple times.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR }
              else { Join-Path $env:LOCALAPPDATA "TransferDaemon\bin" }
$DaemonAddr = if ($env:TRANSFERD_ADDR) { $env:TRANSFERD_ADDR }
              else { "http://127.0.0.1:50051" }
$AppName    = "TransferDaemon"

function Write-Banner([string]$msg) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════"
    Write-Host "  $msg"
    Write-Host "═══════════════════════════════════════════"
}

Write-Banner "$AppName — Windows Installer"

# ── 1. Rust toolchain ────────────────────────────────────────────────────────
$rustup = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustup) {
    Write-Host "► Rust not found — installing via winget…"
    winget install --id Rustlang.Rustup --silent --accept-package-agreements --accept-source-agreements
    # Reload PATH so cargo/rustup are visible in this session.
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
} else {
    Write-Host "► Rust already present ($((rustup show active-toolchain) | Select-Object -First 1))"
}
rustup default stable
rustup update

# ── 2. protobuf compiler (required by tonic-build) ───────────────────────────
$protoc = Get-Command protoc -ErrorAction SilentlyContinue
if (-not $protoc) {
    Write-Host "► Installing protoc via winget…"
    winget install --id Google.Protobuf --silent --accept-package-agreements --accept-source-agreements
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
} else {
    Write-Host "► protoc already present ($((protoc --version)))"
}

# ── 3. Build ─────────────────────────────────────────────────────────────────
Write-Host "► Building TransferDaemon (release)…"
Set-Location (Join-Path $RepoDir "transferdaemon")
cargo build --release -p transferd -p transferd-ui -p launcher
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
Write-Host "  Build complete."

# ── 4. Install binaries ──────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Write-Host "► Installing to $InstallDir…"

Copy-Item -Force "target\release\transferd.exe"    "$InstallDir\transferd.exe"
Copy-Item -Force "target\release\transferd-ui.exe" "$InstallDir\transferd-ui.exe"
Copy-Item -Force "target\release\launcher.exe"     "$InstallDir\transferdaemon.exe"
if (Test-Path "target\release\relayd.exe") {
    Copy-Item -Force "target\release\relayd.exe" "$InstallDir\relayd.exe"
}

# Add InstallDir to user PATH persistently if not already present.
$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $InstallDir })) {
    [System.Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
    $env:PATH = "$InstallDir;$env:PATH"
    Write-Host "  Added $InstallDir to user PATH."
}

# ── 5. Scheduled task for daemon autostart ───────────────────────────────────
Write-Host "► Creating scheduled task for daemon autostart…"
$taskName   = "TransferDaemon_Daemon"
$taskAction = New-ScheduledTaskAction `
    -Execute "$InstallDir\transferd.exe" `
    -WorkingDirectory $InstallDir
$taskAction.EnvironmentVariables = @{ TRANSFERD_ADDR = $DaemonAddr }

$taskTrigger   = New-ScheduledTaskTrigger -AtLogon
$taskSettings  = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([timespan]::Zero)   # no time limit
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Highest

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask `
    -TaskName  $taskName `
    -Action    $taskAction `
    -Trigger   $taskTrigger `
    -Settings  $taskSettings `
    -Principal $taskPrincipal `
    -Force | Out-Null

# Start the daemon now without waiting.
Start-ScheduledTask -TaskName $taskName
Write-Host "  Scheduled task '$taskName' registered and started."

# ── 6. Start Menu shortcut ───────────────────────────────────────────────────
Write-Host "► Creating Start Menu shortcut…"
$startMenu  = [System.Environment]::GetFolderPath("StartMenu")
$shortcutPath = Join-Path $startMenu "Programs\TransferDaemon.lnk"
$shell      = New-Object -ComObject WScript.Shell
$shortcut   = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath   = "$InstallDir\transferdaemon.exe"
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description  = "Universal, private, zero-knowledge data transfer"
# Use the exe icon if no separate icon file exists.
$iconPath = Join-Path $RepoDir "assets\icon.ico"
if (Test-Path $iconPath) { $shortcut.IconLocation = $iconPath }
else { $shortcut.IconLocation = "$InstallDir\transferdaemon.exe,0" }
$shortcut.Save()
Write-Host "  Start Menu shortcut created at $shortcutPath"

# ── 7. Optional: Windows Firewall rule ───────────────────────────────────────
$ruleName = "TransferDaemon_gRPC"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction   Inbound `
        -Protocol    TCP `
        -LocalPort   50051 `
        -Action      Allow `
        -Profile     Private,Domain | Out-Null
    Write-Host "  Firewall rule '$ruleName' added (TCP 50051, inbound, private/domain)."
}

# ── 8. Done ──────────────────────────────────────────────────────────────────
Write-Banner "Installation complete!"
Write-Host "  Run:           transferdaemon"
Write-Host "  Or click the   TransferDaemon shortcut in the Start Menu."
Write-Host ""
Write-Host "  Daemon address: $DaemonAddr"
Write-Host "  Binaries:       $InstallDir\"
Write-Host ""
