# TransferDaemon all-in-one installer for Windows.
# Places all binaries in <project-root>\bin\ and creates
# <project-root>\TransferDaemon.exe as the user-facing entry point.
# Keeps the last 10 installer runs in logs\installer_log_N.log.
# No system-wide install, no PATH modification required.
#
# Run from an elevated PowerShell prompt:
#   Set-ExecutionPolicy Bypass -Scope Process -Force; .\install.ps1
# Idempotent — safe to run multiple times.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinDir     = Join-Path $RepoDir "bin"
$DaemonAddr = if ($env:TRANSFERD_ADDR) { $env:TRANSFERD_ADDR }
              else { "http://127.0.0.1:50051" }
$AppName    = "TransferDaemon"

function Write-Banner([string]$msg) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════"
    Write-Host "  $msg"
    Write-Host "═══════════════════════════════════════════"
}

# ── Log rotation ──────────────────────────────────────────────────────────────
$LogDir  = Join-Path $RepoDir "logs"
$MaxLogs = 10
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

for ($i = $MaxLogs - 1; $i -ge 0; $i--) {
    $old = Join-Path $LogDir "installer_log_$i.log"
    if (Test-Path $old) {
        if ($i -lt $MaxLogs - 1) {
            Move-Item -Force $old (Join-Path $LogDir "installer_log_$($i+1).log")
        } else {
            Remove-Item -Force $old
        }
    }
}
$LogFile = Join-Path $LogDir "installer_log_0.log"
# Start-Transcript captures all console output (Write-Host, errors, native exe output).
Start-Transcript -Path $LogFile -Append | Out-Null
Write-Host "Installer started at $(Get-Date)"

Write-Banner "$AppName — Windows Installer"

# ── 1. Rust toolchain ────────────────────────────────────────────────────────
$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

$rustup = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustup) {
    Write-Host "► Rust not found — installing via rustup-init…"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install --id Rustlang.Rustup --silent --accept-package-agreements --accept-source-agreements
    } else {
        Write-Host "  winget not available — downloading rustup-init.exe…"
        $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
        & $rustupInit -y --no-modify-path
    }
    $env:PATH = "$cargoBin;" +
                [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
} else {
    Write-Host "► Rust already present ($((rustup show active-toolchain) | Select-Object -First 1))"
}
rustup default stable
rustup update

# ── 2. protobuf compiler (required by tonic-build) ───────────────────────────
$protoc = Get-Command protoc -ErrorAction SilentlyContinue
if (-not $protoc) {
    Write-Host "► Installing protoc…"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install --id Google.Protobuf --silent --accept-package-agreements --accept-source-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
    } else {
        Write-Host "  winget not available — downloading protoc from GitHub releases…"
        $protocVersion = "29.3"
        $protocZip  = Join-Path $env:TEMP "protoc.zip"
        $protocDir  = Join-Path $env:TEMP "protoc"
        $protocUrl  = "https://github.com/protocolbuffers/protobuf/releases/download/v$protocVersion/protoc-$protocVersion-win64.zip"
        Invoke-WebRequest -Uri $protocUrl -OutFile $protocZip -UseBasicParsing
        Expand-Archive -Path $protocZip -DestinationPath $protocDir -Force
        $protocBin = Join-Path $protocDir "bin"
        $env:PATH = "$protocBin;$env:PATH"
        $userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        if (-not ($userPath -split ";" | Where-Object { $_ -eq $protocBin })) {
            [System.Environment]::SetEnvironmentVariable("PATH", "$protocBin;$userPath", "User")
        }
        Write-Host "  protoc installed to $protocBin"
    }
} else {
    Write-Host "► protoc already present ($((protoc --version)))"
}

# ── 3. Build ─────────────────────────────────────────────────────────────────
Write-Host "► Building TransferDaemon (release)…"
Set-Location (Join-Path $RepoDir "transferdaemon")
cargo build --release -p transferd -p transferd-ui -p launcher
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
Write-Host "  Build complete."

# ── 4. Install binaries into <root>\bin\ ─────────────────────────────────────
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Write-Host "► Installing binaries to $BinDir…"

Copy-Item -Force "target\release\transferd.exe"    "$BinDir\transferd.exe"
Copy-Item -Force "target\release\transferd-ui.exe" "$BinDir\transferd-ui.exe"
Copy-Item -Force "target\release\launcher.exe"     "$BinDir\launcher.exe"
if (Test-Path "target\release\relayd.exe") {
    Copy-Item -Force "target\release\relayd.exe"   "$BinDir\relayd.exe"
}

# ── 5. Root-level entry point ─────────────────────────────────────────────────
$rootExe = Join-Path $RepoDir "TransferDaemon.exe"
Copy-Item -Force "$BinDir\launcher.exe" $rootExe
Write-Host "  Entry point: $rootExe"

# ── 6. Persist daemon address ─────────────────────────────────────────────────
[System.Environment]::SetEnvironmentVariable("TRANSFERD_ADDR", $DaemonAddr, "User")
$env:TRANSFERD_ADDR = $DaemonAddr
Write-Host "  TRANSFERD_ADDR set to $DaemonAddr (user environment)"

# ── 7. Scheduled task for daemon autostart ────────────────────────────────────
Write-Host "► Creating scheduled task for daemon autostart…"
$taskName   = "TransferDaemon_Daemon"
$taskAction = New-ScheduledTaskAction `
    -Execute   "$BinDir\transferd.exe" `
    -WorkingDirectory $BinDir

$taskTrigger   = New-ScheduledTaskTrigger -AtLogon
$taskSettings  = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([timespan]::Zero)
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

Start-ScheduledTask -TaskName $taskName
Write-Host "  Scheduled task '$taskName' registered and started."

# ── 8. Start Menu shortcut ────────────────────────────────────────────────────
Write-Host "► Creating Start Menu shortcut…"
$startMenu    = [System.Environment]::GetFolderPath("StartMenu")
$shortcutPath = Join-Path $startMenu "Programs\TransferDaemon.lnk"
$shell        = New-Object -ComObject WScript.Shell
$shortcut     = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath      = $rootExe
$shortcut.WorkingDirectory = $RepoDir
$shortcut.Description     = "Universal, private, zero-knowledge data transfer"
$iconPath = Join-Path $RepoDir "assets\icon.ico"
if (Test-Path $iconPath) { $shortcut.IconLocation = $iconPath }
else                      { $shortcut.IconLocation = "$rootExe,0" }
$shortcut.Save()
Write-Host "  Start Menu shortcut created at $shortcutPath"

# ── 9. Windows Firewall rule ──────────────────────────────────────────────────
$ruleName = "TransferDaemon_gRPC"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction   Inbound `
        -Protocol    TCP `
        -LocalPort   50051 `
        -Action      Allow `
        -Profile     Private,Domain | Out-Null
    Write-Host "  Firewall rule '$ruleName' added (TCP 50051, inbound, private/domain)."
}

# ── 10. Done ──────────────────────────────────────────────────────────────────
Write-Banner "Installation complete!"
Write-Host "  Double-click:  $rootExe"
Write-Host "  Or run:        .\TransferDaemon.exe"
Write-Host "  Or click the   TransferDaemon shortcut in the Start Menu."
Write-Host ""
Write-Host "  Daemon address: $DaemonAddr"
Write-Host "  Binaries:       $BinDir\"
Write-Host "  Install log:    $LogFile"
Write-Host ""
Write-Host "Installer finished successfully at $(Get-Date)"
Stop-Transcript | Out-Null
