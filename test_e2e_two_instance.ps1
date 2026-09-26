#!/usr/bin/env pwsh
# TransferDaemon Two-Instance End-to-End Test Runner
# Tests peer-to-peer communication by running two daemon+UI instances.
#
# Usage:
#   .\test_e2e_two_instance.ps1          # Full interactive test
#   .\test_e2e_two_instance.ps1 -Quick   # Quick smoke test (daemons only)

param(
    [switch]$Quick,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$DaemonDir = Join-Path $RootDir "transferdaemon"
$BinDir = Join-Path $DaemonDir "target" "release"

if (-not $SkipBuild) {
    Write-Host "=== Building TransferDaemon ===" -ForegroundColor Cyan
    & cargo build --release -p transferd -p transferd-ui -p launcher 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build FAILED" -ForegroundColor Red
        exit 1
    }
    Write-Host "Build SUCCESS" -ForegroundColor Green
}

# Run automated tests first
Write-Host "`n=== Running Automated Tests ===" -ForegroundColor Cyan
$testsPassed = $true

Write-Host "`n--- lib tests ---" -ForegroundColor Yellow
cargo test --workspace --lib 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $testsPassed = $false; Write-Host "FAILED" -ForegroundColor Red }
else { Write-Host "PASSED" -ForegroundColor Green }

Write-Host "--- E2E full stack test ---" -ForegroundColor Yellow
cargo test --test e2e_full_stack 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $testsPassed = $false; Write-Host "FAILED" -ForegroundColor Red }
else { Write-Host "PASSED" -ForegroundColor Green }

Write-Host "--- Integration tests ---" -ForegroundColor Yellow
cargo test --package transferd-tests 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { $testsPassed = $false; Write-Host "FAILED" -ForegroundColor Red }
else { Write-Host "PASSED" -ForegroundColor Green }

if (-not $testsPassed) {
    Write-Host "`nSome automated tests FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "`nAll automated tests PASSED" -ForegroundColor Green

if ($Quick) {
    Write-Host "`n=== Quick smoke test: starting daemons for 5 seconds ===" -ForegroundColor Cyan
    $daemon1 = Start-Process -FilePath (Join-Path $BinDir "transferd.exe") -ArgumentList "127.0.0.1:50051" -NoNewWindow -PassThru
    $daemon2 = Start-Process -FilePath (Join-Path $BinDir "transferd.exe") -ArgumentList "127.0.0.1:50052" -NoNewWindow -PassThru
    Start-Sleep -Seconds 5
    Stop-Process -Id $daemon1.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Quick smoke test COMPLETE" -ForegroundColor Green
    exit 0
}

# Interactive two-instance test
Write-Host "`n=== Launching Two-Instance Test ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will start two daemon+UI pairs for testing." -ForegroundColor White
Write-Host "Follow the steps below to test peer-to-peer communication." -ForegroundColor White
Write-Host ""

# Start daemon 1 on 50051
Write-Host "Starting Daemon 1 (port 50051)..." -ForegroundColor Yellow
$daemon1 = Start-Process -FilePath (Join-Path $BinDir "transferd.exe") -ArgumentList "127.0.0.1:50051" -NoNewWindow -PassThru
Start-Sleep -Seconds 1

# Start daemon 2 on 50052
Write-Host "Starting Daemon 2 (port 50052)..." -ForegroundColor Yellow
$daemon2 = Start-Process -FilePath (Join-Path $BinDir "transferd.exe") -ArgumentList "127.0.0.1:50052" -NoNewWindow -PassThru
Start-Sleep -Seconds 1

# Start UI 1
Write-Host "Starting UI 1 (connecting to daemon 1)..." -ForegroundColor Yellow
$env1 = @{ "TRANSFERD_ADDR" = "http://127.0.0.1:50051" }
$ui1 = Start-Process -FilePath (Join-Path $BinDir "transferd-ui.exe") -NoNewWindow -PassThru

# Start UI 2
Write-Host "Starting UI 2 (connecting to daemon 2)..." -ForegroundColor Yellow
$env2 = @{ "TRANSFERD_ADDR" = "http://127.0.0.1:50052" }
$ui2 = Start-Process -FilePath (Join-Path $BinDir "transferd-ui.exe") -NoNewWindow -PassThru

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "         TWO-INSTANCE TEST INSTRUCTIONS" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "STEP 1: Create Identity on both UIs" -ForegroundColor Green
Write-Host "  - In UI 1: Click 'Create new identity', enter 'Alice'"
Write-Host "  - In UI 2: Click 'Create new identity', enter 'Bob'"
Write-Host ""
Write-Host "STEP 2: Note the public keys" -ForegroundColor Green
Write-Host "  - Go to Settings tab to see each user's public key"
Write-Host ""
Write-Host "STEP 3: Add each other as contacts" -ForegroundColor Green
Write-Host "  - In UI 1: Contacts tab -> enter Bob's public key + address 127.0.0.1:50052"
Write-Host "  - In UI 2: Contacts tab -> enter Alice's public key + address 127.0.0.1:50051"
Write-Host ""
Write-Host "STEP 4: Send a message" -ForegroundColor Green
Write-Host "  - In UI 1: Click on Bob -> type 'Hello Bob!' -> press Enter"
Write-Host "  - In UI 2: Check if message appears in chat"
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press ENTER to shut down all instances when done..." -ForegroundColor Yellow
Read-Host

# Cleanup
Write-Host "`nShutting down..." -ForegroundColor Yellow
Stop-Process -Id $ui1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $ui2.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $daemon1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue

Write-Host "`nTwo-instance test COMPLETE" -ForegroundColor Green
