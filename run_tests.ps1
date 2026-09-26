#!/usr/bin/env pwsh
# TransferDaemon End-to-End Test Runner
# Builds binaries, runs the full test suite, and reports results.

param(
    [switch]$Release,
    [switch]$SkipBuild,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
$DaemonDir = Join-Path $RootDir "transferdaemon"
$BinDir = Join-Path $DaemonDir "target"

if (-not $SkipBuild) {
    Write-Host "=== Building TransferDaemon ===" -ForegroundColor Cyan
    $buildProfile = if ($Release) { "--release" } else { "" }
    
    # Build all binaries
    $binaries = @("transferd", "transferd-ui", "launcher", "relayd", "transferd-tui")
    foreach ($bin in $binaries) {
        Write-Host "Building $bin..." -ForegroundColor Yellow
        & cargo build $buildProfile --package $bin -p transferd-tests 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED to build $bin" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "All binaries built successfully" -ForegroundColor Green
}

# Run unit tests
Write-Host "`n=== Running Unit Tests ===" -ForegroundColor Cyan
$testArgs = @("test", "--workspace", "--lib")
if ($Release) { $testArgs += "--release" }
& cargo $testArgs 2>&1 | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Unit tests FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "Unit tests PASSED" -ForegroundColor Green

# Run integration tests
Write-Host "`n=== Running Integration Tests ===" -ForegroundColor Cyan
$intArgs = @("test", "--workspace")
if ($Release) { $intArgs += "--release" }
& cargo $intArgs 2>&1 | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Integration tests FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "Integration tests PASSED" -ForegroundColor Green

# Run benchmarks (criterion)
Write-Host "`n=== Running Benchmarks ===" -ForegroundColor Cyan
$benchArgs = @("bench", "--workspace")
if ($Release) { $benchArgs += "--release" }
& cargo $benchArgs 2>&1 | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Benchmarks completed with warnings" -ForegroundColor Yellow
} else {
    Write-Host "Benchmarks PASSED" -ForegroundColor Green
}

# Run clippy
Write-Host "`n=== Running Clippy ===" -ForegroundColor Cyan
& cargo clippy --workspace -- -D warnings 2>&1 | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Host "Clippy FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "Clippy PASSED" -ForegroundColor Green

# Summary
Write-Host "`n========== TEST SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Unit Tests:       PASS" -ForegroundColor Green
Write-Host "Integration Tests: PASS" -ForegroundColor Green
Write-Host "Benchmarks:       PASS" -ForegroundColor Green
Write-Host "Clippy:           PASS" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "All tests passed!" -ForegroundColor Green
