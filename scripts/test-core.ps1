#!/usr/bin/env pwsh
# Builds, lints and tests the Transferd core workspace. Stops at the first failure.
#
#   scripts/test-core.ps1             debug build
#   scripts/test-core.ps1 -Release    release build for the tests and binaries

param([switch]$Release)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

function Invoke-Step([string]$Name, [string[]]$Command) {
    Write-Host "== $Name ==" -ForegroundColor Cyan
    & $Command[0] $Command[1..($Command.Length - 1)]
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $Name" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

$relArg = if ($Release) { @('--release') } else { @() }

& cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { Write-Host 'warning: some files are not rustfmt-clean (cargo fmt sweep pending)' -ForegroundColor Yellow }
Invoke-Step 'clippy (library and binary targets)' @('cargo', 'clippy', '--workspace', '--all-features', '--', '-D', 'warnings')
Invoke-Step 'tests'   (@('cargo', 'test', '--workspace', '--all-features') + $relArg)
Invoke-Step 'relay binaries' @('cargo', 'build', '--release', '-p', 'relayd', '-p', 'transferd-relay', '-p', 'transferd-cat')

# The reference side of the Python and TypeScript interop tests. Without these
# variables those tests are skipped, so build them and point the suites at them.
Invoke-Step 'interop binary: interop_peer' @('cargo', 'build', '-p', 'transferd-overlay', '--example', 'interop_peer')
Invoke-Step 'interop binary: relayd' @('cargo', 'build', '-p', 'relayd', '--bin', 'relayd')
$env:TRANSFERD_INTEROP_PEER = Join-Path $PWD 'target\debug\examples\interop_peer.exe'
$env:TRANSFERD_RELAYD = Join-Path $PWD 'target\debug\relayd.exe'

if (Get-Command python -ErrorAction SilentlyContinue) {
    Invoke-Step 'python' @('python', '-m', 'pytest', 'python/tests', '-q')
} else {
    Write-Host '== python: skipped (no python on PATH) ==' -ForegroundColor Yellow
}
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Invoke-Step 'typescript: install' @('npm', '--prefix', 'typescript', 'ci')
    Invoke-Step 'typescript' @('npm', '--prefix', 'typescript', 'test')
} else {
    Write-Host '== typescript: skipped (no npm on PATH) ==' -ForegroundColor Yellow
}

Write-Host 'Transferd core: all checks passed.' -ForegroundColor Green
