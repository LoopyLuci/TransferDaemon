# TransferDaemon — Signed Release APK builder.
#
# Produces a v2+v3 signed release APK at dist\TransferDaemon-<version>.apk.
# All build artefacts are logged to logs\build_apk_release_*.log.
#
# Usage (from project root):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\build_apk_release.ps1 [-Version "1.0.0"] [-SkipRustBuild] [-SkipInstall]
#
# Prerequisites:
#   • JDK 11 (Eclipse Temurin) — auto-detected or set $env:JAVA_HOME
#   • Android SDK with NDK 27+ — auto-detected or set $env:ANDROID_HOME
#   • cargo-ndk                — installed automatically if missing
#   • keytool (from JDK)      — for one-time keystore generation
#   • apksigner (build-tools) — for signing
#   • transferdaemon.keystore  — generated on first run if absent

param(
    [string]$Version       = "1.0.0",
    [switch]$SkipRustBuild,
    [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$AndroidDir  = Join-Path $Root "android"
$CargoDir    = Join-Path $Root "transferdaemon"
$DistDir     = Join-Path $Root "dist"
$LogDir      = Join-Path $Root "logs"
$Keystore    = Join-Path $Root "transferdaemon.keystore"
$KeyAlias    = "transferdaemon"
$StorePass   = "transferdaemon"
$ApkFinal    = Join-Path $DistDir "TransferDaemon-$Version.apk"

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null

# Log rotation (keep last 5)
for ($i = 4; $i -ge 0; $i--) {
    $old = Join-Path $LogDir "build_apk_release_$i.log"
    if (Test-Path $old) {
        if ($i -lt 4) { Move-Item -Force $old (Join-Path $LogDir "build_apk_release_$($i+1).log") }
        else          { Remove-Item -Force $old }
    }
}
$LogFile = Join-Path $LogDir "build_apk_release_0.log"
Start-Transcript -Path $LogFile -Append | Out-Null

function Log([string]$msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}
function Banner([string]$msg) {
    Log ""; Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; Log "  $msg"; Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

Banner "TransferDaemon $Version — Release APK"

# ── Java ──────────────────────────────────────────────────────────────────────
if (-not $env:JAVA_HOME) {
    $jdk = Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Filter "jdk-11*" -Directory -ErrorAction SilentlyContinue |
           Sort-Object Name | Select-Object -Last 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
}
if (-not $env:JAVA_HOME) { throw "JDK 11 not found. Set `$env:JAVA_HOME." }
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
Log "Java: $env:JAVA_HOME"

# ── Android SDK ───────────────────────────────────────────────────────────────
$AndroidHome = $env:ANDROID_HOME ?? $env:ANDROID_SDK_ROOT ?? "$env:LOCALAPPDATA\Android\Sdk"
if (-not (Test-Path $AndroidHome)) { throw "Android SDK not found at $AndroidHome." }
$env:ANDROID_HOME = $AndroidHome

$NdkDir = Get-ChildItem "$AndroidHome\ndk" -Directory -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -like "27.*" -or $_.Name -like "28.*" } |
          Sort-Object Name | Select-Object -Last 1
if (-not $NdkDir) {
    $NdkDir = Get-ChildItem "$AndroidHome\ndk" -Directory | Sort-Object Name | Select-Object -Last 1
}
$env:ANDROID_NDK_HOME = $NdkDir.FullName
$env:NDK_HOME         = $NdkDir.FullName
Log "NDK: $($NdkDir.FullName)"

$BuildTools = (Get-ChildItem "$AndroidHome\build-tools" -Directory | Sort-Object Name | Select-Object -Last 1).FullName
$Apksigner  = Join-Path $BuildTools "apksigner.bat"
Log "Build tools: $BuildTools"

# ── cargo-ndk ─────────────────────────────────────────────────────────────────
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    Log "Installing cargo-ndk..."
    cargo install cargo-ndk
}

# ── Keystore (one-time generation) ────────────────────────────────────────────
if (-not (Test-Path $Keystore)) {
    Banner "Generating signing keystore (one-time)"
    & keytool -genkeypair -v `
        -keystore $Keystore -alias $KeyAlias `
        -keyalg RSA -keysize 4096 -validity 10000 `
        -storepass $StorePass -keypass $StorePass `
        -dname "CN=TransferDaemon, OU=Dev, O=TransferDaemon, L=Unknown, ST=Unknown, C=US"
    if ($LASTEXITCODE -ne 0) { throw "keytool failed" }
    Log "Keystore generated: $Keystore"
    Log "IMPORTANT: Back up $Keystore — you need it to sign future releases."
}

# ── Rust build (3 ABIs) ───────────────────────────────────────────────────────
$abiMap = @{
    "aarch64-linux-android"   = "arm64-v8a"
    "armv7-linux-androideabi" = "armeabi-v7a"
    "x86_64-linux-android"    = "x86_64"
}

if (-not $SkipRustBuild) {
    Banner "Building transferd-mobile — release (3 ABIs)"
    Set-Location $CargoDir
    foreach ($triple in $abiMap.Keys) {
        Log "Compiling $triple..."
        cargo ndk --target $triple --platform 24 -- build --release -p transferd-mobile
        if ($LASTEXITCODE -ne 0) { throw "cargo-ndk failed for $triple" }
    }
}

# ── Copy .so into jniLibs ─────────────────────────────────────────────────────
Banner "Copying .so files"
foreach ($triple in $abiMap.Keys) {
    $abi     = $abiMap[$triple]
    $soSrc   = Join-Path $CargoDir "target\$triple\release\libtransferd_mobile.so"
    $destDir = Join-Path $AndroidDir "app\src\main\jniLibs\$abi"
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    if (-not (Test-Path $soSrc)) { throw ".so not found: $soSrc" }
    Copy-Item -Force $soSrc (Join-Path $destDir "libtransferd_mobile.so")
    Log "  $abi  $([math]::Round((Get-Item $soSrc).Length/1MB,2)) MB"
}

# ── Gradle assembleRelease ────────────────────────────────────────────────────
Banner "Gradle assembleRelease"
Set-Location $AndroidDir
& ".\gradlew.bat" assembleRelease --no-daemon 2>&1
if ($LASTEXITCODE -ne 0) { throw "Gradle assembleRelease failed" }

$UnsignedApk = Get-ChildItem "$AndroidDir\app\build\outputs\apk\release" -Filter "*unsigned*.apk" -ErrorAction SilentlyContinue |
               Select-Object -First 1
if (-not $UnsignedApk) {
    # Some Gradle configs produce a directly-aligned APK even without signing config
    $UnsignedApk = Get-ChildItem "$AndroidDir\app\build\outputs\apk\release" -Filter "*.apk" |
                   Sort-Object LastWriteTime | Select-Object -Last 1
}
if (-not $UnsignedApk) { throw "No APK found in release output dir" }
Log "Unsigned APK: $($UnsignedApk.FullName)  ($([math]::Round($UnsignedApk.Length/1MB,1)) MB)"

# ── Sign with apksigner ───────────────────────────────────────────────────────
Banner "Signing APK"
& $Apksigner sign `
    --ks $Keystore --ks-pass "pass:$StorePass" `
    --ks-key-alias $KeyAlias `
    --out $ApkFinal `
    $UnsignedApk.FullName
if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }

# Verify
$verifyOut = & $Apksigner verify --verbose $ApkFinal 2>&1
Log ($verifyOut -join "`n")
if (-not ($verifyOut | Select-String "Verifies")) { throw "APK verification failed" }

$f = Get-Item $ApkFinal
Banner "Release APK ready"
Log "  File:    $ApkFinal"
Log "  Size:    $([math]::Round($f.Length/1MB,2)) MB"
Log "  Signed:  v2+v3 ✓"
Log ""
Log "Next steps:"
Log "  1. Upload $ApkFinal to the GitHub release at:"
Log "     https://github.com/LoopyLuci/TransferDaemon/releases/tag/v$Version"
Log "  2. Back up transferdaemon.keystore — required for all future release signatures."

Stop-Transcript | Out-Null
