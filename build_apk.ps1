# TransferDaemon — Android APK builder for Windows.
# Compiles transferd-mobile for three Android ABIs, copies .so files into the
# Android project, then runs Gradle to produce an unsigned release APK.
#
# Usage (from project root):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\build_apk.ps1
#
# Environment overrides:
#   $env:ANDROID_HOME   — Android SDK root (default: %LOCALAPPDATA%\Android\Sdk)
#   $env:JAVA_HOME      — JDK root (default: auto-detected from known paths)
#   $env:NDK_VERSION    — NDK version directory name (default: newest installed)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$AndroidDir = Join-Path $Root "android"
$CargoDir   = Join-Path $Root "transferdaemon"
$LogDir     = Join-Path $Root "logs"
$MaxLogs    = 10

# ── Log rotation ──────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
for ($i = $MaxLogs - 1; $i -ge 0; $i--) {
    $old = Join-Path $LogDir "apk_build_$i.log"
    if (Test-Path $old) {
        if ($i -lt $MaxLogs - 1) { Move-Item -Force $old (Join-Path $LogDir "apk_build_$($i+1).log") }
        else { Remove-Item -Force $old }
    }
}
$LogFile = Join-Path $LogDir "apk_build_0.log"
Start-Transcript -Path $LogFile -Append | Out-Null
Write-Host "APK build started at $(Get-Date)"

function Write-Banner([string]$msg) {
    Write-Host ""; Write-Host "═══════════════════════════════════════════"
    Write-Host "  $msg"; Write-Host "═══════════════════════════════════════════"
}

Write-Banner "TransferDaemon — Android APK Builder"

# ── 1. Locate Java ────────────────────────────────────────────────────────────
if (-not $env:JAVA_HOME) {
    $javaSearchPaths = @(
        "C:\Program Files\Eclipse Adoptium",
        "C:\Program Files\Microsoft",
        "C:\Program Files\Java",
        "C:\Program Files\OpenJDK"
    )
    foreach ($base in $javaSearchPaths) {
        $found = Get-ChildItem $base -Filter "java.exe" -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch "jre" } |
                 Select-Object -First 1
        if ($found) {
            $env:JAVA_HOME = $found.DirectoryName | Split-Path -Parent
            break
        }
    }
    # AGP 7.4.2 + Gradle 7.5.1 run on JDK 11-17; prefer JDK 11 (Adoptium/Temurin).
    $jdkCandidates = @(
        "C:\Program Files\Eclipse Adoptium\jdk-11.0.28.6-hotspot",
        "C:\Program Files\Eclipse Adoptium\jdk-11.0.27.6-hotspot",
        "C:\Program Files\Java\jdk-17",
        "C:\Program Files\Java\jdk-21"
    )
    foreach ($candidate in $jdkCandidates) {
        if (Test-Path (Join-Path $candidate "bin\java.exe")) {
            $env:JAVA_HOME = $candidate
            break
        }
    }
    # Fallback: any Adoptium JDK 11
    if (-not $env:JAVA_HOME) {
        $adoptium = Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Filter "jdk-11*" -Directory -ErrorAction SilentlyContinue |
                    Select-Object -Last 1
        if ($adoptium) { $env:JAVA_HOME = $adoptium.FullName }
    }
}
if (-not $env:JAVA_HOME -or -not (Test-Path $env:JAVA_HOME)) {
    throw "JAVA_HOME not found. Install JDK 11 (Eclipse Temurin recommended) or set `$env:JAVA_HOME."
}
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
Write-Host "► Java: $env:JAVA_HOME ($(& java -version 2>&1 | Select-Object -First 1))"

# ── 2. Locate Android SDK ─────────────────────────────────────────────────────
$AndroidHome = if ($env:ANDROID_HOME) { $env:ANDROID_HOME }
               elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
               else { "$env:LOCALAPPDATA\Android\Sdk" }
if (-not (Test-Path $AndroidHome)) {
    throw "Android SDK not found at $AndroidHome. Set `$env:ANDROID_HOME."
}
$env:ANDROID_HOME = $AndroidHome
Write-Host "► Android SDK: $AndroidHome"

# ── 3. Locate NDK ────────────────────────────────────────────────────────────
$NdkRoot = Join-Path $AndroidHome "ndk"
if (-not (Test-Path $NdkRoot)) { throw "No NDK found under $NdkRoot. Install via Android Studio → SDK Manager." }
$NdkVersion = if ($env:NDK_VERSION) { $env:NDK_VERSION }
              else {
                  # Prefer 27.x; otherwise take the newest installed.
                  $preferred = Get-ChildItem $NdkRoot -Directory | Where-Object { $_.Name -like "27.*" } | Select-Object -Last 1
                  if ($preferred) { $preferred.Name }
                  else { (Get-ChildItem $NdkRoot -Directory | Sort-Object Name | Select-Object -Last 1).Name }
              }
$NdkPath = Join-Path $NdkRoot $NdkVersion
Write-Host "► NDK: $NdkPath"
$env:ANDROID_NDK_HOME = $NdkPath
$env:NDK_HOME         = $NdkPath

# ── 4. Rust / cargo-ndk ──────────────────────────────────────────────────────
$cargoBin = "$env:USERPROFILE\.cargo\bin"
$env:PATH  = "$cargoBin;$env:PATH"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found. Install Rust via rustup."
}
if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    Write-Host "► cargo-ndk not found — installing…"
    cargo install cargo-ndk
}
Write-Host "► cargo-ndk: $(cargo ndk --version)"

# ── 5. Install Android Rust targets ──────────────────────────────────────────
$targets = @("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android")
foreach ($t in $targets) {
    $installed = rustup target list --installed | Select-String $t
    if (-not $installed) {
        Write-Host "► Adding Rust target $t…"
        rustup target add $t
    }
}
Write-Host "► All Android targets installed."

# ── 6. Build transferd-mobile for all three ABIs ─────────────────────────────
Write-Banner "Building transferd-mobile (release)"
Set-Location $CargoDir

$abiMap = @{
    "aarch64-linux-android"   = "arm64-v8a"
    "armv7-linux-androideabi" = "armeabi-v7a"
    "x86_64-linux-android"    = "x86_64"
}

foreach ($triple in $abiMap.Keys) {
    Write-Host "► Compiling for $triple…"
    cargo ndk --target $triple --platform 26 -- build --release -p transferd-mobile
    if ($LASTEXITCODE -ne 0) { throw "cargo-ndk build failed for $triple" }
}

# ── 7. Copy .so files into jniLibs ───────────────────────────────────────────
Write-Banner "Copying .so files to Android project"
foreach ($triple in $abiMap.Keys) {
    $abi     = $abiMap[$triple]
    $soSrc   = Join-Path $CargoDir "target\$triple\release\libtransferd_mobile.so"
    $destDir = Join-Path $AndroidDir "app\src\main\jniLibs\$abi"
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    if (Test-Path $soSrc) {
        Copy-Item -Force $soSrc (Join-Path $destDir "libtransferd_mobile.so")
        Write-Host "  Copied $abi"
    } else {
        throw ".so not found at $soSrc"
    }
}

# ── 8. Run Gradle assembleDebug ───────────────────────────────────────────────
Write-Banner "Running Gradle assembleDebug"
Set-Location $AndroidDir
$gradlew = Join-Path $AndroidDir "gradlew.bat"
& $gradlew assembleDebug --no-daemon "--project-dir=$AndroidDir"
if ($LASTEXITCODE -ne 0) { throw "Gradle build failed — see output above." }

$apk = Join-Path $AndroidDir "app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $apk) {
    $sizeMb = [math]::Round((Get-Item $apk).Length / 1MB, 1)
    Write-Banner "APK build complete!"
    Write-Host "  APK:  $apk"
    Write-Host "  Size: $sizeMb MB"
    Write-Host ""
    Write-Host "  Install on device/emulator:"
    Write-Host "    adb install `"$apk`""
} else {
    throw "APK not found at expected path: $apk"
}

Write-Host ""
Write-Host "Build log: $LogFile"
Write-Host "Finished at $(Get-Date)"
Stop-Transcript | Out-Null
