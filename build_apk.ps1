# TransferDaemon — Android APK builder for Windows.
# Compiles transferd-mobile for three Android ABIs, copies .so files into the
# Android project, then runs Gradle to produce a debug APK, signs it, and
# optionally installs it on a connected device.
#
# Usage (from project root):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\build_apk.ps1
#
# Environment overrides:
#   $env:ANDROID_HOME   — Android SDK root (default: %LOCALAPPDATA%\Android\Sdk)
#   $env:JAVA_HOME      — JDK root (default: auto-detected JDK 11)
#   $env:NDK_VERSION    — NDK version directory name (default: newest installed)
#   $env:SKIP_INSTALL   — set to "1" to skip ADB install step

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$AndroidDir = Join-Path $Root "android"
$CargoDir   = Join-Path $Root "transferdaemon"
$BinDir     = Join-Path $Root "bin"
$LogDir     = Join-Path $Root "logs"
$MaxLogs    = 10

# ── Log rotation ──────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
for ($i = $MaxLogs - 1; $i -ge 0; $i--) {
    $old = Join-Path $LogDir "build_apk_log_$i.log"
    if (Test-Path $old) {
        if ($i -lt $MaxLogs - 1) { Move-Item -Force $old (Join-Path $LogDir "build_apk_log_$($i+1).log") }
        else                      { Remove-Item  -Force $old }
    }
}
$LogFile = Join-Path $LogDir "build_apk_log_0.log"
Start-Transcript -Path $LogFile -Append | Out-Null

function Write-Log {
    param([string]$Message)
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[$ts] $Message"
    Write-Host $line
}

function Write-Banner([string]$msg) {
    Write-Log ""
    Write-Log "═══════════════════════════════════════════"
    Write-Log "  $msg"
    Write-Log "═══════════════════════════════════════════"
}

Write-Banner "TransferDaemon — Android APK Builder"
Write-Log "Root:        $Root"
Write-Log "Log file:    $LogFile"

# ── 1. Locate Java (prefer JDK 11, accept 11-17) ─────────────────────────────
if (-not $env:JAVA_HOME) {
    $jdkCandidates = @(
        "C:\Program Files\Eclipse Adoptium\jdk-11.0.28.6-hotspot",
        "C:\Program Files\Eclipse Adoptium\jdk-11.0.27.6-hotspot",
        "C:\Program Files\Java\jdk-17",
        "C:\Program Files\Java\jdk-21"
    )
    # Also try any Adoptium jdk-11* directory
    $adoptium11 = Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Filter "jdk-11*" -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name | Select-Object -Last 1
    if ($adoptium11) { $jdkCandidates = @($adoptium11.FullName) + $jdkCandidates }

    foreach ($c in $jdkCandidates) {
        if (Test-Path (Join-Path $c "bin\java.exe")) { $env:JAVA_HOME = $c; break }
    }
}
if (-not $env:JAVA_HOME -or -not (Test-Path $env:JAVA_HOME)) {
    throw "JAVA_HOME not found. Install JDK 11 (Eclipse Temurin) or set `$env:JAVA_HOME."
}
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
$javaVer = (& java -version 2>&1 | Select-Object -First 1) -replace '"',''
Write-Log "► Java: $env:JAVA_HOME  ($javaVer)"

# ── 2. Locate Android SDK ─────────────────────────────────────────────────────
$AndroidHome = if ($env:ANDROID_HOME)     { $env:ANDROID_HOME }
               elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
               else                        { "$env:LOCALAPPDATA\Android\Sdk" }
if (-not (Test-Path $AndroidHome)) {
    throw "Android SDK not found at $AndroidHome. Set `$env:ANDROID_HOME."
}
$env:ANDROID_HOME = $AndroidHome
Write-Log "► Android SDK: $AndroidHome"

# ── 3. Locate NDK ─────────────────────────────────────────────────────────────
$NdkRoot = Join-Path $AndroidHome "ndk"
if (-not (Test-Path $NdkRoot)) { throw "No NDK found under $NdkRoot. Install via Android Studio → SDK Manager." }
$NdkVersion = if ($env:NDK_VERSION) { $env:NDK_VERSION }
              else {
                  $pref = Get-ChildItem $NdkRoot -Directory | Where-Object { $_.Name -like "27.*" } | Select-Object -Last 1
                  if ($pref) { $pref.Name }
                  else { (Get-ChildItem $NdkRoot -Directory | Sort-Object Name | Select-Object -Last 1).Name }
              }
$NdkPath = Join-Path $NdkRoot $NdkVersion
$env:ANDROID_NDK_HOME = $NdkPath
$env:NDK_HOME         = $NdkPath
Write-Log "► NDK: $NdkPath"

# ── 4. Locate ADB ─────────────────────────────────────────────────────────────
$Adb = Join-Path $AndroidHome "platform-tools\adb.exe"
if (-not (Test-Path $Adb)) { $Adb = $null; Write-Log "  [warn] adb not found — install step will be skipped" }

# ── 5. Locate build-tools for apksigner ───────────────────────────────────────
$BuildToolsDir = Join-Path $AndroidHome "build-tools"
$LatestBuildTools = (Get-ChildItem $BuildToolsDir -Directory | Sort-Object Name | Select-Object -Last 1).FullName
Write-Log "► Build tools: $LatestBuildTools"

# ── 6. Rust / cargo-ndk ───────────────────────────────────────────────────────
$CargoBin = "$env:USERPROFILE\.cargo\bin"
$ProtocBin = "$env:TEMP\protoc\bin"
$env:PATH  = "$CargoBin;$ProtocBin;$env:PATH"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found. Install Rust via rustup."
}
if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    Write-Log "► cargo-ndk not found — installing…"
    cargo install cargo-ndk
}
Write-Log "► cargo-ndk: $(cargo ndk --version 2>&1)"

# ── 7. Install Android Rust targets ───────────────────────────────────────────
$targets = @("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android")
foreach ($t in $targets) {
    if (-not (rustup target list --installed | Select-String $t -Quiet)) {
        Write-Log "► Adding Rust target $t…"
        rustup target add $t
    }
}
Write-Log "► All Android targets installed."

# ── 8. Build transferd-mobile for all ABIs ────────────────────────────────────
Write-Banner "Building transferd-mobile (release)"
Set-Location $CargoDir

$abiMap = @{
    "aarch64-linux-android"   = "arm64-v8a"
    "armv7-linux-androideabi" = "armeabi-v7a"
    "x86_64-linux-android"    = "x86_64"
}

foreach ($triple in $abiMap.Keys) {
    Write-Log "► Compiling $triple…"
    cargo ndk --target $triple --platform 24 -- build --release -p transferd-mobile
    if ($LASTEXITCODE -ne 0) { throw "cargo-ndk build failed for $triple" }
    Write-Log "  ✓ $triple done"
}

# ── 9. Copy .so files into jniLibs ────────────────────────────────────────────
Write-Banner "Copying .so files to jniLibs"
foreach ($triple in $abiMap.Keys) {
    $abi     = $abiMap[$triple]
    $soSrc   = Join-Path $CargoDir "target\$triple\release\libtransferd_mobile.so"
    $destDir = Join-Path $AndroidDir "app\src\main\jniLibs\$abi"
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    if (Test-Path $soSrc) {
        Copy-Item -Force $soSrc (Join-Path $destDir "libtransferd_mobile.so")
        $soMb = [math]::Round((Get-Item $soSrc).Length / 1MB, 2)
        Write-Log "  Copied $abi  ($soMb MB)"
    } else {
        throw ".so not found at $soSrc"
    }
}

# ── 10. Run Gradle assembleDebug ──────────────────────────────────────────────
Write-Banner "Running Gradle assembleDebug"
Set-Location $AndroidDir
$gradlew = Join-Path $AndroidDir "gradlew.bat"
& $gradlew assembleDebug --no-daemon "--project-dir=$AndroidDir"
if ($LASTEXITCODE -ne 0) { throw "Gradle build failed." }

$Apk = Join-Path $AndroidDir "app\build\outputs\apk\debug\app-debug.apk"
if (-not (Test-Path $Apk)) { throw "APK not found: $Apk" }
$ApkMb = [math]::Round((Get-Item $Apk).Length / 1MB, 1)

# Copy APK to bin/
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$ApkOut = Join-Path $BinDir "transferdaemon-debug.apk"
Copy-Item -Force $Apk $ApkOut
Write-Log "► APK: $ApkOut  ($ApkMb MB)"

# ── 11. Install on connected device ───────────────────────────────────────────
if ($env:SKIP_INSTALL -ne "1" -and $Adb) {
    Write-Banner "Installing on device"
    $devices = & $Adb devices 2>&1 | Select-String "device$"
    if ($devices) {
        Write-Log "► Devices: $devices"
        & $Adb uninstall com.transferdaemon.app 2>&1 | Out-Null
        & $Adb install -r $ApkOut 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "► Install succeeded. Launching…"
            & $Adb shell am start -n "com.transferdaemon.app/android.app.NativeActivity" 2>&1
            Write-Log "► Waiting 5 s for startup then capturing logcat…"
            Start-Sleep -Seconds 5
            $deviceLog = Join-Path $LogDir "device_logcat_0.txt"
            & $Adb logcat -d -s "TransferDaemon" "AndroidRuntime" "NativeActivity" 2>&1 | Out-File $deviceLog -Encoding UTF8
            Write-Log "► Logcat saved: $deviceLog"
            Get-Content $deviceLog | Select-Object -Last 30 | ForEach-Object { Write-Log "    $_" }
        } else {
            Write-Log "  [warn] ADB install failed — check device USB debugging"
        }
    } else {
        Write-Log "  [warn] No device connected — skipping install"
    }
}

Write-Banner "Build complete"
Write-Log "  APK:  $ApkOut"
Write-Log "  Size: $ApkMb MB"
Write-Log "  Log:  $LogFile"
Write-Log ""
Write-Log "Finished at $(Get-Date)"
Stop-Transcript | Out-Null
