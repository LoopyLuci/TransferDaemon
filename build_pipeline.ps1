# =============================================================================
# TransferDaemon - Local On-Device CI/CD Pipeline
#
# A fully local, robust build/test/deploy pipeline for BOTH artifacts:
#   - APK  - Android app (3 ABIs) via cargo-ndk + gradle + apksigner
#   - EXE  - desktop binaries (transferd daemon, launcher, transferd-tui)
#
# Stages (fail-fast, each timed):
#   1 preflight - toolchain + environment + connected device checks
#   2 static    - cargo check --all-features, clippy -D warnings
#   3 test      - cargo test --workspace + deterministic wire fuzz
#   4 exe       - cargo build --release (desktop EXEs to dist/)
#   5 apk       - Rust android (3 ABIs) -> gradle assembleRelease -> sign
#   6 deploy    - adb install + launch + smoke (requires connected device)
#   7 report    - timing table, JSON summary, log file, exit code
#
# Usage (from project root):
#   .\build_pipeline.ps1 [-Version "1.0.0"] [-Fast] [-SkipTests] [-SkipExe]
#                        [-SkipApk] [-SkipDeploy] [-RequireDevice]
#
# Opt-in flags make the pipeline incremental and CI-loop friendly:
#   -Fast          skip clippy + tests + fuzz (build-only loop)
#   -SkipTests     skip cargo test + fuzz (keep clippy)
#   -SkipExe       skip desktop release build
#   -SkipApk       skip APK build (Rust android + gradle + sign)
#   -SkipDeploy    skip adb install/smoke
#   -RequireDevice fail preflight if no Android device is connected
# =============================================================================

param(
    [string]$Version      = "1.0.0",
    [switch]$Fast,
    [switch]$SkipTests,
    [switch]$SkipExe,
    [switch]$SkipApk,
    [switch]$SkipDeploy,
    [switch]$RequireDevice
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root       = Split-Path -Parent $MyInvocation.MyCommand.Path
$CargoDir   = Join-Path $Root "transferdaemon"
$AndroidDir = Join-Path $Root "android"
$DistDir    = Join-Path $Root "dist"
$LogDir     = Join-Path $Root "logs"
$Keystore   = Join-Path $Root "transferdaemon.keystore"
$KeyAlias   = "transferdaemon"
$StorePass  = "transferdaemon"
$ApkFinal   = Join-Path $DistDir "TransferDaemon-$Version.apk"

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir  | Out-Null

# --- Log rotation (keep last 8) ---------------------------------------------
$Ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "pipeline_$Ts.log"
Start-Transcript -Path $LogFile -Append | Out-Null

$ExitCode = 0
$Results  = [System.Collections.Generic.List[object]]::new()
$swAll    = [System.Diagnostics.Stopwatch]::StartNew()

function Log([string]$msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}
function Banner([string]$msg) {
    Log ""
    Log "=============================================================="
    Log "  $msg"
    Log "=============================================================="
}

function Start-Stage([string]$name) {
    Banner "==> $name"
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Finish-Stage([string]$name, $sw, [bool]$ok, [string]$detail = "") {
    $ms = $sw.Elapsed.TotalSeconds
    if ($ok) {
        Log "[OK]   $name  (${ms}s)  $detail"
    } else {
        Log "[FAIL] $name  (${ms}s)  $detail"
        $script:ExitCode = 1
    }
    $script:Results.Add([pscustomobject]@{ stage = $name; ok = $ok; seconds = [math]::Round($ms,1); detail = $detail })
    return $ok
}

function Fail-Stage([string]$name, $sw, [string]$err) {
    Finish-Stage $name $sw $false $err
    throw "Pipeline aborted at stage '$name'."
}

# =============================================================================
# Stage 1 - Preflight
# =============================================================================
$sw = Start-Stage "preflight"
$preflightOk = $true
$preflightDetail = @()

$cargo    = Get-Command cargo -ErrorAction SilentlyContinue
$javaHome = if ($env:JAVA_HOME) { $env:JAVA_HOME }
            else { (Get-Command java -ErrorAction SilentlyContinue | Split-Path -Parent | Split-Path -Parent) }
$sdkHome = $env:ANDROID_HOME
if (-not $sdkHome) { $sdkHome = $env:ANDROID_SDK_ROOT }
if (-not $sdkHome) { $sdkHome = "$env:LOCALAPPDATA\Android\Sdk" }

$ndk = Get-ChildItem (Join-Path $sdkHome "ndk") -Directory -ErrorAction SilentlyContinue |
       Sort-Object Name | Select-Object -Last 1
$buildTools = Get-ChildItem (Join-Path $sdkHome "build-tools") -Directory -ErrorAction SilentlyContinue |
              Sort-Object Name | Select-Object -Last 1
$apksigner = if ($buildTools) { Join-Path $buildTools.FullName "apksigner.bat" } else { $null }
$adb       = Join-Path $sdkHome "platform-tools\adb.exe"

$checks = @(
    @{ name = "cargo";      ok = [bool]$cargo; hint = "install Rust: https://rustup.rs" },
    @{ name = "JAVA_HOME";  ok = [bool]$javaHome -and (Test-Path $javaHome); hint = "set `$env:JAVA_HOME" },
    @{ name = "Android SDK"; ok = Test-Path $sdkHome; hint = "set `$env:ANDROID_HOME" },
    @{ name = "NDK";         ok = [bool]$ndk; hint = "SDK Manager - NDK 27+" },
    @{ name = "build-tools"; ok = [bool]$buildTools; hint = "SDK Manager - build-tools" },
    @{ name = "apksigner";   ok = [bool]$apksigner -and (Test-Path $apksigner); hint = "SDK build-tools missing apksigner" },
    @{ name = "adb";         ok = Test-Path $adb; hint = "SDK platform-tools missing adb" }
)
foreach ($c in $checks) {
    if ($c.ok) { $preflightDetail += "    [OK]   $($c.name)" }
    else       { $preflightDetail += "    [FAIL] $($c.name) - $($c.hint)"; $preflightOk = $false }
}

# Rust android toolchain (only needed when building the APK).
if (-not $SkipApk) {
    $targets = & rustup target list --installed 2>$null | Select-String -Pattern "android"
    $hasNdk  = [bool](Get-Command cargo-ndk -ErrorAction SilentlyContinue)
    if (-not $targets -or -not $hasNdk) {
        $preflightOk = $false
        $preflightDetail += "    [FAIL] Rust android toolchain - run: rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; cargo install cargo-ndk"
    } else {
        $preflightDetail += "    [OK]   rust android targets + cargo-ndk"
    }
}

# Connected device (Kindle Fire) - warn unless -RequireDevice.
$devices = @()
if (Test-Path $adb) {
    $devices = @(& $adb devices 2>$null | Where-Object { $_ -match "\tdevice$" })
}
if ($devices.Count -eq 0) {
    if ($RequireDevice) { $preflightOk = $false; $preflightDetail += "    [FAIL] No Android device connected (adb devices)" }
    else                { $preflightDetail += "    [WARN] No Android device connected - deploy stage will be skipped" }
} else {
    $preflightDetail += "    [OK]   Device connected: $($devices[0])"
}

$preflightDetail += "  Version: $Version"
$preflightDetail += "  Log: $LogFile"
$preflightDetail += "  Flags: Fast=$Fast SkipTests=$SkipTests SkipExe=$SkipExe SkipApk=$SkipApk SkipDeploy=$SkipDeploy"

if (-not $preflightOk) {
    Fail-Stage "preflight" $sw ("Toolchain missing:`n" + ($preflightDetail -join "`n"))
}
Finish-Stage "preflight" $sw $true ($preflightDetail -join " | ")

# =============================================================================
# Stage 2 - Static checks
# =============================================================================
if (-not $Fast) {
    $sw = Start-Stage "static"

    Log "cargo check --workspace --all-features ..."
    Push-Location $CargoDir
    cargo check --workspace --all-features 2>&1 | Tee-Object -Variable out | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "static" $sw "cargo check failed" }
    Pop-Location

    Log "cargo clippy --workspace --all-features -- -D warnings ..."
    Push-Location $CargoDir
    cargo clippy --workspace --all-features -- -D warnings 2>&1 | Tee-Object -Variable out2 | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "static" $sw "clippy -D warnings failed" }
    Pop-Location

    Finish-Stage "static" $sw $true "check + clippy clean"
} else {
    Log "[SKIP] static checks skipped (-Fast)"
    $Results.Add([pscustomobject]@{ stage = "static"; ok = $true; seconds = 0; detail = "skipped (-Fast)" })
}

# =============================================================================
# Stage 3 - Tests + fuzz
# =============================================================================
if (-not ($Fast -or $SkipTests)) {
    $sw = Start-Stage "test"

    Log "cargo test --workspace ..."
    Push-Location $CargoDir
    cargo test --workspace 2>&1 | Tee-Object -Variable tOut | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "test" $sw "cargo test failed" }
    Pop-Location

    $passed = 0; $failed = 0
    foreach ($m in ($tOut | Select-String -Pattern "test result: ok\. (\d+) passed; (\d+) failed")) {
        $passed += [int]$m.Matches[0].Groups[1].Value
        $failed += [int]$m.Matches[0].Groups[2].Value
    }
    Log "test summary: $passed passed, $failed failed"

    Log "deterministic wire fuzz (200k) ..."
    Push-Location $CargoDir
    cargo run --release -p transferd-pentest -- fuzz 200000 2>&1 | Tee-Object -Variable fOut | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "test" $sw "fuzz sweep found a crash" }
    Pop-Location

    Finish-Stage "test" $sw $true "tests $passed passed / $failed failed, fuzz clean"
} else {
    Log "[SKIP] tests + fuzz skipped (Fast=$Fast SkipTests=$SkipTests)"
    $Results.Add([pscustomobject]@{ stage = "test"; ok = $true; seconds = 0; detail = "skipped" })
}

# =============================================================================
# Stage 4 - EXE (desktop release)
# =============================================================================
if (-not $SkipExe) {
    $sw = Start-Stage "exe"
    Log "cargo build --release (transferd, launcher, transferd-tui) ..."
    Push-Location $CargoDir
    cargo build --release -p transferd -p launcher -p transferd-tui 2>&1 | Tee-Object -Variable eOut | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "exe" $sw "cargo build --release failed" }
    Pop-Location

    $ext = if ($IsWindows) { ".exe" } else { "" }
    $collected = @()
    foreach ($e in @("transferd", "launcher", "transferd-tui")) {
        $src = Join-Path $CargoDir "target\release\$e$ext"
        if (Test-Path $src) {
            Copy-Item -Force $src (Join-Path $DistDir "$e-$Version$ext")
            $collected += $e
        }
    }
    if ($collected.Count -eq 0) { Fail-Stage "exe" $sw "no EXE binaries produced" }
    Finish-Stage "exe" $sw $true ("collected: " + ($collected -join ", "))
} else {
    Log "[SKIP] EXE build skipped (-SkipExe)"
    $Results.Add([pscustomobject]@{ stage = "exe"; ok = $true; seconds = 0; detail = "skipped" })
}

# =============================================================================
# Stage 5 - APK (Rust android -> gradle -> sign)
# =============================================================================
if (-not $SkipApk) {
    $sw = Start-Stage "apk"

    $env:JAVA_HOME   = $javaHome
    $env:ANDROID_HOME = $sdkHome
    $env:ANDROID_NDK_HOME = $ndk.FullName
    $env:NDK_HOME         = $ndk.FullName
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

    $abiMap = @{
        "aarch64-linux-android"   = "arm64-v8a"
        "armv7-linux-androideabi" = "armeabi-v7a"
        "x86_64-linux-android"    = "x86_64"
    }

    # Rust android release (3 ABIs). cargo handles incremental builds.
    Log "Rust android build (3 ABIs) ..."
    Push-Location $CargoDir
    foreach ($triple in $abiMap.Keys) {
        Log "  compiling $triple ..."
        cargo ndk --target $triple --platform 24 -- build --release -p transferd-mobile 2>&1 | Tee-Object -Variable aOut | Out-Host
        if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "apk" $sw "Rust android build failed for $triple" }
    }
    Pop-Location

    # Copy .so into jniLibs.
    foreach ($triple in $abiMap.Keys) {
        $abi   = $abiMap[$triple]
        $soSrc = Join-Path $CargoDir "target\$triple\release\libtransferd_mobile.so"
        $dest  = Join-Path $AndroidDir "app\src\main\jniLibs\$abi"
        if (-not (Test-Path $soSrc)) { Fail-Stage "apk" $sw "missing .so: $soSrc" }
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Force $soSrc (Join-Path $dest "libtransferd_mobile.so")
        Log "    [OK]   $abi"
    }

    # Keystore (one-time).
    if (-not (Test-Path $Keystore)) {
        Log "Generating signing keystore ..."
        & "$javaHome\bin\keytool" -genkeypair -v `
            -keystore $Keystore -alias $KeyAlias `
            -keyalg RSA -keysize 4096 -validity 10000 `
            -storepass $StorePass -keypass $StorePass `
            -dname "CN=TransferDaemon, OU=Dev, O=TransferDaemon, L=Unknown, ST=Unknown, C=US" | Out-Host
        if ($LASTEXITCODE -ne 0) { Fail-Stage "apk" $sw "keytool failed" }
        Log "    [OK]   keystore created (back it up!)"
    }

    # Gradle assembleRelease.
    Log "gradle assembleRelease ..."
    Push-Location $AndroidDir
    & ".\gradlew.bat" assembleRelease --no-daemon 2>&1 | Tee-Object -Variable gOut | Out-Host
    if ($LASTEXITCODE -ne 0) { Pop-Location; Fail-Stage "apk" $sw "gradle assembleRelease failed" }
    Pop-Location

    # Sign with apksigner.
    $unsigned = Get-ChildItem "$AndroidDir\app\build\outputs\apk\release" -Filter "*.apk" |
                Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $unsigned) { Fail-Stage "apk" $sw "no APK in release output" }
    Log "Signing $($unsigned.Name) ..."
    & $apksigner sign --ks $Keystore --ks-pass "pass:$StorePass" `
        --ks-key-alias $KeyAlias --out $ApkFinal $unsigned.FullName | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail-Stage "apk" $sw "apksigner failed" }

    $verify = & $apksigner verify --verbose $ApkFinal 2>&1
    if (-not ($verify | Select-String "Verifies")) { Fail-Stage "apk" $sw "APK verification failed" }

    $apkSize = [math]::Round((Get-Item $ApkFinal).Length / 1MB, 1)
    Finish-Stage "apk" $sw $true ("$ApkFinal  (${apkSize} MB, signed)")
} else {
    Log "[SKIP] APK build skipped (-SkipApk)"
    $Results.Add([pscustomobject]@{ stage = "apk"; ok = $true; seconds = 0; detail = "skipped" })
}

# =============================================================================
# Stage 6 - Deploy + smoke (Android)
# =============================================================================
if (-not $SkipDeploy -and $devices.Count -gt 0 -and (Test-Path $ApkFinal)) {
    $sw = Start-Stage "deploy"

    Log "adb install -r $ApkFinal ..."
    & $adb install -r $ApkFinal 2>&1 | Tee-Object -Variable iOut | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail-Stage "deploy" $sw "adb install failed" }

    # Kill any stale instance so cold launch is deterministic.
    & $adb shell am force-stop com.transferdaemon.app 2>$null | Out-Null

    # Pre-grant runtime permissions so the first-launch dialogs can't stall the
    # smoke (Fire OS may not know POST_NOTIFICATIONS - that failure is benign).
    foreach ($p in @("android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.POST_NOTIFICATIONS")) {
        & $adb shell pm grant com.transferdaemon.app $p 2>$null | Out-Null
    }

    # Clear logcat so the smoke check only sees fresh app logs.
    & $adb logcat -c 2>$null | Out-Null

    Log "launching com.transferdaemon.app/.PermissionsActivity ..."
    & $adb shell am start -n com.transferdaemon.app/.PermissionsActivity 2>&1 | Out-Host

    # Smoke: poll for the process + daemon-ready markers (Kindles can be slow
    # and logcat floods; also check the app's own on-device log file).
    $appPid = $null
    $booted = $false
    for ($try = 0; $try -lt 20; $try++) {
        Start-Sleep -Seconds 2
        $appPid = (& $adb shell pidof com.transferdaemon.app 2>&1 | Out-String).Trim()
        if ($appPid) {
            $logcat = & $adb logcat -d -t 2000 2>&1 | Out-String
            if ($logcat -match "Daemon ready" -and $logcat -match "Connected to daemon via gRPC") {
                $booted = $true
                break
            }
            # Fallback: the app's rotating file logger always has the markers.
            $pulled = & $adb pull "/sdcard/Android/data/com.transferdaemon.app/files/TransferDaemon/log_0.txt" (Join-Path $env:TEMP "td_smoke_log.txt") 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $env:TEMP "td_smoke_log.txt"))) {
                $file = Get-Content (Join-Path $env:TEMP "td_smoke_log.txt") -Raw
                if ($file -match "Daemon ready" -and $file -match "Connected to daemon via gRPC") {
                    $booted = $true
                    break
                }
            }
        }
    }
    if (-not $appPid) { Fail-Stage "deploy" $sw "app process not running after launch" }
    if (-not $booted) { Fail-Stage "deploy" $sw "daemon did not report ready (pid $appPid) - see $LogFile" }

    Finish-Stage "deploy" $sw $true "pid $appPid, daemon ready + gRPC connected (smoke OK)"
} else {
    Log "[SKIP] deploy skipped (SkipDeploy=$SkipDeploy devices=$($devices.Count) apk=$(Test-Path $ApkFinal))"
    $Results.Add([pscustomobject]@{ stage = "deploy"; ok = $true; seconds = 0; detail = "skipped" })
}

# =============================================================================
# Stage 7 - Report
# =============================================================================
$totalS = [math]::Round($swAll.Elapsed.TotalSeconds, 1)
Banner "Pipeline finished in ${totalS}s - exit code $ExitCode"

$resultsJson = @{
    version = $Version
    finished_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    total_seconds = $totalS
    exit_code = $ExitCode
    stages = @($Results | ForEach-Object {
        [pscustomobject]@{ stage = $_.stage; ok = [bool]$_.ok; seconds = $_.seconds; detail = $_.detail }
    })
} | ConvertTo-Json -Depth 4
Set-Content -Path (Join-Path $LogDir "pipeline_$Ts.json") -Value $resultsJson

foreach ($r in $Results) {
    Log ("  {0,-10} {1}  {2,7}s  {3}" -f $r.stage, $(if ($r.ok) { "OK" } else { "FAIL" }), $r.seconds, $r.detail)
}
Log ""
Log "Artifacts:"
if (Test-Path $ApkFinal) { Log "  APK  -> $ApkFinal" }
Log "  EXEs -> $DistDir (transferd-*, launcher-*, transferd-tui-*)"
Log "Report:"
Log "  Log  -> $LogFile"
Log "  JSON -> $(Join-Path $LogDir "pipeline_$Ts.json")"
Log ""

Stop-Transcript | Out-Null

if ($ExitCode -ne 0) {
    Log "RESULT: [FAIL] pipeline FAILED"
    exit 1
} else {
    Log "RESULT: [OK] ALL STAGES GREEN"
    exit 0
}