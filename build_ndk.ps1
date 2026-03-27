#Requires -Version 5.1
<#
.SYNOPSIS
    Build dl_interceptor and di_injector for Android using NDK.
.DESCRIPTION
    Auto-detects Android SDK/NDK/CMake paths from environment variables
    and common install locations. Builds the shared library and injector
    (with embedded .so) for all supported ABIs.
.PARAMETER Abi
    Target ABI(s). Default: arm64-v8a (other ABIs untested)
.PARAMETER ApiLevel
    Minimum Android API level. Default: 21
.PARAMETER Clean
    Remove build directory before building.
.PARAMETER NdkPath
    Override NDK path (auto-detected if not set).
#>
param(
    [string[]]$Abi,
    [int]$ApiLevel = 21,
    [switch]$Clean,
    [string]$NdkPath
)

$ErrorActionPreference = "Stop"
$ROOT = (Get-Location).Path -replace '\\', '/'

# ---------------------------------------------------------------------------
# Auto-detect SDK / NDK / CMake
# ---------------------------------------------------------------------------

function Find-AndroidSdk {
    $candidates = @(
        $env:ANDROID_SDK_ROOT,
        $env:ANDROID_HOME,
        "$env:LOCALAPPDATA\Android\Sdk",
        "C:\Android\Sdk",
        "D:\Android\Sdk",
        "$env:USERPROFILE\AppData\Local\Android\Sdk"
    ) | Where-Object { $_ -and (Test-Path "$_\platforms") }
    if ($candidates) { return $candidates[0] }
    return $null
}

function Find-Ndk {
    param([string]$SdkPath)
    if ($NdkPath -and (Test-Path $NdkPath)) { return $NdkPath }
    if ($env:ANDROID_NDK_ROOT -and (Test-Path $env:ANDROID_NDK_ROOT)) { return $env:ANDROID_NDK_ROOT }
    if ($env:NDK_ROOT -and (Test-Path $env:NDK_ROOT)) { return $env:NDK_ROOT }
    # Pick the latest NDK under SDK
    if ($SdkPath) {
        $ndkDir = "$SdkPath\ndk"
        if (Test-Path $ndkDir) {
            $latest = Get-ChildItem $ndkDir -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($latest) { return $latest.FullName }
        }
    }
    return $null
}

function Find-SdkCmake {
    param([string]$SdkPath)
    # Find cmake bundled with Android SDK (has ninja too)
    if ($SdkPath) {
        $cmakeDir = "$SdkPath\cmake"
        if (Test-Path $cmakeDir) {
            $latest = Get-ChildItem $cmakeDir -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($latest -and (Test-Path "$($latest.FullName)\bin\cmake.exe")) {
                return $latest.FullName
            }
        }
    }
    # Fallback: system cmake + ninja
    $sysCmake = Get-Command cmake -ErrorAction SilentlyContinue
    $sysNinja = Get-Command ninja -ErrorAction SilentlyContinue
    if ($sysCmake -and $sysNinja) { return $null }  # signal to use system
    return $null
}

$SDK = Find-AndroidSdk
if (-not $SDK) { throw "Android SDK not found. Set ANDROID_SDK_ROOT or ANDROID_HOME." }
Write-Host "SDK: $SDK" -ForegroundColor DarkGray

$NDK = Find-Ndk -SdkPath $SDK
if (-not $NDK) { throw "Android NDK not found. Set ANDROID_NDK_ROOT or pass -NdkPath." }
Write-Host "NDK: $NDK" -ForegroundColor DarkGray

$CMAKE_HOME = Find-SdkCmake -SdkPath $SDK
if ($CMAKE_HOME) {
    $CMAKE = "$CMAKE_HOME\bin\cmake.exe"
    $NINJA = "$CMAKE_HOME\bin\ninja.exe"
} else {
    $CMAKE = (Get-Command cmake).Source
    $NINJA = (Get-Command ninja).Source
}
Write-Host "CMake: $CMAKE" -ForegroundColor DarkGray
Write-Host "Ninja: $NINJA" -ForegroundColor DarkGray

$TOOLCHAIN = "$NDK\build\cmake\android.toolchain.cmake"
$BUILD_DIR = "build"
$ALL_ABIS  = @("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
$ABIS      = if ($Abi) { $Abi } else { @("arm64-v8a") }

if (-not $Abi) {
    Write-Host "Default ABI: arm64-v8a (use -Abi to build others, e.g. -Abi armeabi-v7a,x86)" -ForegroundColor Yellow
    Write-Host "Note: only arm64-v8a is tested. Other ABIs may work but are not verified." -ForegroundColor Yellow
}

if ($Clean -and (Test-Path $BUILD_DIR)) {
    Write-Host "Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $BUILD_DIR
}

# ---------------------------------------------------------------------------
# Helper: run cmake configure + build
# ---------------------------------------------------------------------------
function Invoke-CMakeBuild {
    param([string[]]$ConfigArgs, [string]$BuildDir, [string]$Label)
    Write-Host "`n=== $Label ===" -ForegroundColor Cyan
    & $CMAKE @ConfigArgs
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed: $Label" }
    & $CMAKE --build $BuildDir --config Release -j $env:NUMBER_OF_PROCESSORS
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $Label" }
    Write-Host "  OK" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 1: Build dl_interceptor shared .so for each ABI
# ---------------------------------------------------------------------------
foreach ($abi in $ABIS) {
    $buildDir = "$BUILD_DIR/lib-$abi"
    Invoke-CMakeBuild -BuildDir $buildDir -Label "dl_interceptor .so ($abi)" -ConfigArgs @(
        "-B", $buildDir,
        "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN",
        "-DANDROID_ABI=$abi",
        "-DANDROID_PLATFORM=android-$ApiLevel",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DANDROID_STL=c++_static",
        "-G", "Ninja",
        "-DCMAKE_MAKE_PROGRAM=$NINJA",
        "-DDI_BUILD_SHARED=ON",
        "-DDI_DUMMY_LIB_NAME=/data/local/tmp/libdl_interceptor_nothing.so"
    )
}

# ---------------------------------------------------------------------------
# Step 2: Build injector with embedded .so for each ABI
# ---------------------------------------------------------------------------
foreach ($abi in $ABIS) {
    $buildDir    = "$BUILD_DIR/injector-$abi"
    $soPath      = "$ROOT/$BUILD_DIR/lib-$abi/libdl_interceptor.so"
    $nothingPath = "$ROOT/$BUILD_DIR/lib-$abi/libdl_interceptor_nothing.so"

    Invoke-CMakeBuild -BuildDir $buildDir -Label "di_injector ($abi)" -ConfigArgs @(
        "-B", $buildDir,
        "-S", "injector",
        "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN",
        "-DANDROID_ABI=$abi",
        "-DANDROID_PLATFORM=android-$ApiLevel",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DANDROID_STL=c++_static",
        "-G", "Ninja",
        "-DCMAKE_MAKE_PROGRAM=$NINJA",
        "-DDI_INTERCEPTOR_SO=$soPath",
        "-DDI_NOTHING_SO=$nothingPath"
    )
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green

foreach ($abi in $ABIS) {
    $inj = Get-Item "$BUILD_DIR/injector-$abi/di_injector" -ErrorAction SilentlyContinue
    if ($inj) {
        $kb = [math]::Round($inj.Length / 1024)
        Write-Host "  $abi : di_injector (${kb} KB)" -ForegroundColor White
    }
}
Write-Host ""
Write-Host "  Usage: adb push build/injector-<abi>/di_injector /data/local/tmp/" -ForegroundColor DarkGray
Write-Host "         adb shell su -c '/data/local/tmp/di_injector -p <package>'" -ForegroundColor DarkGray
Write-Host ""
