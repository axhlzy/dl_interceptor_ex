#Requires -Version 5.1
<#
.SYNOPSIS
    Build (if needed), push, and run di_injector on a connected Android device.
.DESCRIPTION
    Auto-detects device architecture, builds the matching ABI if needed,
    pushes to device, and runs with the given arguments.
    Usage is identical to running di_injector directly on the device.
.EXAMPLE
    ./run.ps1 -p com.example.app
    ./run.ps1 -p com.example.app -b libfk.so:1
    ./run.ps1 -p com.example.app -d libfk.so:1 -b libfk.so:1
#>

$ErrorActionPreference = "Stop"

$REMOTE_PATH = "/data/local/tmp/di_injector"

# ---------------------------------------------------------------------------
# Device connection
# ---------------------------------------------------------------------------

function Find-Device {
    if ($env:DI_SSH_TARGET) { return @{ Method = "ssh"; Target = $env:DI_SSH_TARGET } }
    $adb = Get-Command adb -ErrorAction SilentlyContinue
    if ($adb) {
        $devices = & adb devices 2>$null | Select-String "device$"
        if ($devices) { return @{ Method = "adb"; Target = $null } }
    }
    return $null
}

function Invoke-DeviceCmd {
    param([string]$Cmd)
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    if ($script:Device.Method -eq "ssh") {
        $output = & ssh $script:Device.Target $Cmd 2>&1
    } else {
        $output = & adb shell "su -c '$Cmd'" 2>&1
    }
    $ErrorActionPreference = $prev
    $output | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message }
        else { $_ }
    }
}

function Push-File {
    param([string]$Local, [string]$Remote)
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    if ($script:Device.Method -eq "ssh") {
        & scp $Local "$($script:Device.Target):$Remote" 2>&1 | Out-Null
    } else {
        & adb push $Local $Remote 2>&1 | Out-Null
    }
    $ErrorActionPreference = $prev
}

function Get-RemoteMd5 {
    param([string]$Path)
    $out = Invoke-DeviceCmd "md5sum $Path 2>/dev/null"
    if ($out -match '([a-f0-9]{32})') { return $Matches[1] }
    return $null
}

function Get-LocalMd5 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm MD5).Hash.ToLower()
}

# ---------------------------------------------------------------------------
# Detect device ABI
# ---------------------------------------------------------------------------

function Get-DeviceAbi {
    $abi = (Invoke-DeviceCmd "getprop ro.product.cpu.abi") | Select-Object -First 1
    if ($abi) { return $abi.Trim() }
    return $null
}

$ABI_MAP = @{
    "arm64-v8a"   = "arm64-v8a"
    "armeabi-v7a" = "armeabi-v7a"
    "x86_64"      = "x86_64"
    "x86"         = "x86"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Step 1: Connect to device
Write-Host "Connecting to device..." -ForegroundColor DarkGray
$script:Device = Find-Device
if (-not $Device) {
    Write-Host "No device found. Connect via USB (adb) or set DI_SSH_TARGET=root@<ip>" -ForegroundColor Red
    exit 1
}
Write-Host "Device: $($Device.Method)$(if ($Device.Target) { " ($($Device.Target))" })" -ForegroundColor DarkGray

# Step 2: Detect device architecture
$deviceAbi = Get-DeviceAbi
if (-not $deviceAbi -or -not $ABI_MAP.ContainsKey($deviceAbi)) {
    Write-Host "Could not detect device ABI (got: '$deviceAbi'), defaulting to arm64-v8a" -ForegroundColor Yellow
    $deviceAbi = "arm64-v8a"
}
Write-Host "Device ABI: $deviceAbi" -ForegroundColor DarkGray

$ABI = $ABI_MAP[$deviceAbi]
$INJECTOR_REL = "build/injector-$ABI/di_injector"

# Step 3: Build if needed
if (-not (Test-Path $INJECTOR_REL)) {
    Write-Host "Injector not found for $ABI, building..." -ForegroundColor Yellow
    & powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\build_ndk.ps1" -Abi $ABI
    if (-not (Test-Path $INJECTOR_REL)) {
        Write-Host "Build failed" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
}

$localSize = [math]::Round((Get-Item $INJECTOR_REL).Length / 1024)
Write-Host "Binary: $INJECTOR_REL ($localSize KB)" -ForegroundColor DarkGray

# Step 4: Push if needed (compare md5)
$localMd5  = Get-LocalMd5 -Path $INJECTOR_REL
$remoteMd5 = Get-RemoteMd5 -Path $REMOTE_PATH

if ($localMd5 -ne $remoteMd5) {
    Write-Host "Pushing to device..." -ForegroundColor Yellow
    Push-File -Local $INJECTOR_REL -Remote $REMOTE_PATH
    Invoke-DeviceCmd "chmod +x $REMOTE_PATH" | Out-Null
    Write-Host "Pushed OK" -ForegroundColor Green
} else {
    Write-Host "Device binary up to date" -ForegroundColor DarkGray
}

# Step 5: Run with all arguments passed through
$passArgs = $args -join ' '

if (-not $passArgs) {
    Write-Host ""
    Invoke-DeviceCmd "$REMOTE_PATH -h"
    exit 0
}

Write-Host ""
Write-Host ">>> di_injector $passArgs" -ForegroundColor Cyan
Write-Host ""

$prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
if ($Device.Method -eq "ssh") {
    & ssh $Device.Target "$REMOTE_PATH $passArgs" 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { Write-Host $_.Exception.Message }
        else { Write-Host $_ }
    }
} else {
    & adb shell "su -c '$REMOTE_PATH $passArgs'" 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { Write-Host $_.Exception.Message }
        else { Write-Host $_ }
    }
}
$ErrorActionPreference = $prev

# Step 6: Launch logcat if injection succeeded
if ($LASTEXITCODE -eq 0 -and $passArgs -match "(^|\s)-p\s") {
    Write-Host "`nSpawning logcat window..." -ForegroundColor Green
    
    # Use Explorer's Shell.Application to launch as a standard user (de-elevate if current session is admin)
    try {
        $shell = New-Object -ComObject Shell.Application
        if ($Device.Method -eq "ssh") {
            $shell.ShellExecute("pwsh", "-NoExit -Command `"ssh $($Device.Target) logcat -v color -s DLInterceptor`"", "", "", 1)
        } else {
            $shell.ShellExecute("pwsh", "-NoExit -Command `"adb logcat -v color -s DLInterceptor`"", "", "", 1)
        }
    } catch {
        # Fallback to Start-Process if Shell.Application fails
        if ($Device.Method -eq "ssh") {
            Start-Process pwsh -ArgumentList "-NoExit", "-Command", "ssh $($Device.Target) logcat -v color -s DLInterceptor"
        } else {
            Start-Process pwsh -ArgumentList "-NoExit", "-Command", "adb logcat -v color -s DLInterceptor"
        }
    }
}

exit $LASTEXITCODE
