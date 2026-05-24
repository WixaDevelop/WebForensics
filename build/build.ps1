<#
.SYNOPSIS
    Build script for WebForensics — produces dist/WebForensics/ and, if
    Inno Setup is installed, a single-file installer in dist/.

.DESCRIPTION
    Usage from the project root:

        powershell -ExecutionPolicy Bypass -File .\build\build.ps1

    Steps:
      1. Verify Python + required packages are present.
      2. Wipe ``build/`` and ``dist/`` from previous runs.
      3. Run PyInstaller against ``build/webforensics.spec``.
      4. If ``iscc.exe`` (Inno Setup) is on PATH, compile the installer.

#>

$ErrorActionPreference = "Stop"

# 1. Sanity checks ----------------------------------------------------------
Write-Host "==> Checking Python toolchain..." -ForegroundColor Cyan
$pyVersion = (& python --version) 2>&1
Write-Host "    $pyVersion"

Write-Host "==> Ensuring build dependencies..." -ForegroundColor Cyan
& python -m pip install --quiet --upgrade pip
& python -m pip install --quiet -r (Join-Path $PSScriptRoot "..\requirements.txt")

# 2. Clean previous build artefacts ----------------------------------------
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$buildDir    = Join-Path $projectRoot "build"
$distDir     = Join-Path $projectRoot "dist"

foreach ($d in @($distDir, (Join-Path $buildDir "WebForensics"))) {
    if (Test-Path $d) {
        Write-Host "==> Removing $d" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $d
    }
}

# 3. PyInstaller -----------------------------------------------------------
Write-Host "==> Running PyInstaller..." -ForegroundColor Cyan
Push-Location $projectRoot
try {
    & python -m PyInstaller (Join-Path "build" "webforensics.spec") --noconfirm
} finally {
    Pop-Location
}

if (-not (Test-Path (Join-Path $distDir "WebForensics\WebForensics.exe"))) {
    throw "PyInstaller did not produce dist/WebForensics/WebForensics.exe"
}
Write-Host "==> dist/WebForensics built successfully" -ForegroundColor Green

# 4. Optional installer ----------------------------------------------------
$iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue)
if ($null -eq $iscc) {
    Write-Host "==> Inno Setup (iscc.exe) not found on PATH -- skipping installer step" -ForegroundColor Yellow
    Write-Host "    Install from https://jrsoftware.org/isdl.php and re-run to build the installer."
    return
}

Write-Host "==> Building installer with Inno Setup..." -ForegroundColor Cyan
$iss = Join-Path $buildDir "installer.iss"
& iscc.exe $iss
Write-Host "==> Installer ready in dist/" -ForegroundColor Green
