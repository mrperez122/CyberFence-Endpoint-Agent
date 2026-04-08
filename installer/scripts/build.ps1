<#
.SYNOPSIS
    Build the CyberFence Endpoint Protection Agent MSI installer (Windows, WiX Toolset 3.x).

.DESCRIPTION
    Requires:
      - WiX Toolset 3.11+ installed (candle.exe / light.exe on PATH, or set $WixDir)
      - cf-agent.exe already cross-compiled (or run from repo after `cargo build --release`)

.PARAMETER WixDir
    Path to WiX bin directory. Defaults to auto-detection from PATH or
    "C:\Program Files (x86)\WiX Toolset v3.11\bin".

.PARAMETER Configuration
    Build configuration: Release (default) or Debug.

.PARAMETER SignCert
    Optional. Thumbprint of code-signing certificate in the local cert store.
    If provided, the MSI will be signed with signtool.exe.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -SignCert "AB12CD34..." -WixDir "C:\Program Files (x86)\WiX Toolset v3.11\bin"
#>

param(
    [string]$WixDir       = "",
    [string]$Configuration = "Release",
    [string]$SignCert      = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve paths ─────────────────────────────────────────────────────────
$RepoRoot      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$InstallerDir  = Join-Path $RepoRoot "installer"
$WxsDir        = Join-Path $InstallerDir "wix"
$ResourcesDir  = Join-Path $InstallerDir "resources"
$DistDir       = Join-Path $RepoRoot "dist\CyberFence-Endpoint-v0.1.0-Windows"
$BuildDir      = Join-Path $InstallerDir "build"
$OutputMsi     = Join-Path $RepoRoot "dist\CyberFence-Endpoint-v0.1.0.msi"

# ── Locate WiX ────────────────────────────────────────────────────────────
if ($WixDir -eq "") {
    $CandleExe = Get-Command "candle.exe" -ErrorAction SilentlyContinue
    if ($CandleExe) {
        $WixDir = Split-Path $CandleExe.Source
    } else {
        $Default = "C:\Program Files (x86)\WiX Toolset v3.11\bin"
        if (Test-Path $Default) {
            $WixDir = $Default
        } else {
            Write-Error @"
WiX Toolset not found. Install it from https://wixtoolset.org/releases/
or pass -WixDir 'C:\path\to\wix\bin'
"@
        }
    }
}

$Candle = Join-Path $WixDir "candle.exe"
$Light  = Join-Path $WixDir "light.exe"

if (-not (Test-Path $Candle)) { Write-Error "candle.exe not found at: $Candle" }
if (-not (Test-Path $Light))  { Write-Error "light.exe not found at: $Light"  }

Write-Host "Using WiX: $WixDir" -ForegroundColor Cyan

# ── Validate dist directory ───────────────────────────────────────────────
if (-not (Test-Path "$DistDir\cf-agent.exe")) {
    Write-Error @"
cf-agent.exe not found at: $DistDir\cf-agent.exe
Build the agent first:
  cargo build --release --target x86_64-pc-windows-msvc
  copy target\x86_64-pc-windows-msvc\release\cf-agent.exe dist\CyberFence-Endpoint-v0.1.0-Windows\
"@
}

# ── Create build directory ────────────────────────────────────────────────
if (-not (Test-Path $BuildDir)) { New-Item -ItemType Directory -Path $BuildDir | Out-Null }

Write-Host "Build directory: $BuildDir" -ForegroundColor Gray

# ── WiX preprocessor variables ───────────────────────────────────────────
$WixVars = @(
    "-dInstallerResourcesDir=$ResourcesDir",
    "-dDistDir=$DistDir",
    "-dVersion=0.1.0"
)

# ── Step 1: Compile .wxs → .wixobj ───────────────────────────────────────
Write-Host "`n[1/3] Compiling WiX sources..." -ForegroundColor Green

$WxsFiles = Get-ChildItem -Path $WxsDir -Filter "*.wxs" | Select-Object -ExpandProperty FullName

$CandleArgs = @("-nologo", "-arch", "x64", "-out", "$BuildDir\") + $WixVars + $WxsFiles
Write-Host "  candle $($CandleArgs -join ' ')"

& $Candle @CandleArgs
if ($LASTEXITCODE -ne 0) { Write-Error "candle.exe failed with exit code $LASTEXITCODE" }

# ── Step 2: Link .wixobj → .msi ──────────────────────────────────────────
Write-Host "`n[2/3] Linking MSI..." -ForegroundColor Green

$WixobjFiles = Get-ChildItem -Path $BuildDir -Filter "*.wixobj" | Select-Object -ExpandProperty FullName

$LightArgs = @(
    "-nologo",
    "-ext", "WixUIExtension",
    "-ext", "WixUtilExtension",
    "-out", $OutputMsi,
    "-b", $ResourcesDir,
    "-b", $DistDir,
    "-cultures:en-US"
) + $WixobjFiles

Write-Host "  light $($LightArgs -join ' ')"

& $Light @LightArgs
if ($LASTEXITCODE -ne 0) { Write-Error "light.exe failed with exit code $LASTEXITCODE" }

# ── Step 3: Sign the MSI (optional) ──────────────────────────────────────
if ($SignCert -ne "") {
    Write-Host "`n[3/3] Signing MSI..." -ForegroundColor Green

    $SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
    if (-not (Test-Path $SignTool)) {
        $SignTool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }
    if (-not $SignTool) {
        Write-Warning "signtool.exe not found — skipping signing. Install Windows SDK."
    } else {
        & $SignTool sign `
            /sha1  $SignCert `
            /td    sha256 `
            /fd    sha256 `
            /tr    "http://timestamp.digicert.com" `
            /d     "CyberFence Endpoint Protection Agent" `
            /du    "https://www.cyberfenceplatform.com" `
            $OutputMsi

        if ($LASTEXITCODE -ne 0) { Write-Error "signtool.exe failed with exit code $LASTEXITCODE" }
        Write-Host "  MSI signed successfully." -ForegroundColor Green
    }
} else {
    Write-Host "`n[3/3] Signing skipped (no -SignCert provided)." -ForegroundColor Yellow
    Write-Host "  To sign for distribution, re-run with -SignCert '<thumbprint>'" -ForegroundColor Yellow
}

# ── Done ──────────────────────────────────────────────────────────────────
$MsiSize = [math]::Round((Get-Item $OutputMsi).Length / 1MB, 1)
Write-Host "`n✓ MSI built successfully!" -ForegroundColor Green
Write-Host "  Output : $OutputMsi" -ForegroundColor White
Write-Host "  Size   : ${MsiSize} MB" -ForegroundColor White
Write-Host ""
Write-Host "Test: msiexec /i `"$OutputMsi`" /l*v install.log" -ForegroundColor Cyan
