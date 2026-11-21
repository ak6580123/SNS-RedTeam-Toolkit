<#
    Builds the final installer: runs build-app.ps1, then publishes the WPF setup program
    (self-contained single-file exe) with the payload embedded.
    Output: dist/Scripter-Setup-<version>.exe
    Use -SkipApp to reuse an existing build/payload.zip.
#>
param([switch]$SkipApp)
$ErrorActionPreference = 'Stop'
$Pkg  = $PSScriptRoot
$Root = Split-Path $Pkg -Parent
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# --- prerequisites
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Fail ".NET SDK 8 or newer not found. Install it (e.g. `winget install Microsoft.DotNet.SDK.8`) and re-run."
}
$sdks = @(& dotnet --list-sdks) | ForEach-Object { [int]($_.Split('.')[0]) }
if (-not ($sdks | Where-Object { $_ -ge 8 })) { Fail ".NET SDK 8+ required; found: $($sdks -join ', ')." }

# --- app bundle
if (-not $SkipApp) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Pkg 'build-app.ps1')
    if ($LASTEXITCODE) { Fail 'App build failed.' }
}
$Payload = Join-Path $Root 'build\payload.zip'
if (-not (Test-Path $Payload)) { Fail "Missing $Payload - run build-app.ps1 first." }

$pp = Get-Content (Join-Path $Root 'pyproject.toml') -Raw
if ($pp -notmatch '(?m)^version\s*=\s*"([^"]+)"') { Fail 'Could not read version from pyproject.toml' }
$Version = $Matches[1]

# --- publish setup
$Pub = Join-Path $Root 'build\setup-publish'
if (Test-Path $Pub) { Remove-Item $Pub -Recurse -Force }
Write-Host "==> Publishing Setup $Version" -ForegroundColor Cyan
& dotnet publish (Join-Path $Pkg 'installer\Setup.csproj') -c Release -o $Pub `
    "-p:Version=$Version" "-p:PayloadPath=$Payload" --nologo -v:minimal
if ($LASTEXITCODE) { Fail 'dotnet publish failed (first build needs network access to restore the runtime pack).' }

$Dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force $Dist | Out-Null
$Out = Join-Path $Dist "Scripter-Setup-$Version.exe"
Copy-Item (Join-Path $Pub 'Setup.exe') $Out -Force
Write-Host ('==> Installer: {0}  ({1:N1} MB)' -f $Out, ((Get-Item $Out).Length / 1MB)) -ForegroundColor Green
