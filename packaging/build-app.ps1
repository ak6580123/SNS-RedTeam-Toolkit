<#
    Builds the standalone (onedir) Scripter bundle and zips it into build/payload.zip.
    Output: build/app/Scripter/  and  build/payload.zip
    Uses a private venv in build/venv, so your project .venv is never touched.
#>
$ErrorActionPreference = 'Stop'
$Pkg   = $PSScriptRoot
$Root  = Split-Path $Pkg -Parent
$Build = Join-Path $Root 'build'
$Venv  = Join-Path $Build 'venv'
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }
New-Item -ItemType Directory -Force $Build | Out-Null

# --- version from pyproject.toml
$pp = Get-Content (Join-Path $Root 'pyproject.toml') -Raw
if ($pp -notmatch '(?m)^version\s*=\s*"([^"]+)"') { Fail 'Could not read version from pyproject.toml' }
$Version = $Matches[1]
$parts = @(($Version -replace '[^0-9.]', '').Split('.')) + @('0', '0', '0', '0')
$Four = ($parts[0..3]) -join '.'
Write-Host "==> Scripter $Version" -ForegroundColor Cyan

# --- find a Python >= 3.11
function Test-Py($exe, $pre) {
    try { $v = & $exe @pre -c 'import sys;print(sys.version_info[0]*100+sys.version_info[1])' 2>$null } catch { return $false }
    if (-not $v) { return $false }
    return ([int]"$v" -ge 311)
}
$cands = @(
    @{ exe = 'py'; pre = @('-3.12') }, @{ exe = 'py'; pre = @('-3.11') }, @{ exe = 'py'; pre = @('-3.13') },
    @{ exe = 'python'; pre = @() }, @{ exe = (Join-Path $Root '.venv\Scripts\python.exe'); pre = @() }
)
$py = $null
foreach ($c in $cands) { if (Test-Py $c.exe $c.pre) { $py = $c; break } }
if (-not $py) { Fail 'Python 3.11+ not found. Install it from python.org (or `winget install Python.Python.3.12`) and re-run.' }

# --- private build venv
if (-not (Test-Path (Join-Path $Venv 'Scripts\python.exe'))) {
    Write-Host '==> Creating build venv'
    & $py.exe @($py.pre) -m venv $Venv; if ($LASTEXITCODE) { Fail 'venv creation failed' }
}
$VPy = Join-Path $Venv 'Scripts\python.exe'
Write-Host '==> Installing dependencies + PyInstaller'
& $VPy -m pip install --quiet --disable-pip-version-check -r (Join-Path $Root 'requirements.txt') pyinstaller
if ($LASTEXITCODE) { Fail 'pip install failed (network access is needed on the first build).' }

# --- assets
if (-not (Test-Path (Join-Path $Pkg 'assets\icon.ico'))) { & powershell -NoProfile -File (Join-Path $Pkg 'make-assets.ps1') }

# --- Windows version resource
$vi = @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($($Four -replace '\.', ', ')), prodvers=($($Four -replace '\.', ', ')), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'Scripter'), StringStruct('FileDescription', 'Scripter'),
    StringStruct('FileVersion', '$Version'), StringStruct('ProductName', 'Scripter'),
    StringStruct('ProductVersion', '$Version'), StringStruct('OriginalFilename', 'scripter.exe')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
"@
$ViPath = Join-Path $Pkg 'version_info.txt'
Set-Content -Path $ViPath -Value $vi -Encoding UTF8

# --- PyInstaller
$AppOut = Join-Path $Build 'app'
if (Test-Path $AppOut) { Remove-Item $AppOut -Recurse -Force }
Write-Host '==> Running PyInstaller (this takes a minute)'
& $VPy -m PyInstaller --noconfirm --clean --distpath $AppOut --workpath (Join-Path $Build 'pyi-work') (Join-Path $Pkg 'scripter.spec')
$rc = $LASTEXITCODE
Remove-Item $ViPath -Force -ErrorAction SilentlyContinue
if ($rc) { Fail 'PyInstaller failed - see output above.' }
$Bundle = Join-Path $AppOut 'Scripter'
if (-not (Test-Path (Join-Path $Bundle 'scripter.exe'))) { Fail 'scripter.exe missing from bundle.' }

# --- files that live next to the exe
New-Item -ItemType Directory -Force (Join-Path $Bundle 'config') | Out-Null
Copy-Item (Join-Path $Root 'config\config.example.toml') (Join-Path $Bundle 'config\config.example.toml')
Copy-Item (Join-Path $Pkg 'LICENSE.txt') $Bundle
Copy-Item (Join-Path $Pkg 'assets\icon.ico') $Bundle
Copy-Item (Join-Path $Pkg 'launcher.ps1') $Bundle
Set-Content -Path (Join-Path $Bundle 'version.txt') -Value $Version -Encoding ASCII

# --- smoke test the frozen exe (isolated workspace)
Write-Host '==> Smoke-testing bundle'
$env:SCRIPTER_HOME = Join-Path $Build 'smoke-home'
$env:SCRIPTER_NO_SPLASH = '1'
& (Join-Path $Bundle 'scripter.exe') --help | Out-Null
$rc = $LASTEXITCODE
Remove-Item Env:SCRIPTER_HOME, Env:SCRIPTER_NO_SPLASH
if ($rc) { Fail 'Frozen scripter.exe --help failed.' }
Remove-Item (Join-Path $Build 'smoke-home') -Recurse -Force -ErrorAction SilentlyContinue

# --- payload zip
$Zip = Join-Path $Build 'payload.zip'
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path (Join-Path $Bundle '*') -DestinationPath $Zip -CompressionLevel Optimal
Write-Host ('==> Payload: {0}  ({1:N1} MB)' -f $Zip, ((Get-Item $Zip).Length / 1MB)) -ForegroundColor Green
