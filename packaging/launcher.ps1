<#
    Scripter launcher - target of the Start Menu / Desktop shortcut.
    Scripter uses plain TCP connects only (no raw sockets), so it needs no
    elevation and this launcher never requests it.
#>
param([string]$Command)

$InstallDir = $PSScriptRoot
$Exe = Join-Path $InstallDir 'scripter.exe'
$Host.UI.RawUI.WindowTitle = 'Scripter'

if (-not (Test-Path $Exe)) {
    Write-Host "scripter.exe not found in $InstallDir - the install looks damaged. Re-run Setup." -ForegroundColor Red
    Read-Host 'Press Enter to close' | Out-Null
    exit 1
}
# Ensure the install dir is on PATH for this session
if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path = "$InstallDir;$env:Path" }

function Invoke-Scripter([string[]]$CmdArgs) { & $Exe @CmdArgs }

$menu = [ordered]@{
    '1' = @{ Label = 'Dashboard (TUI)';                  Args = @('tui') }
    '2' = @{ Label = 'Doctor (check env + config)';       Args = @('doctor') }
    '3' = @{ Label = 'Discover (TCP sweep)';              Args = @('discover') }
    '4' = @{ Label = 'Enumerate (banner grab)';           Args = @('enumerate') }
    '5' = @{ Label = 'Vuln-map (match signatures)';       Args = @('vuln-map') }
    '6' = @{ Label = 'Validate (non-destructive checks)'; Args = @('validate') }
    '7' = @{ Label = 'Report (json,csv,html)';            Args = @('report', '--formats', 'json,csv,html') }
    '8' = @{ Label = 'Run-all (full pipeline)';           Args = @('run-all') }
    '9' = @{ Label = 'Run-all + validate + report';       Args = @('run-all', '--validate', '--formats', 'json,csv,html') }
    'c' = @{ Label = 'CVE lookup (needs [intel] cve_lookup_enabled)'; Args = @('cve-lookup') }
    'e' = @{ Label = 'Edit config (opens in Notepad)';    Args = @() }
    'h' = @{ Label = 'Help (--help)';                     Args = @('--help') }
}

if ($Command) { Invoke-Scripter @($Command); exit $LASTEXITCODE }

while ($true) {
    Write-Host ''
    Write-Host '=== Scripter ===' -ForegroundColor Yellow
    foreach ($k in $menu.Keys) { Write-Host ('  [{0}] {1}' -f $k, $menu[$k].Label) }
    Write-Host '  [q] Quit'
    try { $choice = Read-Host 'Select an option' } catch { break }
    if (-not $choice -or $choice -eq 'q') { break }
    if ($choice -eq 'e') {
        $cfgHome = if ($env:SCRIPTER_HOME) { $env:SCRIPTER_HOME } else { Join-Path $env:LOCALAPPDATA 'Scripter' }
        $cfg = Join-Path $cfgHome 'workspace\config\config.toml'
        if (-not (Test-Path $cfg)) { Invoke-Scripter @('--help') | Out-Null }   # first run seeds the workspace
        if (Test-Path $cfg) { Start-Process notepad.exe $cfg } else { Write-Host "No config yet at $cfg" -ForegroundColor Yellow }
        continue
    }
    if ($menu.Contains($choice)) { Write-Host ''; Invoke-Scripter $menu[$choice].Args }
    else { Write-Host "Unrecognized option: $choice" -ForegroundColor Yellow }
}
