<#
    Scripter launcher (Windows / PowerShell)
    Shows a menu of pipeline stages and runs the matching CLI command
    against the venv in this project.
#>

param(
    [string]$Command
)

$RootDir = $PSScriptRoot
$Python = Join-Path $RootDir ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Warning "No .venv found at $Python — falling back to 'python' on PATH."
    Write-Warning "Run the install steps in README.md to create .venv first."
    $Python = "python"
}

function Invoke-Scripter {
    param([string[]]$CmdArgs)
    & $Python -m scripter @CmdArgs
}

$menu = [ordered]@{
    "1" = @{ Label = "Dashboard (TUI)";                     Args = @("tui") }
    "2" = @{ Label = "Doctor (check env + config)";          Args = @("doctor") }
    "3" = @{ Label = "Discover (TCP sweep)";                 Args = @("discover") }
    "4" = @{ Label = "Enumerate (banner grab)";              Args = @("enumerate") }
    "5" = @{ Label = "Vuln-map (match signatures)";          Args = @("vuln-map") }
    "6" = @{ Label = "Validate (non-destructive checks)";    Args = @("validate") }
    "7" = @{ Label = "Report (json,csv,html)";               Args = @("report", "--formats", "json,csv,html") }
    "8" = @{ Label = "Run-all (full pipeline)";               Args = @("run-all") }
    "9" = @{ Label = "Run-all + validate + report";          Args = @("run-all", "--validate", "--formats", "json,csv,html") }
    "c" = @{ Label = "CVE lookup (NVD - needs [intel] cve_lookup_enabled)"; Args = @("cve-lookup") }
    "h" = @{ Label = "Help (--help)";                        Args = @("--help") }
}

if ($Command) {
    Invoke-Scripter -CmdArgs @($Command)
    exit $LASTEXITCODE
}

while ($true) {
    Write-Host ""
    Write-Host "=== Scripter launcher ===" -ForegroundColor Cyan
    foreach ($key in $menu.Keys) {
        Write-Host ("  [{0}] {1}" -f $key, $menu[$key].Label)
    }
    Write-Host "  [q] Quit"
    Write-Host ""
    try {
        $choice = Read-Host "Select an option"
    }
    catch {
        break
    }

    if ($null -eq $choice -or $choice -eq "q" -or $choice -eq "") {
        break
    }

    if ($menu.Contains($choice)) {
        Write-Host ""
        Invoke-Scripter -CmdArgs $menu[$choice].Args
    }
    else {
        Write-Host "Unrecognized option: $choice" -ForegroundColor Yellow
    }
}
