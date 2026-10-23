#!/usr/bin/env bash
# Scripter launcher (Linux/macOS/WSL)
# Shows a menu of pipeline stages and runs the matching CLI command
# against the venv in this project.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHON=""
for candidate in \
    "$ROOT_DIR/.venv-wsl/bin/python" \
    "$ROOT_DIR/.venv/bin/python" \
    "$ROOT_DIR/.venv/Scripts/python.exe"; do
    if [[ -x "$candidate" ]]; then
        PYTHON="$candidate"
        break
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "Warning: no .venv-wsl or .venv found — falling back to 'python3' on PATH." >&2
    echo "Run the install steps in README.md to create a venv first." >&2
    PYTHON="python3"
fi

run_scripter() {
    "$PYTHON" -m scripter "$@"
}

print_menu() {
    echo ""
    echo "=== Scripter launcher ==="
    echo "  [1] Dashboard (TUI)"
    echo "  [2] Doctor (check env + config)"
    echo "  [3] Discover (TCP sweep)"
    echo "  [4] Enumerate (banner grab)"
    echo "  [5] Vuln-map (match signatures)"
    echo "  [6] Validate (non-destructive checks)"
    echo "  [7] Report (json,csv,html)"
    echo "  [8] Run-all (full pipeline)"
    echo "  [9] Run-all + validate + report"
    echo "  [c] CVE lookup (NVD - needs [intel] cve_lookup_enabled)"
    echo "  [h] Help (--help)"
    echo "  [q] Quit"
    echo ""
}

dispatch() {
    case "$1" in
        1) run_scripter tui ;;
        2) run_scripter doctor ;;
        3) run_scripter discover ;;
        4) run_scripter enumerate ;;
        5) run_scripter vuln-map ;;
        6) run_scripter validate ;;
        7) run_scripter report --formats json,csv,html ;;
        8) run_scripter run-all ;;
        9) run_scripter run-all --validate --formats json,csv,html ;;
        c) run_scripter cve-lookup ;;
        h) run_scripter --help ;;
        q|"") return 1 ;;
        *) echo "Unrecognized option: $1" ;;
    esac
    return 0
}

if [[ $# -gt 0 ]]; then
    run_scripter "$@"
    exit $?
fi

while true; do
    print_menu
    read -rp "Select an option: " choice
    dispatch "$choice" || break
done
