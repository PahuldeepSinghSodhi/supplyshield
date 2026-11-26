# SupplyShield live demo (run from the repository root in PowerShell):
#   powershell -ExecutionPolicy Bypass -File presentation\demo.ps1
# Each step waits for Enter so you can talk between them.

function Step($title, $cmd) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
    Write-Host "> $cmd" -ForegroundColor DarkGray
    Read-Host "Press Enter to run" | Out-Null
    Invoke-Expression $cmd
}

Step "1. A clean package" "python -m supplyshield scan samples/pypi/clean-tidytext"
Step "2. Existing tool on a malicious package: npm audit sees nothing" "Get-Content samples/npm/mal-postinstall-exfil/package.json; Get-Content samples/npm/mal-postinstall-exfil/setup.js"
Step "3. SupplyShield on the same package" "python -m supplyshield scan samples/npm/mal-postinstall-exfil"
Step "4. Hidden base64 payload" "python -m supplyshield scan samples/pypi/mal-obfuscated"
Step "5. Typosquat (lodahs vs lodash)" "python -m supplyshield scan samples/npm/mal-typosquat-lodahs"
Step "6. Poisoned update: what did version 1.1 add?" "python -m supplyshield diff samples/pypi/colorlib-1.0 samples/pypi/colorlib-1.1"
Step "7. Honest limit: the evasive sample is missed" "python -m supplyshield scan samples/pypi/mal-evasive"
