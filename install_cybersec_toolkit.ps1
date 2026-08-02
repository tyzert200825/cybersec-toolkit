# Elara SecOps Toolkit Installer for Windows PowerShell
# Run from the cloned repo directory

$ErrorActionPreference = "Stop"
function WS($m) { Write-Host "`n[*] $m" -ForegroundColor Cyan }
function WOK($m) { Write-Host "    [OK] $m" -ForegroundColor Green }
function WW($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }

WS "Elara SecOps Toolkit Installer"
$Dir = "$env:USERPROFILE\cybersec-toolkit"
$Repo = $PWD.Path
Write-Host "    Target: $Dir"
Write-Host "    Repo:   $Repo"

# 1. Python
WS "Checking Python..."
$pyOK = $false
try { $v = python --version 2>&1; if ($v -match "Python 3") { WOK "Python: $v"; $pyOK = $true } } catch {}
if (!$pyOK) {
    WW "Installing Python 3.12..."
    winget install Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    $v = python --version 2>&1
    if ($v -match "Python 3") { WOK "Python: $v" } else { Write-Host "Restart PowerShell and re-run" -ForegroundColor Red; exit 1 }
}

# 2. Dependencies
WS "Installing dependencies..."
$deps = @("pyserial","smbus2","python-can","pyusb","w1thermsensor","requests","beautifulsoup4","lxml","scikit-learn","numpy","pyyaml","python-dotenv","colorama","tabulate","aiohttp","pyfiglet")
foreach ($d in $deps) {
    Write-Host "    $d..." -NoNewline
    try { pip install $d --quiet 2>&1 | Out-Null; Write-Host " OK" -ForegroundColor Green }
    catch { Write-Host " SKIP" -ForegroundColor Yellow }
}
WOK "Dependencies installed"

# 3. Copy modules
WS "Installing Elara modules..."
if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
Copy-Item -Path "$Repo\elara_modules\*" -Destination $Dir -Recurse -Force
WOK "Modules copied to $Dir"

# 4. Launcher
WS "Creating launcher..."
$bat = @'
@echo off
title Elara SecOps
cd /d "%USERPROFILE%\cybersec-toolkit"
echo.
echo  Elara SecOps - Cybersec Toolkit
echo  ================================
echo  1. Hardware Scanner     (10 interfaces)
echo  2. GitHub Secret Hunter
echo  3. Oops Scanner         (Deleted commits)
echo  4. Code Dorker          (35+ patterns)
echo  5. Google Dorker        (70+ queries)
echo  6. Paste Monitor
echo  7. ML Secret Classifier
echo  8. Web Terminal
echo  9. Full Pipeline
echo.
set /p c=Select (1-9): 
if "%c%"=="1" python hardware_scanner.py --all
if "%c%"=="2" python gh_secret_hunter.py --mode archive
if "%c%"=="3" python oops_scanner.py --hour 2024-01-15-12
if "%c%"=="4" python code_dorker.py --all
if "%c%"=="5" python google_dorker.py
if "%c%"=="6" python paste_monitor.py --continuous
if "%c%"=="7" python ml_secret_classifier.py
if "%c%"=="8" start webshell.html
if "%c%"=="9" python hardware_scanner.py --all --json
pause
'@
Set-Content -Path "$Dir\launcher.bat" -Value $bat -Encoding ASCII
WOK "launcher.bat created"

# 5. Alias
WS "Creating PowerShell alias..."
$alias = "function secops { Set-Location '$Dir'; & '.\launcher.bat' }"
if (Test-Path $PROFILE) {
    $existing = Get-Content $PROFILE -Raw
    if ($existing -notmatch "function secops") { Add-Content -Path $PROFILE -Value "`n$alias"; WOK "secops alias added" }
    else { WOK "alias already exists" }
} else {
    $pd = Split-Path $PROFILE
    if (!(Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force | Out-Null }
    Set-Content -Path $PROFILE -Value $alias
    WOK "profile + alias created"
}

# 6. Verify
WS "Verifying..."
$tools = @("hardware_scanner.py","gh_secret_hunter.py","oops_scanner.py","code_dorker.py","google_dorker.py","paste_monitor.py","ml_secret_classifier.py","secret_patterns.py","webshell.html")
$allOK = $true
foreach ($t in $tools) {
    if (Test-Path "$Dir\$t") { Write-Host "    [OK] $t" -ForegroundColor Green }
    else { Write-Host "    [X]  $t" -ForegroundColor Red; $allOK = $false }
}

Write-Host ""
if ($allOK) { Write-Host "INSTALLATION COMPLETE" -ForegroundColor Green }
else { Write-Host "INSTALLATION PARTIAL" -ForegroundColor Yellow }
Write-Host "  Location: $Dir"
Write-Host "  Launcher: $Dir\launcher.bat"
Write-Host "  Type 'secops' in PowerShell (after restart)"
Write-Host ""
Write-Host "Quick start:" -ForegroundColor Yellow
Write-Host "  python $Dir\hardware_scanner.py --all"
Write-Host "  python $Dir\oops_scanner.py --hour 2024-01-15-12"
Write-Host "  python $Dir\gh_secret_hunter.py --mode archive"
Write-Host ""
