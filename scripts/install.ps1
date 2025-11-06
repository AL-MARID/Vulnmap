Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  Vulnmap Installation Script" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] Python not found. Please install Python 3.8+ from https://www.python.org/" -ForegroundColor Red
    exit 1
}
$versionMatch = [regex]::Match($pythonVersion, "Python (\d+)\.(\d+)")
if ($versionMatch.Success) {
    $majorVersion = [int]$versionMatch.Groups[1].Value
    $minorVersion = [int]$versionMatch.Groups[2].Value
    if ($majorVersion -lt 3 -or ($majorVersion -eq 3 -and $minorVersion -lt 8)) {
        Write-Host "[!] Python 3.8 or higher is required. Current version: $pythonVersion" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""
Write-Host "[*] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "..\venv") {
    Write-Host "[*] Virtual environment already exists. Skipping..." -ForegroundColor Yellow
} else {
    Set-Location ..
    python -m venv venv
    Set-Location scripts
    Write-Host "[+] Virtual environment created" -ForegroundColor Green
}
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
..\venv\Scripts\Activate.ps1
Write-Host ""
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
Write-Host ""
Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
pip install -r ..\requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Dependencies installed successfully" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Creating necessary directories..." -ForegroundColor Yellow
$directories = @("..\logs", "..\data", "..\reports", "..\templates")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Green
    } else {
        Write-Host "[*] Directory already exists: $dir" -ForegroundColor Yellow
    }
}
Write-Host ""
Write-Host "[*] Setting up configuration..." -ForegroundColor Yellow
if (!(Test-Path "..\config\config.yaml")) {
    Copy-Item "..\config\config.example.yaml" "..\config\config.yaml"
    Write-Host "[+] Configuration file created: config\config.yaml" -ForegroundColor Green
    Write-Host "[!] IMPORTANT: Edit config\config.yaml and add your API keys!" -ForegroundColor Yellow
} else {
    Write-Host "[*] Configuration file already exists" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Edit config\config.yaml and add your AI provider API keys" -ForegroundColor White
Write-Host "2. Activate virtual environment: .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "3. Run Vulnmap: python vulnmap.py -u https://example.com" -ForegroundColor White
Write-Host ""
Write-Host "For help: python vulnmap.py --help" -ForegroundColor White
Write-Host "Documentation: See README.md and docs/ folder" -ForegroundColor White
Write-Host ""
Write-Host "WARNING: Only use on authorized targets!" -ForegroundColor Red
Write-Host ""
