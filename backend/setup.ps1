# ASKQ backend setup (Windows PowerShell).
# Creates .venv if missing, installs pinned dependencies, and installs the
# project-local import-path isolation (see tools\README.md).
# Usage (from the backend folder):  .\setup.ps1
# If script execution is blocked:   powershell -ExecutionPolicy Bypass -File .\setup.ps1

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    Write-Host 'Creating virtual environment (.venv)...'
    python -m venv .venv
}

$py = '.\.venv\Scripts\python.exe'

$sitePackages = & $py -c "import sysconfig; print(sysconfig.get_path('purelib'))"
Copy-Item .\tools\askq_isolate_base_dir.pth -Destination $sitePackages -Force
Write-Host "Installed import-path isolation into $sitePackages"

& $py -m pip install --upgrade pip
& $py -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

Write-Host 'Backend setup complete. Run tests with:  .\.venv\Scripts\python -m pytest'
