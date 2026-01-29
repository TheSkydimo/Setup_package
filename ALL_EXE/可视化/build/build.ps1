$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vizDir = (Resolve-Path (Join-Path $scriptDir "..")).Path
$repoRoot = (Resolve-Path (Join-Path $vizDir "..")).Path

Write-Host "RepoRoot: $repoRoot"
Set-Location $repoRoot

Write-Host "Install deps..."
python -m pip install --upgrade pip
python -m pip install -r (Join-Path $vizDir "requirements.txt")

$dist = Join-Path $vizDir "dist"
$work = Join-Path $vizDir "build\work"
$spec = Join-Path $vizDir "build\spec"

New-Item -ItemType Directory -Force -Path $dist | Out-Null
New-Item -ItemType Directory -Force -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path $spec | Out-Null

# If the launcher is running, PyInstaller cannot overwrite the EXE (WinError 5).
Write-Host "Ensure ALL_EXE_Launcher.exe is not running..."
try {
  taskkill /IM "ALL_EXE_Launcher.exe" /F 2>$null | Out-Null
} catch {
  # ignore
}

Write-Host "Build EXE..."
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "ALL_EXE_Launcher" `
  --collect-submodules "selenium" `
  --collect-submodules "webdriver_manager" `
  --add-data "$($vizDir)\assets\Unified.iss;assets" `
  --add-data "$($repoRoot)\360_auto_upload.py;assets" `
  --distpath $dist `
  --workpath $work `
  --specpath $spec `
  (Join-Path $vizDir "launcher_gui.py")

Write-Host "Done: $dist\ALL_EXE_Launcher.exe"

