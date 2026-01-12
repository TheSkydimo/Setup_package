param(
  [ValidateSet('SKYDIMO','APEX','MAGEELIFE','AARGB')]
  [string]$Product = 'SKYDIMO',
  [string]$Iscc = 'ISCC.exe'
)

$ErrorActionPreference = 'Stop'

function Find-Iscc {
  param([string]$Explicit = $null)

  $candidates = New-Object System.Collections.Generic.List[string]
  if ($Explicit) { $candidates.Add($Explicit) }

  if ($env:ISCC_EXE) { $candidates.Add($env:ISCC_EXE) }

  $fromPath = (Get-Command ISCC.exe -ErrorAction SilentlyContinue)?.Source
  if ($fromPath) { $candidates.Add($fromPath) }

  $candidates.Add("C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe")
  $candidates.Add("C:\\Program Files\\Inno Setup 6\\ISCC.exe")
  $candidates.Add("C:\\Program Files (x86)\\Inno Setup 5\\ISCC.exe")
  $candidates.Add("C:\\Program Files\\Inno Setup 5\\ISCC.exe")

  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) {
      return $c
    }
  }

  return $null
}

$defs = switch ($Product) {
  'SKYDIMO'   { '/DPROD_SKYDIMO' }
  'APEX'      { '/DPROD_APEX' }
  'MAGEELIFE' { '/DPROD_MAGEELIFE' }
  'AARGB'     { '/DPROD_AARGB' }
}

Write-Host "Building product: $Product"
$isccPath = Find-Iscc -Explicit $Iscc
if (-not $isccPath) {
  throw "ISCC.exe not found. Install Inno Setup, or set ISCC_EXE env var, or pass -Iscc 'C:\\Path\\To\\ISCC.exe'."
}

& $isccPath ".\Unified.iss" $defs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

