# Local / CI helper (PowerShell): seed baseline then fail on NEW findings.
# Usage:
#   $env:TARGET = "example.com"; .\scripts\ci-misconfig.ps1
#   $env:PORTS = "apps"; $env:MIN_SEV = "high"; .\scripts\ci-misconfig.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Target = if ($env:TARGET) { $env:TARGET } else { "127.0.0.1" }
$Ports = if ($env:PORTS) { $env:PORTS } else { "web" }
$MinSev = if ($env:MIN_SEV) { $env:MIN_SEV } else { "medium" }
$DataDir = if ($env:ARES_DATA_DIR) { $env:ARES_DATA_DIR } else { Join-Path $Root ".ares-data" }
$env:ARES_DATA_DIR = $DataDir
$env:ARES_QUIET = "1"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$Bin = Join-Path $env:LOCALAPPDATA "aresprobe-target\release\ares.exe"
$BinDbg = Join-Path $env:LOCALAPPDATA "aresprobe-target\debug\ares.exe"
if (-not (Test-Path $Bin)) {
  if (Test-Path $BinDbg) {
    $Bin = $BinDbg
  } else {
    Write-Host "building ares-cli…"
    $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA "aresprobe-target"
    cargo build -p ares-cli --release
    $Bin = Join-Path $env:LOCALAPPDATA "aresprobe-target\release\ares.exe"
  }
}

Write-Host "==> store: $DataDir"
& $Bin test $Target -p $Ports --no-path-probes --save -q --format csv 2>$null

$args = @(
  "test", $Target, "-p", $Ports, "--no-path-probes", "--save",
  "--fail-on-new", "--min-severity", $MinSev, "-q", "--format", "csv"
)
if ($env:ARES_NOTIFY_URL) {
  $args += @("--notify", $env:ARES_NOTIFY_URL, "--notify-on", "new")
}

& $Bin @args
$code = $LASTEXITCODE
Write-Host "ares exit=$code (2 => new findings)"
exit $code
