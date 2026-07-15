# Add AresBird release build to the current PowerShell session PATH.
# Usage (from repo root or anywhere):
#   . .\scripts\path-aresbird.ps1
# Optional: -DebugBuild to prefer debug\ares.exe

param(
    [switch]$DebugBuild,
    [switch]$PersistUser
)

$root = Join-Path $env:LOCALAPPDATA "aresbird-target"
$dir = if ($DebugBuild) {
    Join-Path $root "debug"
} else {
    Join-Path $root "release"
}
$exe = Join-Path $dir "ares.exe"

if (-not (Test-Path $exe)) {
    Write-Host "ares.exe not found at $exe"
    Write-Host "Build first:"
    Write-Host '  $env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\aresbird-target"'
    Write-Host "  cargo build -p ares-cli --release"
    exit 1
}

$env:Path = "$dir;$env:Path"
Write-Host "AresBird on PATH for this session: $dir"
& $exe -q version

if ($PersistUser) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable("Path", "$dir;$userPath", "User")
        Write-Host "Persisted to user PATH. Open a new terminal to use it everywhere."
    } else {
        Write-Host "Already on user PATH."
    }
}
