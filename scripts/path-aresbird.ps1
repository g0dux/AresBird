# Add AresBird build to the current PowerShell session PATH.
# Usage (from repo root or anywhere):
#   . .\scripts\path-aresbird.ps1
# Optional: -DebugBuild to prefer debug\ares.exe
# Default order: release → dist → debug

param(
    [switch]$DebugBuild,
    [switch]$PersistUser
)

$root = Join-Path $env:LOCALAPPDATA "aresbird-target"
# Keep future cargo builds off Desktop (SAC-friendly)
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = $root
}
$candidates = @(
    (Join-Path $root "release"),
    (Join-Path $root "dist"),
    (Join-Path $root "debug")
)

$dir = $null
if ($DebugBuild) {
    $dir = Join-Path $root "debug"
} else {
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "ares.exe")) {
            $dir = $c
            break
        }
    }
    if (-not $dir) { $dir = $candidates[0] }
}

$exe = Join-Path $dir "ares.exe"

if (-not (Test-Path $exe)) {
    Write-Host "ares.exe not found at $exe"
    Write-Host "Build first (artifacts under LOCALAPPDATA; avoids SAC on Desktop sources):"
    Write-Host "  cargo build -p ares-cli --release"
    Write-Host "  # or if SAC blocks release (4551): cargo build -p ares-cli --profile dist"
    Write-Host "  # or: cargo build -p ares-cli"
    exit 1
}

if ($dir -like "*\debug" -and -not $DebugBuild) {
    Write-Host "using debug build (release/dist not found)"
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
