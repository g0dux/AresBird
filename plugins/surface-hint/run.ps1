# Example NDJSON plugin — emit structured Event lines for AresProbe.
$ErrorActionPreference = "Stop"
$targets = $env:ARES_TARGETS
$ports = $env:ARES_PORTS
if (-not $ports) { $ports = "80,443" }

$msg = "surface-hint targets=$targets ports=$ports"
@{ type = "log"; level = "info"; message = $msg } | ConvertTo-Json -Compress
