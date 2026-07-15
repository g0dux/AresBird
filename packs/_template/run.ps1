# Pack script scaffold — emit NDJSON Event lines (misconfig_finding / log / banner).
$ErrorActionPreference = "Stop"
$targets = $env:ARES_TARGETS
$ports = $env:ARES_PORTS
# Example finding (edit for real observe logic):
# @{ type = "misconfig_finding"; addr = $targets; port = [int]$ports.Split(',')[0]; finding = "example"; severity = "info" } | ConvertTo-Json -Compress
@{ type = "log"; level = "info"; message = "my-script ok targets=$targets ports=$ports" } | ConvertTo-Json -Compress
