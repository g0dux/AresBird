# AresProbe script plugin scaffold
# Reads ARES_CONTEXT_JSON / stdin and emits one Event per stdout line (NDJSON).

$ErrorActionPreference = "Stop"
$ctxRaw = if ($env:ARES_CONTEXT_JSON) { $env:ARES_CONTEXT_JSON } else { [Console]::In.ReadToEnd() }
$targets = $env:ARES_TARGETS
$ports = $env:ARES_PORTS

$msg = "my-plugin ok targets=$targets ports=$ports"
@{ type = "log"; level = "info"; message = $msg } | ConvertTo-Json -Compress
