# Example pack script — emits a log Event for each invocation.
$ErrorActionPreference = "Stop"
$targets = $env:ARES_TARGETS
$ports = $env:ARES_PORTS
$open = $env:ARES_OPEN_PORTS
$msg = "echo-open pack targets=$targets ports=$ports open_ports=$open"
@{ type = "log"; level = "info"; message = $msg } | ConvertTo-Json -Compress
