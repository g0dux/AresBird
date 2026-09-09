# Flag well-known high-risk open ports as info findings (observe-only).
$ErrorActionPreference = "SilentlyContinue"
$targets = ($env:ARES_TARGETS -split ",")[0]
$raw = @()
if ($env:ARES_OPEN_PORTS) { $raw += ($env:ARES_OPEN_PORTS -split ",") }
if ($env:ARES_PORTS) { $raw += ($env:ARES_PORTS -split ",") }

$risk = @{
  6379 = @("Redis", "high")
  9200 = @("Elasticsearch", "high")
  11211 = @("Memcached", "high")
  27017 = @("MongoDB", "medium")
  2375 = @("Docker API", "high")
  2379 = @("etcd", "high")
  8500 = @("Consul", "high")
  5984 = @("CouchDB", "high")
  2181 = @("ZooKeeper", "high")
  9090 = @("Prometheus", "high")
  8080 = @("HTTP alt / Jenkins-ish", "low")
  3389 = @("RDP", "medium")
  5900 = @("VNC", "medium")
}

foreach ($entry in $raw) {
  if (-not $entry) { continue }
  $addr = $targets
  $port = $null
  if ($entry -match '^(?<a>[^:]+):(?<p>\d+)') {
    $addr = $Matches.a
    $port = [int]$Matches.p
  } elseif ($entry -match '^\d+$') {
    $port = [int]$entry
  } else { continue }
  if (-not $risk.ContainsKey($port)) { continue }
  $label = $risk[$port][0]
  $sev = $risk[$port][1]
  @{
    type = "misconfig_finding"
    addr = $addr
    port = $port
    finding = "$label port $port open — verify auth and network exposure"
    severity = $sev
  } | ConvertTo-Json -Compress
}
