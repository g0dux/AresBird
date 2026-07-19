# Probe a few well-known control-plane HTTP paths (observe-only).
$ErrorActionPreference = "SilentlyContinue"
$target = ($env:ARES_TARGETS -split ",")[0]
$ports = @(($env:ARES_PORTS -split ",") | Where-Object { $_ })
if (-not $ports) { $ports = @(2375, 2379, 8500, 9000, 9090, 3000) }
$paths = @("/version", "/v1/agent/self", "/-/healthy", "/minio/health/live", "/api/health")

foreach ($p in $ports) {
  $scheme = if ([int]$p -in 443, 6443, 8443) { "https" } else { "http" }
  foreach ($path in $paths) {
    $uri = "${scheme}://${target}:${p}${path}"
    try {
      if ($scheme -eq "https") {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
      }
      $req = [System.Net.HttpWebRequest]::Create($uri)
      $req.Method = "GET"
      $req.Timeout = 3000
      $req.UserAgent = "AresBird-control-plane/0.1"
      $req.AllowAutoRedirect = $false
      $resp = $req.GetResponse()
      $code = [int]$resp.StatusCode
      $resp.Close()
    } catch {
      if ($_.Exception.InnerException -and $_.Exception.InnerException.Response) {
        $code = [int]$_.Exception.InnerException.Response.StatusCode
      } elseif ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
      } else { continue }
    }
    if ($code -in 0, 404, 502, 503, 504) { continue }
    @{
      type = "probe_result"
      addr = $target
      port = [int]$p
      probe = "control-plane-hint"
      detail = "GET $path → HTTP $code"
      confidence = 0.55
    } | ConvertTo-Json -Compress
    if ($code -eq 200) {
      $sev = if ([int]$p -in 2375, 2379, 6443) { "high" } else { "medium" }
      @{
        type = "misconfig_finding"
        addr = $target
        port = [int]$p
        finding = "Control-plane path $path reachable on :$p (HTTP $code) — verify auth"
        severity = $sev
      } | ConvertTo-Json -Compress
    }
  }
}
