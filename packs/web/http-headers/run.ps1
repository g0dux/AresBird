# Light HTTP GET / — emit interesting response headers as NDJSON.
# Works on Windows PowerShell 5+ (pack scripts on Linux CI use builtins).
$ErrorActionPreference = "SilentlyContinue"
$targets = ($env:ARES_TARGETS -split ",")[0]
$ports = @(($env:ARES_PORTS -split ",") | Where-Object { $_ })
if (-not $ports) { $ports = @(80) }

foreach ($p in $ports) {
    $scheme = if ([int]$p -eq 443 -or [int]$p -eq 8443) { "https" } else { "http" }
    $uri = "${scheme}://${targets}:${p}/"
    try {
        # Skip cert errors for observe-only labs
        if ($scheme -eq "https") {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        $req = [System.Net.HttpWebRequest]::Create($uri)
        $req.Method = "GET"
        $req.Timeout = 5000
        $req.UserAgent = "AresBird-http-headers/0.1"
        $req.AllowAutoRedirect = $false
        $resp = $req.GetResponse()
        $server = $resp.Headers["Server"]
        $powered = $resp.Headers["X-Powered-By"]
        $via = $resp.Headers["Via"]
        $code = [int]$resp.StatusCode
        $resp.Close()
        $detail = "HTTP $code Server=$server X-Powered-By=$powered Via=$via"
        @{
            type = "probe_result"
            addr = $targets
            port = [int]$p
            probe = "http-headers"
            detail = $detail
            confidence = 0.7
        } | ConvertTo-Json -Compress
    } catch {
        @{
            type = "log"
            level = "info"
            message = "http-headers ${targets}:${p} — $($_.Exception.Message)"
        } | ConvertTo-Json -Compress
    }
}
