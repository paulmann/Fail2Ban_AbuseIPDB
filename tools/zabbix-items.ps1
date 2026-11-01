#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference = 'Stop'
$raw = & python C:\AutoClaw\RAGRAF\tools\ragraf.py secrets reveal 'Zabbix администратор md @192.168.31.31' --reason 'check the Fail2Ban AbuseIPDB items on the hosts' 2>&1
$password = ($raw | Select-Object -First 1).ToString().Trim()
$uri = 'https://22877.ru/api_jsonrpc.php'
function Rpc([string]$m, $p, [string]$t = '') {
    $b = @{ jsonrpc = '2.0'; method = $m; params = $p; id = 1 } | ConvertTo-Json -Depth 10
    $h = @{}
    if ($t) { $h['Authorization'] = "Bearer $t" }
    $r = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $b -Headers $h -TimeoutSec 60
    if ($r.error) { throw "$m : $($r.error.data)" }
    $r
}
$token = (Rpc 'user.login' @{ username = 'md'; password = $password } '').result

foreach ($name in @('vps-176-99-5-35', 'hp-debian', 'vpn-exit-de-web')) {
    $hostRow = (Rpc 'host.get' @{ filter = @{ host = @($name) }; output = @('hostid', 'host') } $token).result
    if (-not $hostRow) { "host $name NOT FOUND"; continue }
    $items = (Rpc 'item.get' @{
            hostids = @($hostRow[0].hostid)
            search  = @{ key_ = 'fail2ban.abuseipdb' }
            output  = @('name', 'key_', 'lastvalue', 'lastclock', 'state', 'error')
        } $token).result
    "=== $name : $($items.Count) items"
    foreach ($item in ($items | Sort-Object key_)) {
        "{0,-50} value={1,-12} last={2} state={3} {4}" -f $item.key_, $item.lastvalue, $item.lastclock, $item.state, $item.error
    }
}
