#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Drill: prove that a problem tagged like the module moves the service.

.DESCRIPTION
    Creates a temporary trigger on an existing numeric item of one host, with the two
    tags the module's triggers carry, so the trigger fires immediately. Then it waits
    for the service recalculation, prints the child service status, and removes the
    trigger again.

    A green tree does not prove the matching works - a service whose tags do not match
    anything stays green forever. This drill is what tells the two apart.

.PARAMETER HostName
    Zabbix host to drill on (default hp-debian, a lab-safe choice).
#>
param(
    [string]$HostName = 'hp-debian',
    [string]$ServiceTag = 'fail2ban-abuseipdb',
    [string]$ParentName = 'Fail2Ban AbuseIPDB',
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$raw = & python C:\AutoClaw\RAGRAF\tools\ragraf.py secrets reveal 'Zabbix администратор md @192.168.31.31' --reason 'service matching drill' 2>&1
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

$hostRow = (Rpc 'host.get' @{ filter = @{ host = @($HostName) }; output = @('hostid') } $token).result
$hostId = $hostRow[0].hostid

# an existing numeric item that already has a positive value: the trigger fires at once
$items = (Rpc 'item.get' @{
        hostids = @($hostId); output = @('itemid', 'key_', 'lastvalue', 'value_type'); filter = @{ value_type = 3 }
    } $token).result
$pick = $items | Where-Object { $_.lastvalue -and [double]$_.lastvalue -gt 0 } | Select-Object -First 1
if (-not $pick) { throw "no numeric item with a positive value on $HostName" }
"triggering on $($pick.key_) (last value $($pick.lastvalue))"

$drill = "zz drill: service matching on $HostName"
$trigger = (Rpc 'trigger.create' @{
        description = $drill
        expression  = "last(/${HostName}/$($pick.key_))>0"
        priority    = 4
        tags        = @(
            @{ tag = 'server'; value = $HostName },
            @{ tag = 'service'; value = $ServiceTag }
        )
    } $token).result.triggerids[0]
"trigger created: $trigger"

$child = "$ParentName / $HostName"
$moved = $false
for ($i = 1; $i -le 6; $i++) {
    Start-Sleep -Seconds 25
    $service = (Rpc 'service.get' @{ filter = @{ name = @($child) }; output = @('name', 'status') } $token).result
    $problems = @((Rpc 'problem.get' @{ output = @('name'); recent = $true } $token).result |
            Where-Object { $_.name -eq $drill })
    "attempt {0}: problems={1} service status={2}" -f $i, $problems.Count, $service[0].status
    if ($service[0].status -ne '-1') { $moved = $true; break }
}

"result: service matching {0}" -f $(if ($moved) { 'WORKS' } else { 'NOT PROVEN' })

if (-not $Keep) {
    $null = Rpc 'trigger.delete' @(@($trigger)) $token
    "drill trigger removed"
}
