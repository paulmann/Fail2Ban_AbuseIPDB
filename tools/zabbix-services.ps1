#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Create (or update) the "Fail2Ban AbuseIPDB" service tree in Zabbix.

.DESCRIPTION
    Parent service + one child per server. Problems are matched through the service's
    problem tags - server=<host> AND service=fail2ban-abuseipdb - which is exactly what
    the template's triggers carry. This installation has no status rules on any
    service, so problem tags are the matching mechanism here too.

    Idempotent: an existing service with the same name is updated, not duplicated.

.PARAMETER Hosts
    Zabbix host names (technical "host" field), not visible names.

.PARAMETER Status
    Only print the current tree and its statuses (no changes).

.EXAMPLE
    pwsh -File tools/zabbix-services.ps1 -Hosts 'hp-debian','vps-176-99-5-35'
#>
param(
    [string[]]$Hosts = @('vps-176-99-5-35', 'hp-debian', 'vpn-exit-de-web'),
    [string]$ParentName = 'Fail2Ban AbuseIPDB',
    [string]$ServiceTag = 'fail2ban-abuseipdb',
    [switch]$Status
)
$ErrorActionPreference = 'Stop'
$raw = & python C:\AutoClaw\RAGRAF\tools\ragraf.py secrets reveal 'Zabbix администратор md @192.168.31.31' --reason 'manage the Fail2Ban AbuseIPDB service tree' 2>&1
$password = ($raw | Select-Object -First 1).ToString().Trim()
$uri = 'https://22877.ru/api_jsonrpc.php'

function Rpc([string]$method, $params, [string]$token = '') {
    $body = @{ jsonrpc = '2.0'; method = $method; params = $params; id = 1 } | ConvertTo-Json -Depth 12
    $headers = @{}
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    $response = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $body -Headers $headers -TimeoutSec 60
    if ($response.error) { throw "$method : $($response.error.data)" }
    $response
}

$token = (Rpc 'user.login' @{ username = 'md'; password = $password } '').result

if ($Status) {
    $all = (Rpc 'service.get' @{ output = 'extend' } $token).result
    $parent = $all | Where-Object { $_.name -eq $ParentName } | Select-Object -First 1
    if (-not $parent) { "service '$ParentName' not found"; return }
    $children = (Rpc 'service.get' @{ parentids = @($parent.serviceid); output = 'extend' } $token).result
    "parent: $ParentName status=$($parent.status) id=$($parent.serviceid)"
    foreach ($child in $children | Sort-Object name) {
        "  {0,-52} status={1} id={2}" -f $child.name, $child.status, $child.serviceid
    }
    return
}

$existing = (Rpc 'service.get' @{ filter = @{ name = @($ParentName) }; output = @('serviceid', 'name') } $token).result
if ($existing) {
    $parentId = $existing[0].serviceid
    "parent exists: $ParentName ($parentId)"
} else {
    $parentId = (Rpc 'service.create' @{
            name        = $ParentName
            algorithm   = 1   # worst of the children
            sortorder   = 0
            description = 'Ban reporting health per server (template Fail2Ban AbuseIPDB reporter).'
        } $token).result.serviceids[0]
    "parent created: $ParentName ($parentId)"
}

foreach ($server in $Hosts) {
    $childName = "$ParentName / $server"
    $problemTags = @(
        @{ tag = 'server'; operator = 0; value = $server },
        @{ tag = 'service'; operator = 0; value = $ServiceTag }
    )
    $found = (Rpc 'service.get' @{ filter = @{ name = @($childName) }; output = @('serviceid') } $token).result
    if ($found) {
        $null = Rpc 'service.update' @{
            serviceid    = $found[0].serviceid
            parents      = @(@{ serviceid = $parentId })
            algorithm    = 1
            problem_tags = $problemTags
        } $token
        "child updated: $childName ($($found[0].serviceid))"
    } else {
        $newId = (Rpc 'service.create' @{
                name         = $childName
                parents      = @(@{ serviceid = $parentId })
                algorithm    = 1
                sortorder    = 0
                problem_tags = $problemTags
                description  = "Problems tagged server=$server AND service=$ServiceTag."
            } $token).result.serviceids[0]
        "child created: $childName ($newId)"
    }
}

$children = (Rpc 'service.get' @{ parentids = @($parentId); output = 'extend' } $token).result
"tree: $ParentName -> $($children.Count) children"
foreach ($child in $children | Sort-Object name) {
    "  {0,-52} status={1}" -f $child.name, $child.status
}
