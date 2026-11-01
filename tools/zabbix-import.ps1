#Requires -Version 7.6
#Requires -PSEdition Core
param(
    [switch]$Import,
    [string[]]$Hosts = @('vps-176-99-5-35', 'hp-debian', 'vpn-exit-de-web')
)
$ErrorActionPreference = 'Stop'
$raw = & python C:\AutoClaw\RAGRAF\tools\ragraf.py secrets reveal 'Zabbix администратор md @192.168.31.31' --reason 'import Fail2Ban AbuseIPDB template into Zabbix 22877.ru' 2>&1
$password = ($raw | Select-Object -First 1).ToString().Trim()
$uri = 'https://22877.ru/api_jsonrpc.php'

function Rpc([string]$method, $params, [string]$token = '') {
    $body = @{ jsonrpc = '2.0'; method = $method; params = $params; id = 1 } | ConvertTo-Json -Depth 12
    $headers = @{}
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $body -Headers $headers -TimeoutSec 60
}

$token = (Rpc 'user.login' @{ username = 'md'; password = $password } '').result
$yaml = Get-Content (Join-Path $PSScriptRoot '..\monitoring\zabbix\fail2ban_abuseipdb.yaml') -Raw

if ($Import) {
    $rules = @{
        templates = @{ createMissing = $true; updateExisting = $true }
        items     = @{ createMissing = $true; updateExisting = $true; deleteMissing = $false }
        triggers  = @{ createMissing = $true; updateExisting = $true; deleteMissing = $false }
    }
    $result = Rpc 'configuration.import' @{ format = 'yaml'; rules = $rules; source = $yaml } $token
    "import: $($result | ConvertTo-Json -Depth 4 -Compress)"
}

# template id
$tpl = (Rpc 'template.get' @{ filter = @{ host = @('Fail2Ban AbuseIPDB reporter') }; output = @('templateid', 'host') } $token).result
if (-not $tpl) { throw 'template not found after import' }
$tplId = $tpl[0].templateid
"templateid: $tplId"

# items and triggers that arrived
$items = (Rpc 'item.get' @{ templateids = @($tplId); output = @('name', 'key_', 'value_type', 'type') } $token).result
"items: $($items.Count)"
$trg = (Rpc 'trigger.get' @{ templateids = @($tplId); output = @('description', 'expression', 'priority') } $token).result
"triggers: $($trg.Count)"

# link to hosts, keeping the templates they already have
foreach ($name in $Hosts) {
    $hostRow = (Rpc 'host.get' @{ filter = @{ host = @($name) }; output = @('hostid', 'host'); selectParentTemplates = @('templateid') } $token).result
    if (-not $hostRow) { "host $name : NOT FOUND"; continue }
    $current = @($hostRow[0].parentTemplates | ForEach-Object { @{ templateid = $_.templateid } })
    if ($current | Where-Object { $_.templateid -eq $tplId }) { "host $name : already linked"; continue }
    $templates = @($current) + @(@{ templateid = $tplId })
    $null = Rpc 'host.update' @{ hostid = $hostRow[0].hostid; templates = $templates } $token
    "host $name : linked ($($current.Count) -> $($templates.Count) templates)"
}
