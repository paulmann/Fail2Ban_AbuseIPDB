#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Install the Zabbix agent key for Fail2Ban_AbuseIPDB on this environment's hosts.

.DESCRIPTION
    Copies the UserParameter and the narrow sudo rule, restarts the agent that listens
    on port 10050 (agent 2 or agent 1 - the include directory and the config file
    differ per host), then verifies the key with the agent's own -t mode as the agent
    user.

.PARAMETER VerifyOnly
    Skip the install and just run the -t check and one real value.

.EXAMPLE
    pwsh -File tools/zabbix-agent-install.ps1
#>
param(
    [string]$UserParameterFile = (Join-Path $PSScriptRoot '..\monitoring\zabbix\userparameter_fail2ban_abuseipdb.conf'),
    [string]$SudoersFile = (Join-Path $PSScriptRoot '..\monitoring\zabbix\abuseipdb-metrics-sudoers'),
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'
$ssh = 'C:\Program Files\Git\usr\bin\ssh.exe'
$key = 'fail2ban.abuseipdb.metric[pending_events]'

$Targets = @(
    @{ Name = 'bs535'; Ssh = @('-o', 'BatchMode=yes', 'bs535')
       Include = '/etc/zabbix/zabbix_agentd.d'; Unit = 'zabbix-agent'
       Binary = '/usr/local/sbin/zabbix_agentd'; Conf = '/etc/zabbix/zabbix_agentd.conf' },
    @{ Name = '192.168.31.31'; Ssh = @('-o', 'BatchMode=yes', '-i', "$env:USERPROFILE\.ssh\id_debian_root", 'root@192.168.31.31')
       Include = '/usr/local/etc/zabbix_agentd.conf.d'; Unit = 'zabbix-agent'
       Binary = '/usr/local/sbin/zabbix_agentd'; Conf = '/usr/local/etc/zabbix_agentd.conf' },
    @{ Name = 'deweb-ch'; Ssh = @('-o', 'BatchMode=yes', 'deweb-ch')
       Include = '/etc/zabbix/zabbix_agent2.d'; Unit = 'zabbix-agent2'
       Binary = '/usr/sbin/zabbix_agent2'; Conf = '/etc/zabbix/zabbix_agent2.conf' }
)

$userParameter = Get-Content $UserParameterFile -Raw
$sudoers = Get-Content $SudoersFile -Raw

foreach ($target in $Targets) {
    "=== $($target.Name)"
    $script = if ($VerifyOnly) {
        @"
systemctl is-active '$($target.Unit)'
sudo -u zabbix $($target.Binary) -c $($target.Conf) -t '$key' 2>&1 | tail -3
echo "value: `$(sudo -u zabbix -n /usr/local/sbin/abuseipdb-report --metric pending_events 2>&1)"
"@
    } else {
        @"
set -e
install -d -m 755 '$($target.Include)'
cat > /tmp/up.conf <<'UP'
$userParameter
UP
install -m 644 /tmp/up.conf '$($target.Include)/userparameter_fail2ban_abuseipdb.conf'
cat > /tmp/zbx-sudoers <<'SUDO'
$sudoers
SUDO
install -m 0440 /tmp/zbx-sudoers /etc/sudoers.d/zabbix-abuseipdb
visudo -c -q && echo "sudoers ok"
systemctl restart '$($target.Unit)'
sleep 3
systemctl is-active '$($target.Unit)'
sudo -u zabbix $($target.Binary) -c $($target.Conf) -t '$key' 2>&1 | tail -3
echo "value: `$(sudo -u zabbix -n /usr/local/sbin/abuseipdb-report --metric pending_events 2>&1)"
rm -f /tmp/up.conf /tmp/zbx-sudoers
"@
    }
    $script | & $ssh @($target.Ssh) 'bash -s' 2>&1 | ForEach-Object { "  $_" }
}
