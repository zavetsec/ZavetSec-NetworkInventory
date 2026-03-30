#Requires -Version 5.1
<#
.SYNOPSIS
    Zavet-Sec-NetworkInventory - Network subnet scanner and asset inventory.
.DESCRIPTION
    Scans one or more subnets and collects:
      - Host discovery (ICMP ping + TCP port probe fallback)
      - Open ports and running services
      - OS fingerprinting (TTL, WMI, SMB banner)
      - NetBIOS / hostname resolution
      - SMB signing status
      - RDP / WinRM / SSH availability
      - Shared folders enumeration
      - Outdated / EOL OS detection
      - Default credentials check (optional)
      - Export to HTML report + CSV
.PARAMETER Subnets
    One or more subnets in CIDR notation. E.g. '192.168.1.0/24','10.0.0.0/24'
.PARAMETER Ports
    Additional ports to scan beyond the default set.
.PARAMETER Threads
    Number of parallel scan threads. Default = 50.
.PARAMETER TimeoutMs
    TCP connect timeout in milliseconds. Default = 500.
.PARAMETER OutputPath
    Path for HTML report. Default = Desktop.
.PARAMETER CsvPath
    Path for CSV export. Default = Desktop.
.PARAMETER SkipPing
    Skip ICMP ping; probe all hosts directly (slower but more complete).
.PARAMETER ScanShares
    Enumerate SMB shares on discovered hosts (requires network access).
.EXAMPLE
    .\Get-NetworkInventory.ps1 -Subnets '192.168.1.0/24'
    .\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24','10.0.1.0/24' -Threads 100
    .\Get-NetworkInventory.ps1 -Subnets '192.168.1.0/24' -SkipPing -ScanShares
.NOTES
    Version : 1.0
    Author  : ZavetSec (github.com/zavetsec)
    Requires: PowerShell 5.1+
    Note    : Run with appropriate authorization only. Scanning without permission is illegal.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$Subnets = @(),

    [int[]]$Ports      = @(
                            # Remote access & management
                            22,23,3389,5985,5986,5900,5901,4899,
                            # Web
                            80,280,443,591,593,800,808,8000,8008,8080,8081,8443,8800,8888,9000,9080,9090,9443,
                            # Mail
                            25,110,143,465,587,636,993,995,
                            # File transfer
                            20,21,69,115,989,990,2049,
                            # DNS & directory
                            53,88,389,636,3268,3269,
                            # Windows / SMB / RPC
                            135,137,139,445,593,
                            # Databases
                            1433,1434,1521,3306,5432,5984,6379,7474,8086,8087,9042,9200,9300,27017,27018,28017,
                            # Network infrastructure
                            161,162,500,1194,1701,1723,4500,
                            # Application servers & middleware
                            1099,4444,4445,4848,7001,7002,7070,7071,8161,8500,9990,11211,
                            # CI/CD & DevOps
                            2375,2376,2377,4243,8153,8180,8888,9418,
                            # Monitoring & metrics
                            3000,4040,5601,8086,9090,9100,9182,9273,
                            # Other common
                            111,512,513,514,873,1080,1900,2000,2100,3128,3306,4000,6000,6001,6666,8009,10000
                        ),
    [int]   $Threads   = 50,
    [int]   $TimeoutMs = 500,
    [string]$OutputPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\NetworkInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$CsvPath    = "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\NetworkInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$SkipPing,
    [switch]$ScanShares,
    [switch]$FastScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# -------------------------------------------------------
# BANNER
# -------------------------------------------------------
Write-Host ''
Write-Host '    ______                _    ____            ' -ForegroundColor DarkYellow
Write-Host '   |___  /__ _  _____ ___| |_ / __/__ ___     ' -ForegroundColor Yellow
Write-Host '      / // _` |/ / -_)  _||  _\__ \/ -_) _|   ' -ForegroundColor Yellow
Write-Host '     /___\__,_|\_/\___|\__| |_||___/\___|\__|  ' -ForegroundColor DarkYellow
Write-Host ''
Write-Host '    +----------------------------------------------+' -ForegroundColor DarkGray
Write-Host '    |  N E T W O R K   I N V E N T O R Y  v 1.0  |' -ForegroundColor White
Write-Host '    |  SOC/DFIR  //  Zero Dependencies  //  PS5.1 |' -ForegroundColor Gray
Write-Host '    |  github.com/zavetsec                        |' -ForegroundColor DarkGray
Write-Host '    +----------------------------------------------+' -ForegroundColor DarkGray
Write-Host ''
Write-Host ""


if (-not $Subnets -or $Subnets.Count -eq 0 -or ($Subnets.Count -eq 1 -and $Subnets[0] -eq '')) {
    Write-Host ""
    Write-Host "  Enter subnets to scan (CIDR notation, e.g. 192.168.1.0/24)." -ForegroundColor Cyan
    Write-Host "  Multiple subnets: 10.0.0.0/24,10.0.1.0/24" -ForegroundColor Gray
    Write-Host ""
    $inputRaw = Read-Host "  Subnets"
    if (-not $inputRaw -or $inputRaw.Trim() -eq '') {
        Write-Host "  [!] No subnet entered. Exiting." -ForegroundColor Red
        exit 1
    }
    $Subnets = $inputRaw -split '[,;\s]+' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }
}

$global:StartTime = Get-Date
$global:Results   = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
function Write-Section { param([string]$T); Write-Host ""; Write-Host "[*] $T" -ForegroundColor Cyan }
function Write-Info    { param([string]$M); Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Warn    { param([string]$M); Write-Host "  [!] $M" -ForegroundColor Yellow }

# Service name map for common ports
$portServices = @{
    # Remote access
    22='SSH'; 23='Telnet'; 3389='RDP'; 5985='WinRM-HTTP'; 5986='WinRM-HTTPS'
    5900='VNC'; 5901='VNC-1'; 4899='Radmin'
    # Web
    80='HTTP'; 280='HTTP-Mgmt'; 443='HTTPS'; 591='FileMaker'; 593='HTTP-RPC'
    800='HTTP-Alt'; 808='HTTP-Alt'; 8000='HTTP-Alt'; 8008='HTTP-Alt'; 8080='HTTP-Proxy'
    8081='HTTP-Alt'; 8443='HTTPS-Alt'; 8800='HTTP-Alt'; 8888='HTTP-Dev'
    9000='HTTP-Alt'; 9080='HTTP-Alt'; 9090='HTTP-Alt'; 9443='HTTPS-Alt'
    # Mail
    25='SMTP'; 110='POP3'; 143='IMAP'; 465='SMTPS'; 587='SMTP-Sub'
    636='LDAPS'; 993='IMAPS'; 995='POP3S'
    # File transfer
    20='FTP-Data'; 21='FTP'; 69='TFTP'; 115='SFTP'; 989='FTPS-Data'; 990='FTPS'; 2049='NFS'
    # DNS & directory
    53='DNS'; 88='Kerberos'; 389='LDAP'; 3268='LDAP-GC'; 3269='LDAPS-GC'
    # Windows / SMB
    135='MS-RPC'; 137='NetBIOS-NS'; 139='NetBIOS'; 445='SMB'
    # Databases
    1433='MSSQL'; 1434='MSSQL-UDP'; 1521='Oracle'; 3306='MySQL'; 5432='PostgreSQL'
    5984='CouchDB'; 6379='Redis'; 7474='Neo4j'; 8086='InfluxDB'; 9042='Cassandra'
    9200='Elasticsearch'; 9300='ES-Cluster'; 27017='MongoDB'; 27018='MongoDB-2'; 28017='MongoDB-Web'
    # Network
    161='SNMP'; 162='SNMP-Trap'; 500='IKE'; 1194='OpenVPN'; 1701='L2TP'
    1723='PPTP'; 4500='IPSec-NAT'
    # App servers
    1099='Java-RMI'; 4444='JBoss'; 4445='JBoss-2'; 4848='GlassFish'
    7001='WebLogic'; 7002='WebLogic-SSL'; 7070='HTTP-Alt'; 7071='Zimbra'
    8161='ActiveMQ'; 8500='Consul'; 9990='WildFly'; 11211='Memcached'
    # DevOps / containers
    2375='Docker'; 2376='Docker-TLS'; 2377='Docker-Swarm'; 4243='Docker-Alt'
    8153='GoCD'; 8180='Jenkins-Alt'; 9418='Git'
    # Monitoring
    3000='Grafana'; 4040='Spark-UI'; 5601='Kibana'; 9100='NodeExporter'; 9182='WinExporter'; 9273='Prometheus-Alt'
    # Other
    111='RPC'; 512='rexec'; 513='rlogin'; 514='Syslog'; 873='rsync'
    1080='SOCKS'; 1900='UPnP'; 2000='Cisco-SCCP'; 2100='FTP-Alt'
    3128='Squid'; 4000='ICQ'; 6000='X11'; 6001='X11-1'; 6666='IRC'
    8009='AJP'; 10000='Webmin'
                # Huawei
                '3CC786'='Huawei'; '38CA84'='Huawei'; '84BA59'='Huawei'; 'D843AE'='Huawei'
                '846993'='Huawei'; 'BCFCE7'='Huawei'; '047C16'='Huawei'; '74563C'='Huawei'
                '5C60BA'='Huawei'; '4C1FCC'='Huawei'; '000E5E'='Huawei'; '001882'='Huawei'
                '00259E'='Huawei'; '20A680'='Huawei'; '30D17E'='Huawei'; '3C47C9'='Huawei'
                '48D539'='Huawei'; '4C54BB'='Huawei'; '58E289'='Huawei'; '6416F0'='Huawei'
                '70723C'='Huawei'; '74A063'='Huawei'; '788A20'='Huawei'; '84A9C4'='Huawei'
                '88A2D7'='Huawei'; '98E7F5'='Huawei'; 'A08CF8'='Huawei'; 'AC853D'='Huawei'
                'B4430D'='Huawei'; 'BC7574'='Huawei'; 'C8D15E'='Huawei'; 'D4F9A1'='Huawei'
                'E8CD2D'='Huawei'; 'F48E38'='Huawei'; 'F832E4'='Huawei'
                # Proxmox / QEMU
                'BC2411'='Proxmox'
                # ZTE
                '001E73'='ZTE'; '08EBD2'='ZTE'; '1C8769'='ZTE'; '2C957F'='ZTE'
                '3413E8'='ZTE'; '40E0B6'='ZTE'; '5C5178'='ZTE'; '7014A6'='ZTE'
                '80B28A'='ZTE'; 'B07D47'='ZTE'; 'C864C7'='ZTE'; 'D030AD'='ZTE'
                # Ruijie
                '001AAA'='Ruijie'; '001E42'='Ruijie'; '001F65'='Ruijie'; '342573'='Ruijie'
                '5408F0'='Ruijie'; '68B599'='Ruijie'; '748776'='Ruijie'; 'C4E1A1'='Ruijie'
            }

# EOL OS patterns
$eolOS = @(
    'Windows XP','Windows Server 2003','Windows Vista',
    'Windows Server 2008','Windows 7','Windows Server 2012',
    'Windows 8','Windows 8.1'
)

# Risky open ports (should not be internet-facing)
$riskyPorts = @(23,69,111,135,137,139,161,445,512,513,514,1080,1099,1433,1434,1521,2049,2375,2376,3128,3306,3389,4444,4445,4848,4899,5432,5900,5901,6379,6666,7001,7002,8009,8161,9200,11211,27017,27018)

# OUI Vendor Database
$ouiDb = @{
    '0017C8'='AboCom'
    'AC1F6B'='Apple'; '000A27'='Apple'; 'F0D1A9'='Apple'
    '000B86'='Aruba'; '001A1E'='Aruba'
    '000C41'='Asus'; '049226'='Asus'; '107B44'='Asus'; '2C56DC'='Asus'; '38D547'='Asus'
    '3C2AF4'='Canon'
    '000E7F'='Cisco'; '000F23'='Cisco'; '001143'='Cisco'; '0013C4'='Cisco'; '001518'='Cisco'
    '001A2F'='Cisco'; '001B53'='Cisco'; '001C57'='Cisco'; '001D45'='Cisco'; '001E49'='Cisco'
    '001F26'='Cisco'; '002155'='Cisco'; '0022BD'='Cisco'; '0023EB'='Cisco'; '0025B4'='Cisco'
    '2C3124'='Cisco'; '3C0E23'='Cisco'; '58AC78'='Cisco'; '70CA9B'='Cisco'; '8843E1'='Cisco'
    '94D469'='Cisco'; 'A067FB'='Cisco'; 'B0AA77'='Cisco'; 'C47D4F'='Cisco'; 'D072DC'='Cisco'
    '000EB6'='D-Link'; '001195'='D-Link'; '001AA2'='D-Link'; '28107B'='D-Link'; '340804'='D-Link'
    '9094E4'='D-Link'; 'B8A386'='D-Link'
    '001A6B'='Dell'; '001B21'='Dell'; '001D09'='Dell'; '001E4F'='Dell'; '14FEB5'='Dell'
    '18A994'='Dell'; '24B6FD'='Dell'; '5CF9DD'='Dell'; '74E6E2'='Dell'; 'B8AC6F'='Dell'
    '001BD4'='Fortinet'; '0090FB'='Fortinet'; '70673C'='Fortinet'; 'B8AF67'='Fortinet'
    '001788'='HP'; '0018FE'='HP'; '001A4B'='HP'; '001C2E'='HP'; '001E0B'='HP'
    '001F29'='HP'; '002170'='HP'; '0022A3'='HP'; '30E171'='HP'; '5CB901'='HP'
    '9CB654'='HP'
    '000E5E'='Huawei'; '001882'='Huawei'; '00259E'='Huawei'; '003048'='Huawei'; '04F938'='Huawei'
    '0C37DC'='Huawei'; '10B1F8'='Huawei'; '1C8E5C'='Huawei'; '20A680'='Huawei'; '30D17E'='Huawei'
    '3C47C9'='Huawei'; '3CC786'='Huawei'; '38CA84'='Huawei'; '48D539'='Huawei'; '4C1FCC'='Huawei'
    '4C54BB'='Huawei'; '58E289'='Huawei'; '5C60BA'='Huawei'; '6416F0'='Huawei'; '6C8D37'='Huawei'
    '70723C'='Huawei'; '74A063'='Huawei'; '788A20'='Huawei'; '84A9C4'='Huawei'; '84BA59'='Huawei'
    '846993'='Huawei'; '88A2D7'='Huawei'; '98E7F5'='Huawei'; 'A08CF8'='Huawei'; 'AC853D'='Huawei'
    'B4430D'='Huawei'; 'BC7574'='Huawei'; 'BCFCE7'='Huawei'; 'C8D15E'='Huawei'; 'D843AE'='Huawei'
    'D4F9A1'='Huawei'; 'E8CD2D'='Huawei'; 'F48E38'='Huawei'; 'F832E4'='Huawei'; '047C16'='Huawei'
    '00155D'='Hyper-V'; '0050AC'='Hyper-V'
    '001AA0'='Intel'; '001D72'='Intel'; '001FE1'='Intel'; '00216A'='Intel'; '0022FA'='Intel'
    '0023BE'='Intel'; '00248D'='Intel'; 'A4C361'='Intel'; 'B0A819'='Intel'; 'B4B686'='Intel'
    '001A8C'='Juniper'; '0021A1'='Juniper'; '002408'='Juniper'; '28C025'='Juniper'
    '001018'='Lenovo'; '40A8F0'='Lenovo'; '484B0C'='Lenovo'; '88706E'='Lenovo'; 'D0817A'='Lenovo'
    '00004E'='Lexmark'; '002035'='Lexmark'
    '000D3A'='Microsoft'; '0017FA'='Microsoft'; '001DD8'='Microsoft'
    '00177F'='Mikrotik'; '2CC8BA'='Mikrotik'; '48A979'='Mikrotik'; '74D435'='Mikrotik'; 'B8690A'='Mikrotik'
    'C4AD34'='Mikrotik'; 'DC2C6E'='Mikrotik'; 'E48D8C'='Mikrotik'
    '001E2A'='Netgear'; '002275'='Netgear'; '20E52A'='Netgear'; '000B7A'='Netgear'
    '000AE4'='Palo Alto'; '4479ED'='Palo Alto'
    'BC2411'='Proxmox'
    '525400'='QEMU/KVM'; 'FE5400'='QEMU/KVM'
    '001B69'='QNAP'; '0008A5'='QNAP'; '24055F'='QNAP'
    '000AEB'='Realtek'; '00E04C'='Realtek'
    '001170'='Ricoh'
    '001AAA'='Ruijie'; '001E42'='Ruijie'; '342573'='Ruijie'; '5408F0'='Ruijie'; '68B599'='Ruijie'
    '748776'='Ruijie'; 'C4E1A1'='Ruijie'
    '00085D'='Supermicro'; '001C25'='Supermicro'; '002590'='Supermicro'; 'AC9AA9'='Supermicro'
    '001092'='Synology'; '0C7310'='Synology'; '9097D5'='Synology'; 'BC5FF4'='Synology'
    '00036F'='TP-Link'; '1C3BF3'='TP-Link'; '1C61B4'='TP-Link'; '50FA84'='TP-Link'; '549B12'='TP-Link'
    '60E327'='TP-Link'; '8CFDF0'='TP-Link'; 'C4E984'='TP-Link'; 'D83078'='TP-Link'; 'E89CC1'='TP-Link'
    'F8D111'='TP-Link'
    '001F92'='Ubiquiti'; '002722'='Ubiquiti'; '0418D6'='Ubiquiti'; '24A43C'='Ubiquiti'; '44D9E7'='Ubiquiti'
    '68727B'='Ubiquiti'; '78454E'='Ubiquiti'; 'B4FBE4'='Ubiquiti'; 'DC9FDB'='Ubiquiti'; 'F09FC2'='Ubiquiti'
    '000C29'='VMware'; '000569'='VMware'; '001C14'='VMware'; '005056'='VMware'
    '080027'='VirtualBox'; '0A0027'='VirtualBox'
    '000480'='Xerox'
    '001E73'='ZTE'; '08EBD2'='ZTE'; '1C8769'='ZTE'; '2C957F'='ZTE'; '3413E8'='ZTE'
    '40E0B6'='ZTE'; '5C5178'='ZTE'; '7014A6'='ZTE'; '80B28A'='ZTE'; 'B07D47'='ZTE'
    'C864C7'='ZTE'; 'D030AD'='ZTE'
}

# -------------------------------------------------------
# SUBNET EXPANSION
# -------------------------------------------------------
function Get-SubnetHosts {
    param([string]$Cidr)
    $parts   = $Cidr -split '/'
    $ip      = $parts[0]
    $prefix  = [int]$parts[1]
    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt   = [BitConverter]::ToUInt32($ipBytes, 0)
    $mask    = [uint32]([Math]::Pow(2,32) - [Math]::Pow(2, 32 - $prefix))
    $netInt  = $ipInt -band $mask
    $bcInt   = $netInt -bor (-bnot $mask -band [uint32]::MaxValue)
    $hosts   = [System.Collections.Generic.List[string]]::new()
    for ($i = $netInt + 1; $i -lt $bcInt; $i++) {
        $b = [BitConverter]::GetBytes([uint32]$i)
        [Array]::Reverse($b)
        $hosts.Add("$($b[0]).$($b[1]).$($b[2]).$($b[3])")
    }
    return [string[]]$hosts
}

# -------------------------------------------------------
# PORT SCANNER
# -------------------------------------------------------
function Test-TcpPort {
    param([string]$IP, [int]$Port, [int]$Timeout)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
        $tcp.Close()
    } catch {}
    return $false
}

# -------------------------------------------------------
# HOST PROBING
# -------------------------------------------------------
function Get-BannerSafe {
    param([string]$IP, [int]$Port, [int]$Timeout = 1000)
    try {
        $tcp    = [System.Net.Sockets.TcpClient]::new()
        $ar     = $tcp.BeginConnect($IP, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($Timeout, $false)) { $tcp.Close(); return '' }
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = $Timeout
        $buf    = New-Object byte[] 256
        $read   = $stream.Read($buf, 0, 256)
        $tcp.Close()
        if ($read -gt 0) {
            return [System.Text.Encoding]::ASCII.GetString($buf, 0, $read).Trim() -replace '[^\x20-\x7E]',''
        }
    } catch {}
    return ''
}

function Get-OSGuess {
    param([string]$IP)
    # TTL-based OS guess via ping
    try {
        $ping   = [System.Net.NetworkInformation.Ping]::new()
        $reply  = $ping.Send($IP, 1000)
        if ($reply.Status -eq 'Success') {
            $ttl = $reply.Options.Ttl
            if ($ttl -le 64)  { return 'Linux/Unix (TTL<=64)' }
            if ($ttl -le 128) { return 'Windows (TTL<=128)' }
            if ($ttl -le 255) { return 'Cisco/Network (TTL<=255)' }
        }
    } catch {}
    return ''
}

function Get-SMBInfo {
    param([string]$IP)
    $info = @{ Signing=$null; OS=''; Domain=''; Name='' }
    try {
        # SMB negotiate - check signing via raw TCP
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($IP, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(1000, $false)) { $tcp.Close(); return $info }

        $stream = $tcp.GetStream()

        # SMB1 Negotiate Request (minimal)
        $smb1Neg = [byte[]](
            0x00,0x00,0x00,0x54,  # NetBIOS length
            0xFF,0x53,0x4D,0x42,  # SMB magic
            0x72,                  # Command: Negotiate
            0x00,0x00,0x00,0x00,  # NT Status
            0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x31,0x00,
            0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
            0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x30,0x30,0x32,0x00,
            0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x3F,0x3F,0x3F,0x00
        )
        $stream.Write($smb1Neg, 0, $smb1Neg.Length)
        $stream.ReadTimeout = 2000
        $buf  = New-Object byte[] 512
        $read = $stream.Read($buf, 0, 512)
        $tcp.Close()

        if ($read -gt 36) {
            # Check signing flags in SMB response
            # Byte 39 = SecurityMode: bit 3 = signing required, bit 2 = signing enabled
            $secMode = $buf[39]
            if ($secMode -band 0x08) { $info.Signing = 'Required' }
            elseif ($secMode -band 0x04) { $info.Signing = 'Enabled (not required)' }
            else { $info.Signing = 'Disabled' }
        }
    } catch {
        $info.Signing = 'Unknown'
    }
    return $info
}

function Get-WMIInfo {
    param([string]$IP)
    $info = @{ OS=''; Version=''; Domain=''; LastBoot=''; Architecture='' }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $IP -OperationTimeoutSec 3 -EA Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem   -ComputerName $IP -OperationTimeoutSec 3 -EA Stop
        $info.OS           = $os.Caption
        $info.Version      = $os.Version
        $info.Domain       = $cs.Domain
        $info.LastBoot     = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        $info.Architecture = $os.OSArchitecture
    } catch {}
    return $info
}

function Get-NetBIOSName {
    param([string]$IP)
    try {
        $entry = [System.Net.Dns]::GetHostEntry($IP)
        return $entry.HostName
    } catch { return '' }
}

function Get-SMBShares {
    param([string]$IP)
    $shares = @()
    try {
        $shares = Get-SmbShare -CimSession (New-CimSession -ComputerName $IP -OperationTimeoutSec 3 -EA Stop) -EA Stop |
            Where-Object { $_.Name -notmatch '^\w+\$$' } |
            Select-Object -ExpandProperty Name
    } catch {
        try {
            $net = net view "\\$IP" 2>$null
            $shares = $net | Where-Object { $_ -match '^\s+\S+\s+Disk' } |
                      ForEach-Object { ($_ -split '\s+')[1] }
        } catch {}
    }
    return $shares
}

# -------------------------------------------------------
# BUILD TARGET LIST
# -------------------------------------------------------
Write-Section "Building target IP list"

$allTargets = [System.Collections.Generic.List[string]]::new()
foreach ($subnet in $Subnets) {
    try {
        $hosts = Get-SubnetHosts $subnet
        $allTargets.AddRange([string[]]$hosts)
        Write-Info "$subnet -> $($hosts.Count) hosts"
    } catch {
        Write-Warn "Failed to parse subnet: $subnet - $_"
    }
}
Write-Info "Total targets: $($allTargets.Count)"

# -------------------------------------------------------
# PHASE 1: HOST DISCOVERY
# -------------------------------------------------------
Write-Section "Phase 1: Host discovery (ping sweep)"

$liveHosts = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$pingCount  = [System.Threading.ThreadSafeRandom]::new()
$done       = [ref]0

$pingJobs = $allTargets | ForEach-Object -ThrottleLimit $Threads -Parallel {
    $ip   = $_
    $live = $using:liveHosts
    $skip = $using:SkipPing
    $tout = $using:TimeoutMs

    $isLive = $false

    if (-not $skip) {
        try {
            $p = [System.Net.NetworkInformation.Ping]::new()
            $r = $p.Send($ip, [Math]::Min($tout, 1000))
            if ($r.Status -eq 'Success') { $isLive = $true }
        } catch {}
    }

    # Fallback: try common ports if ping fails or SkipPing
    if (-not $isLive) {
        foreach ($p in @(80,443,445,22,3389)) {
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $ar  = $tcp.BeginConnect($ip, $p, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne($tout, $false) -and $tcp.Connected) {
                    $tcp.Close(); $isLive = $true; break
                }
                $tcp.Close()
            } catch {}
        }
    }

    if ($isLive) { $live.Add($ip) }
} 2>$null

# Handle older PS without -Parallel
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $liveHosts = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $runspaces = [System.Collections.Generic.List[hashtable]]::new()
    $pool      = [System.Management.Automation.Runspaces.RunspacePool]::CreateRunspacePool(1, $Threads)
    $pool.Open()

    foreach ($ip in $allTargets) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript({
            param($ip, $tout, $skip)
            $isLive = $false
            if (-not $skip) {
                try {
                    $p = [System.Net.NetworkInformation.Ping]::new()
                    $r = $p.Send($ip, [Math]::Min($tout, 1000))
                    if ($r.Status -eq 'Success') { $isLive = $true }
                } catch {}
            }
            if (-not $isLive) {
                foreach ($port in @(80,443,445,22,3389)) {
                    try {
                        $tcp = [System.Net.Sockets.TcpClient]::new()
                        $ar  = $tcp.BeginConnect($ip, $port, $null, $null)
                        if ($ar.AsyncWaitHandle.WaitOne($tout, $false) -and $tcp.Connected) {
                            $tcp.Close(); $isLive = $true; break
                        }
                        $tcp.Close()
                    } catch {}
                }
            }
            return $isLive
        }).AddArgument($ip).AddArgument($TimeoutMs).AddArgument($SkipPing.IsPresent)

        $runspaces.Add(@{ PS=$ps; Handle=$ps.BeginInvoke(); IP=$ip })
    }

    foreach ($rs in $runspaces) {
        $result = $rs.PS.EndInvoke($rs.Handle)
        if ($result) { $liveHosts.Add($rs.IP) }
        $rs.PS.Dispose()
    }
    $pool.Close(); $pool.Dispose()
}

$liveArray = $liveHosts.ToArray() | Sort-Object { [Version]$_ }
Write-Info "Live hosts: $($liveArray.Count) / $($allTargets.Count)"

if ($liveArray.Count -eq 0) {
    Write-Warn "No live hosts found. Check subnet, firewall rules, or use -SkipPing."
    exit 1
}

# -------------------------------------------------------
# PHASE 2: PORT SCAN + SERVICE DETECTION
# -------------------------------------------------------
Write-Section "Phase 2: Port scanning $($liveArray.Count) hosts on $($Ports.Count) ports"

$scanResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$counter     = [ref]0
$total_hosts = $liveArray.Count

$pool2 = [System.Management.Automation.Runspaces.RunspacePool]::CreateRunspacePool(1, $Threads)
$pool2.Open()
$runspaces2 = [System.Collections.Generic.List[hashtable]]::new()

foreach ($ip in $liveArray) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool2
    [void]$ps.AddScript({
        param($ip, $ports, $tout, $portSvcMap, $scanShares, $eolList, $riskyList, $ouiDb, $fastMode)

        function Test-Port {
            param([string]$IP, [int]$P, [int]$T)
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $ar  = $tcp.BeginConnect($IP, $P, $null, $null)
                $ok  = $ar.AsyncWaitHandle.WaitOne($T, $false)
                if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
                $tcp.Close()
            } catch {}
            return $false
        }

        function Get-Banner {
            param([string]$IP, [int]$P)
            try {
                $tcp    = [System.Net.Sockets.TcpClient]::new()
                $ar     = $tcp.BeginConnect($IP, $P, $null, $null)
                if (-not $ar.AsyncWaitHandle.WaitOne(1500, $false)) { $tcp.Close(); return '' }
                $stream = $tcp.GetStream(); $stream.ReadTimeout = 1500
                $buf    = New-Object byte[] 512
                $read   = $stream.Read($buf, 0, 512); $tcp.Close()
                if ($read -gt 0) {
                    return [System.Text.Encoding]::ASCII.GetString($buf, 0, $read).Trim() -replace '[^\x20-\x7E]',''
                }
            } catch {}
            return ''
        }

        # Scan ports
        $openPorts = @()
        $openSvcs  = @()
        foreach ($p in $ports) {
            if (Test-Port $ip $p $tout) {
                $openPorts += $p
                $svcName = if ($portSvcMap[$p]) { $portSvcMap[$p] } else { "port$p" }
                $openSvcs += $svcName
            }
        }

        # Deduplicate open ports
        $openPorts = @($openPorts | Select-Object -Unique)
        $openSvcs  = @($openSvcs  | Select-Object -Unique)

        # Hostname
        $hostname = ''
        try { $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}

        # Extract domain from hostname if not set via WMI
        if ($hostname -and $hostname -match '\.') {
            $hnParts = $hostname -split '\.', 2
            if (-not $wmiDomain -or $wmiDomain -eq '') {
                $wmiDomain = $hnParts[1]
            }
            $hostname = $hnParts[0]
        }

        # OS via TTL
        $osGuess = ''
        try {
            $ping  = [System.Net.NetworkInformation.Ping]::new()
            $reply = $ping.Send($ip, 1000)
            if ($reply.Status -eq 'Success') {
                $ttl = $reply.Options.Ttl
                $osGuess = if ($ttl -le 64) { 'Linux/Unix' } elseif ($ttl -le 128) { 'Windows' } else { 'Network Device' }
            }
        } catch {}

        # WMI OS info (works only if WMI accessible)
        $wmiOS = ''; $wmiVer = ''; $wmiDomain = ''; $wmiLastBoot = ''; $wmiArch = ''
        try {
            $osObj = Get-CimInstance Win32_OperatingSystem -ComputerName $ip -OperationTimeoutSec 3 -EA Stop
            $csObj = Get-CimInstance Win32_ComputerSystem  -ComputerName $ip -OperationTimeoutSec 3 -EA Stop
            $wmiOS       = $osObj.Caption
            $wmiVer      = $osObj.Version
            $wmiDomain   = $csObj.Domain
            $wmiLastBoot = $osObj.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
            $wmiArch     = $osObj.OSArchitecture
        } catch {}

        # SMB signing check
        $smbSigning = 'N/A'
        if ($openPorts -contains 445) {
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $ar  = $tcp.BeginConnect($ip, 445, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne(1000, $false)) {
                    $stream = $tcp.GetStream()
                    $smb1   = [byte[]](0x00,0x00,0x00,0x54,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,
                               0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                               0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0x00,
                               0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00,
                               0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x30,0x30,0x32,0x00,
                               0x02,0x53,0x4D,0x42,0x20,0x32,0x2E,0x3F,0x3F,0x3F,0x00)
                    $stream.Write($smb1, 0, $smb1.Length)
                    $stream.ReadTimeout = 2000
                    $buf  = New-Object byte[] 512
                    $read = $stream.Read($buf, 0, 512)
                    if ($read -gt 39) {
                        $sec = $buf[39]
                        $smbSigning = if ($sec -band 0x08) { 'Required' }
                                      elseif ($sec -band 0x04) { 'Enabled' }
                                      else { 'Disabled' }
                    }
                }
                $tcp.Close()
            } catch { $smbSigning = 'Unknown' }
        }

        # ---- BANNER GRABBING (extended) ----
        $banners = @{}
        $bannerPorts = @(21,22,23,25,80,110,143,443,445,3389,5985,8080,8443,9200,27017)
        foreach ($bp in $bannerPorts) {
            if ($openPorts -contains $bp) {
                $b = Get-Banner $ip $bp
                if ($b) { $banners[$bp] = $b.Substring(0, [Math]::Min(200, $b.Length)) }
            }
        }

        # ---- ICMP TIMESTAMP FINGERPRINTING ----
        if (-not $fastMode) {
        $icmpTimestamp = $false
        try {
            $sock = [System.Net.Sockets.Socket]::new(
                [System.Net.Sockets.AddressFamily]::InterNetwork,
                [System.Net.Sockets.SocketType]::Raw,
                [System.Net.Sockets.ProtocolType]::Icmp)
            $sock.ReceiveTimeout = 1000
            $tsReq = [byte[]](0x0D,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
            $sum = 0
            for ($i = 0; $i -lt $tsReq.Length; $i += 2) { $sum += ([int]$tsReq[$i] -shl 8) + [int]$tsReq[$i+1] }
            while ($sum -shr 16) { $sum = ($sum -band 0xFFFF) + ($sum -shr 16) }
            $ck = [uint16](-bnot $sum -band 0xFFFF)
            $tsReq[2] = [byte](($ck -shr 8) -band 0xFF); $tsReq[3] = [byte]($ck -band 0xFF)
            $ep2 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($ip), 0)
            $sock.SendTo($tsReq, $ep2) | Out-Null
            $bufTs = New-Object byte[] 128
            try {
                $r2 = $sock.ReceiveFrom($bufTs, [ref]$ep2)
                if ($r2 -gt 0 -and $bufTs[20] -eq 14) { $icmpTimestamp = $true }
            } catch {}
            $sock.Close()
        } catch {}
        } # end -not fastMode (ICMP)

        # ---- SSL/TLS CHECK ----
        $sslInfo = @{}
        if (-not $fastMode) { foreach ($sp in @(443,8443,636,993,995,465,990,9443)) {
            if ($openPorts -contains $sp) {
                try {
                    $tcpSsl = [System.Net.Sockets.TcpClient]::new()
                    $arSsl  = $tcpSsl.BeginConnect($ip, $sp, $null, $null)
                    if ($arSsl.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpSsl.Connected) {
                        $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
                        $sslStream = [System.Net.Security.SslStream]::new($tcpSsl.GetStream(), $false, $cb)
                        try {
                            $sslStream.AuthenticateAsClient($ip)
                            $cert   = $sslStream.RemoteCertificate
                            $proto  = $sslStream.SslProtocol.ToString()
                            $expiry = $null; $subject = ''; $selfSigned = $false; $expired = $false
                            if ($cert) {
                                try { $expiry = [datetime]::Parse($cert.GetExpirationDateString()) } catch {}
                                $subject    = $cert.Subject
                                $selfSigned = ($cert.Subject -eq $cert.Issuer)
                                $expired    = ($expiry -and $expiry -lt (Get-Date))
                            }
                            $sslInfo[$sp] = @{
                                Protocol   = $proto
                                Expiry     = if ($expiry) { $expiry.ToString('yyyy-MM-dd') } else { '' }
                                Subject    = $subject
                                SelfSigned = $selfSigned
                                Expired    = $expired
                                WeakProto  = ($proto -match 'Ssl3|^Tls$|Tls10|Tls11')
                            }
                        } catch {
                            $sslInfo[$sp] = @{ Protocol='Error';WeakProto=$false;SelfSigned=$false;Expired=$false;Expiry='';Subject='' }
                        }
                        try { $sslStream.Close() } catch {}
                    }
                    $tcpSsl.Close()
                } catch {}
            }
        } } # end ssl foreach + fastMode

        # ---- MS17-010 ETERNALBLUE CHECK ----
        $ms17010 = 'N/A'
        if (-not $fastMode -and ($openPorts -contains 445)) {
            try {
                $tcpEB = [System.Net.Sockets.TcpClient]::new()
                $arEB  = $tcpEB.BeginConnect($ip, 445, $null, $null)
                if ($arEB.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpEB.Connected) {
                    $stEB  = $tcpEB.GetStream()
                    $stEB.ReadTimeout = 2000
                    $neg = [byte[]](0x00,0x00,0x00,0x85,0xFF,0x53,0x4D,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x53,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFE,0x00,0x00,0x00,0x00,0x00,0x62,0x00,0x02,0x50,0x43,0x20,0x4E,0x45,0x54,0x57,0x4F,0x52,0x4B,0x20,0x50,0x52,0x4F,0x47,0x52,0x41,0x4D,0x20,0x31,0x2E,0x30,0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x31,0x2E,0x30,0x00,0x02,0x57,0x69,0x6E,0x64,0x6F,0x77,0x73,0x20,0x66,0x6F,0x72,0x20,0x57,0x6F,0x72,0x6B,0x67,0x72,0x6F,0x75,0x70,0x73,0x20,0x33,0x2E,0x31,0x61,0x00,0x02,0x4C,0x4D,0x31,0x2E,0x32,0x58,0x30,0x30,0x32,0x00,0x02,0x4C,0x41,0x4E,0x4D,0x41,0x4E,0x32,0x2E,0x31,0x00,0x02,0x4E,0x54,0x20,0x4C,0x4D,0x20,0x30,0x2E,0x31,0x32,0x00)
                    $stEB.Write($neg, 0, $neg.Length)
                    $bufEB = New-Object byte[] 1024
                    $rdEB  = $stEB.Read($bufEB, 0, 1024)
                    if ($rdEB -gt 36) {
                        $sess = [byte[]](0x00,0x00,0x00,0x63,0xFF,0x53,0x4D,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x07,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFE,0x00,0x00,0x40,0x00,0x0C,0xFF,0x00,0x00,0x00,0xFF,0xFF,0x02,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x26,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                        $stEB.Write($sess, 0, $sess.Length)
                        $rdEB2 = $stEB.Read($bufEB, 0, 1024)
                        if ($rdEB2 -gt 32) {
                            $uid = [BitConverter]::ToUInt16($bufEB, 32)
                            $ntT = [byte[]](0x00,0x00,0x00,0x9F,0xFF,0x53,0x4D,0x42,0xA0,0x00,0x00,0x00,0x00,0x18,0x07,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0xFF,0xFE,[byte]($uid -band 0xFF),[byte](($uid -shr 8) -band 0xFF),0x40,0x00,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x26,0x00,0x00,0x40,0x4A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                            $stEB.Write($ntT, 0, $ntT.Length)
                            $rdEB3 = $stEB.Read($bufEB, 0, 1024)
                            if ($rdEB3 -gt 12) {
                                $status = [BitConverter]::ToUInt32($bufEB, 9)
                                $ms17010 = if ($status -eq 0xC0000205) { 'VULNERABLE' } elseif ($rdEB3 -gt 0) { 'Patched' } else { 'Unknown' }
                            }
                        }
                    }
                    try { $stEB.Close(); $tcpEB.Close() } catch {}
                }
            } catch { $ms17010 = 'Error' }
        }

        # ---- DEFAULT CREDENTIALS CHECK ----
        $weakCreds = @()
        if (-not $fastMode -and ($openPorts -contains 21)) {
            try {
                $ftpReq = [System.Net.FtpWebRequest]::Create("ftp://$ip/")
                $ftpReq.Method      = [System.Net.WebRequestMethods+Ftp]::ListDirectory
                $ftpReq.Credentials = [System.Net.NetworkCredential]::new('anonymous', 'scan@scan.local')
                $ftpReq.Timeout     = 3000
                $ftpResp = $ftpReq.GetResponse()
                $weakCreds += 'FTP:anonymous'
                $ftpResp.Close()
            } catch {}
        }
        if (-not $fastMode -and ($openPorts -contains 6379)) {
            try {
                $tcpR = [System.Net.Sockets.TcpClient]::new()
                $arR  = $tcpR.BeginConnect($ip, 6379, $null, $null)
                if ($arR.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpR.Connected) {
                    $stR = $tcpR.GetStream(); $stR.ReadTimeout = 1500
                    $cmdR = [System.Text.Encoding]::ASCII.GetBytes("PING`r`n")
                    $stR.Write($cmdR, 0, $cmdR.Length)
                    $bufR = New-Object byte[] 64
                    $rdR  = $stR.Read($bufR, 0, 64)
                    if ([System.Text.Encoding]::ASCII.GetString($bufR, 0, $rdR) -match '\+PONG') { $weakCreds += 'Redis:no-auth' }
                    $tcpR.Close()
                }
            } catch {}
        }
        if (-not $fastMode -and ($openPorts -contains 11211)) {
            try {
                $tcpMe = [System.Net.Sockets.TcpClient]::new()
                $arMe  = $tcpMe.BeginConnect($ip, 11211, $null, $null)
                if ($arMe.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpMe.Connected) {
                    $stMe = $tcpMe.GetStream(); $stMe.ReadTimeout = 1500
                    $cmdMe = [System.Text.Encoding]::ASCII.GetBytes("stats`r`n")
                    $stMe.Write($cmdMe, 0, $cmdMe.Length)
                    $bufMe = New-Object byte[] 128
                    $rdMe  = $stMe.Read($bufMe, 0, 128)
                    if ([System.Text.Encoding]::ASCII.GetString($bufMe, 0, $rdMe) -match 'STAT') { $weakCreds += 'Memcached:no-auth' }
                    $tcpMe.Close()
                }
            } catch {}
        }
        if (-not $fastMode -and ($openPorts -contains 27017)) {
            try {
                $tcpMg = [System.Net.Sockets.TcpClient]::new()
                $arMg  = $tcpMg.BeginConnect($ip, 27017, $null, $null)
                if ($arMg.AsyncWaitHandle.WaitOne(2000, $false) -and $tcpMg.Connected) {
                    $stMg = $tcpMg.GetStream(); $stMg.ReadTimeout = 1500
                    $mq = [byte[]](0x3f,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x13,0x00,0x00,0x00,0x10,0x69,0x73,0x6d,0x61,0x73,0x74,0x65,0x72,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
                    $stMg.Write($mq, 0, $mq.Length)
                    $bufMg = New-Object byte[] 256
                    $rdMg  = $stMg.Read($bufMg, 0, 256)
                    if ($rdMg -gt 0) { $weakCreds += 'MongoDB:no-auth' }
                    $tcpMg.Close()
                }
            } catch {}
        }

        # ---- SHARES ----
        $shareList = @()
        if ($scanShares -and ($openPorts -contains 445)) {
            try {
                $net = & net view "\\$ip" 2>$null
                $shareList = $net | Where-Object { $_ -match 'Disk' } |
                    ForEach-Object { ($_ -split '\s+') | Where-Object { $_ } | Select-Object -First 1 }
            } catch {}
        }

        # ---- MAC ADDRESS + OUI VENDOR LOOKUP ----
        $macAddress = ''
        $vendor     = ''
        try {
            # Try ARP cache first (fast, no privileges needed)
            $arpOut = & arp -a $ip 2>$null
            foreach ($line in $arpOut) {
                if ($line -match [regex]::Escape($ip) + '\s+([\da-fA-F\-]{17})') {
                    $macAddress = $Matches[1].ToUpper().Replace('-',':')
                    break
                }
            }
            # If not in ARP cache, send a ping to populate it then retry
            if (-not $macAddress) {
                try {
                    $p2 = [System.Net.NetworkInformation.Ping]::new()
                    $p2.Send($ip, 500) | Out-Null
                } catch {}
                $arpOut2 = & arp -a $ip 2>$null
                foreach ($line in $arpOut2) {
                    if ($line -match [regex]::Escape($ip) + '\s+([\da-fA-F\-]{17})') {
                        $macAddress = $Matches[1].ToUpper().Replace('-',':')
                        break
                    }
                }
            }
        } catch {}

        # OUI vendor lookup (database passed from main scope)
        if ($macAddress -and $ouiDb) {
            $oui = $macAddress.Substring(0,8).Replace(':','').ToUpper()
            if ($ouiDb.ContainsKey($oui)) { $vendor = $ouiDb[$oui] }
            else {
                $oui6 = $oui.Substring(0,6)
                if ($ouiDb.ContainsKey($oui6)) { $vendor = $ouiDb[$oui6] }
                else { $vendor = 'Unknown' }
            }
        }

        # ---- RISK ASSESSMENT ----
        $risks = @()
        $openRisky = $openPorts | Where-Object { $_ -in $riskyList }
        if ($openRisky)                              { $risks += "Risky ports: $($openRisky -join ',')" }
        if ($smbSigning -eq 'Disabled' -and ($openPorts -contains 445)) { $risks += 'SMB signing disabled' }
        if ($openPorts -contains 23)                 { $risks += 'Telnet open' }
        if ($openPorts -contains 21)                 { $risks += 'FTP open' }
        if ($ms17010 -eq 'VULNERABLE')               { $risks += 'MS17-010 EternalBlue!' }
        if ($weakCreds.Count -gt 0)                  { $risks += "Weak creds: $($weakCreds -join ', ')" }
        if ($icmpTimestamp)                          { $risks += 'ICMP Timestamp reply' }
        foreach ($sp in $sslInfo.Keys) {
            $si = $sslInfo[$sp]
            if ($si.WeakProto)  { $risks += "Weak TLS/$sp ($($si.Protocol))" }
            if ($si.Expired)    { $risks += "Cert expired/$sp ($($si.Expiry))" }
            if ($si.SelfSigned) { $risks += "Self-signed/$sp" }
        }
        $isEOL = $false
        foreach ($e in $eolList) { if ($wmiOS -match [Regex]::Escape($e)) { $isEOL = $true; $risks += "EOL OS: $wmiOS"; break } }

        $riskLevel = if ($isEOL -or ($openPorts -contains 23) -or ($ms17010 -eq 'VULNERABLE')) { 'CRITICAL' }
                     elseif ($smbSigning -eq 'Disabled' -or $weakCreds.Count -gt 0 -or $openRisky.Count -gt 3) { 'HIGH' }
                     elseif ($risks.Count -gt 0) { 'MEDIUM' }
                     else { 'LOW' }

        $finalOS = if ($wmiOS) { $wmiOS } else { $osGuess }

        return [PSCustomObject]@{
            IP            = $ip
            Hostname      = $hostname
            OS            = $finalOS
            OSVersion     = $wmiVer
            Architecture  = $wmiArch
            Domain        = $wmiDomain
            LastBoot      = $wmiLastBoot
            OpenPorts     = $openPorts
            Services      = $openSvcs
            PortCount     = $openPorts.Count
            SmbSigning    = $smbSigning
            Banners       = $banners
            Shares        = $shareList
            Risks         = $risks
            RiskLevel     = $riskLevel
            IsEOL         = $isEOL
            MS17010       = $ms17010
            WeakCreds     = $weakCreds
            SSLInfo       = $sslInfo
            ICMPTimestamp = $icmpTimestamp
            MacAddress    = $macAddress
            Vendor        = $vendor
            HasRDP        = ($openPorts -contains 3389)
            HasWinRM      = ($openPorts -contains 5985 -or $openPorts -contains 5986)
            HasSSH        = ($openPorts -contains 22)
            HasSMB        = ($openPorts -contains 445)
            HasDB         = ($openPorts | Where-Object { $_ -in @(1433,1521,3306,5432,6379,27017) }).Count -gt 0
        }
    }).AddArgument($ip).AddArgument($Ports).AddArgument($TimeoutMs).AddArgument($portServices).AddArgument($ScanShares.IsPresent).AddArgument($eolOS).AddArgument($riskyPorts).AddArgument($ouiDb).AddArgument($FastScan.IsPresent)

    $runspaces2.Add(@{ PS=$ps; Handle=$ps.BeginInvoke(); IP=$ip })
}

# Collect results with progress
$completed = 0
foreach ($rs in $runspaces2) {
    $result = $rs.PS.EndInvoke($rs.Handle)
    if ($result) { $scanResults.Add($result) }
    $rs.PS.Dispose()
    $completed++
    $pct = [Math]::Round($completed / $liveArray.Count * 100)
    Write-Progress -Activity "Scanning hosts" -Status "$completed / $($liveArray.Count) ($pct%)" -PercentComplete $pct
}
$pool2.Close(); $pool2.Dispose()
Write-Progress -Activity "Scanning hosts" -Completed

$allResults = $scanResults.ToArray() | Sort-Object { [Version]$_.IP }
Write-Info "Scan complete: $($allResults.Count) hosts profiled"

# -------------------------------------------------------
# EXPORT CSV
# -------------------------------------------------------
Write-Section "Exporting CSV"
$allResults | Select-Object IP,Hostname,OS,OSVersion,Domain,LastBoot,PortCount,SmbSigning,RiskLevel,IsEOL,HasRDP,HasWinRM,HasSSH,HasSMB,HasDB,
    @{N='OpenPorts';E={$_.OpenPorts -join ','}},
    @{N='Services'; E={$_.Services  -join ','}},
    @{N='Risks';    E={$_.Risks     -join ' | '}} |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Info "CSV saved: $CsvPath"

# -------------------------------------------------------
# STATISTICS
# -------------------------------------------------------
$statsTotal    = $allResults.Count
$statsWindows  = ($allResults | Where-Object { $_.OS -match 'Windows' }).Count
$statsLinux    = ($allResults | Where-Object { $_.OS -match 'Linux|Unix' }).Count
$statsEOL      = ($allResults | Where-Object { $_.IsEOL }).Count
$statsRDP      = ($allResults | Where-Object { $_.HasRDP }).Count
$statsWinRM    = ($allResults | Where-Object { $_.HasWinRM }).Count
$statsSSH      = ($allResults | Where-Object { $_.HasSSH }).Count
$statsSMBUnsigned = ($allResults | Where-Object { $_.SmbSigning -eq 'Disabled' }).Count
$statsDBOpen   = ($allResults | Where-Object { $_.HasDB }).Count
$statsCritical = ($allResults | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
$statsHigh     = ($allResults | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
$statsMedium   = ($allResults | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count

# Top open ports
$portFreq = @{}
foreach ($r in $allResults) { foreach ($p in $r.OpenPorts) { $portFreq[$p] = ($portFreq[$p] -as [int]) + 1 } }
$topPorts = $portFreq.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10

# OS distribution
$osDist = $allResults | Group-Object {
    if ($_.OS -match 'Windows Server 2022') { 'WinSrv 2022' }
    elseif ($_.OS -match 'Windows Server 2019') { 'WinSrv 2019' }
    elseif ($_.OS -match 'Windows Server 2016') { 'WinSrv 2016' }
    elseif ($_.OS -match 'Windows Server 2012') { 'WinSrv 2012 (EOL)' }
    elseif ($_.OS -match 'Windows Server 2008') { 'WinSrv 2008 (EOL)' }
    elseif ($_.OS -match 'Windows 11') { 'Win 11' }
    elseif ($_.OS -match 'Windows 10') { 'Win 10' }
    elseif ($_.OS -match 'Windows 7')  { 'Win 7 (EOL)' }
    elseif ($_.OS -match 'Linux')      { 'Linux' }
    elseif ($_.OS -match 'Windows')    { 'Windows (other)' }
    elseif ($_.OS -match 'Network')    { 'Network Device' }
    else { 'Unknown' }
} | Sort-Object Count -Descending

# -------------------------------------------------------
# HTML REPORT
# -------------------------------------------------------
Write-Section "Generating HTML Report"

$duration = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")

function Get-RiskColor { param([string]$r)
    switch ($r) { 'CRITICAL'{'#ff2d55'} 'HIGH'{'#ff6b00'} 'MEDIUM'{'#ffd60a'} 'LOW'{'#30d158'} default{'#6e6e73'} }
}

# Host table rows
$hostRows = foreach ($h in $allResults) {
    $rc     = Get-RiskColor $h.RiskLevel
    $portsHtml = [System.Text.StringBuilder]::new()
    [void]$portsHtml.Append("<table class='port-tbl'>")
    foreach ($p in $h.OpenPorts) {
        $pi = [int]"$p"
        $sn = ''; if ($portServices.ContainsKey($pi)) { $sn = [string]$portServices[$pi] }
        $pc = if ($pi -in $riskyPorts) { '#ff6b00' } else { '#00d4ff' }
        $sc = ''
        if ($pi -eq 3389)                                        { $sc = 'rdp' }
        elseif ($pi -eq 5985 -or $pi -eq 5986)                  { $sc = 'winrm' }
        elseif ($pi -eq 22)                                      { $sc = 'ssh' }
        elseif ($pi -eq 445)                                     { $sc = 'smb' }
        elseif ($pi -eq 1433 -or $pi -eq 1521 -or $pi -eq 3306 -or $pi -eq 5432 -or $pi -eq 6379 -or $pi -eq 27017) { $sc = 'db' }
        $bg = ''
        if ($sn -ne '') {
            if ($sc -ne '') { $bg = "<span class='svc " + $sc + "'>" + $sn + "</span>" }
            else            { $bg = "<span style='display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;background:#181828;color:#6e6e80;border:1px solid #282838'>" + $sn + "</span>" }
        }
        [void]$portsHtml.Append('<tr><td style="font-family:Courier New,monospace;font-size:10px;color:' + $pc + ';padding:2px 5px 2px 0;min-width:36px;font-size:10px;text-align:right">' + "$pi" + '</td><td style="padding:2px 0;vertical-align:middle">' + $bg + '</td></tr>')
    }
    [void]$portsHtml.Append("</table>")
    $portsHtmlOut = $portsHtml.ToString()
    $riskItems = @($h.Risks | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
    $risks = if ($riskItems.Count -gt 0) {
        $rb = [System.Text.StringBuilder]::new()
        [void]$rb.Append("<table class='port-tbl'>")
        foreach ($ri in $riskItems) {
            $rColor = if ($ri -match 'EternalBlue|VULNERABLE|EOL|Telnet') { '#ff2d55' }
                      elseif ($ri -match 'SMB sign|Weak creds|Weak TLS|expired|FTP open') { '#ff6b00' }
                      elseif ($ri -match 'Self-signed|ICMP|Risky') { '#ffd60a' }
                      else { '#a0a0c0' }
            [void]$rb.Append('<tr><td style="padding:2px 0;white-space:nowrap"><span style="display:inline-block;padding:1px 7px;border-radius:3px;font-size:9px;font-weight:700;background:#1a1020;border:1px solid ' + $rColor + ';color:' + $rColor + '">' + $ri + '</span></td></tr>')
        }
        [void]$rb.Append("</table>")
        $rb.ToString()
    } else { '' }
    $smbClr = switch ($h.SmbSigning) { 'Required'{'#30d158'} 'Enabled'{'#ffd60a'} 'Disabled'{'#ff2d55'} default{'#6e6e80'} }
    $osClr  = if ($h.IsEOL) { '#ff2d55' } else { '#e2e2e8' }
    $hn     = [System.Net.WebUtility]::HtmlEncode($(if($h.Hostname){$h.Hostname}else{'-'}))
    $os     = [System.Net.WebUtility]::HtmlEncode($(if($h.OS){$h.OS}else{'-'}))
    $dom    = [System.Net.WebUtility]::HtmlEncode($(if($h.Domain){$h.Domain}else{'-'}))
    $macRaw    = @($h.MacAddress | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
    $macStr    = if ($macRaw.Count -gt 0) { $macRaw[0] } else { '' }
    $vendorRaw = @($h.Vendor | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
    $vendorStr = if ($vendorRaw.Count -gt 0) { $vendorRaw[0] } else { '' }

    $eolTag   = if ($h.IsEOL) { '<span class="eol-tag">EOL</span>' } else { '' }
    $row = [System.Text.StringBuilder]::new()
    [void]$row.Append('<tr>')
    [void]$row.Append("<td><span class='badge' style='background:$rc'>$($h.RiskLevel)</span></td>")
    [void]$row.Append("<td class='ip'>$($h.IP)</td>")
    [void]$row.Append("<td class='hn'>$hn</td>")
    [void]$row.Append("<td style='color:$osClr;font-size:11px'>$os$eolTag</td>")
    [void]$row.Append("<td class='dom'>$dom</td>")
    [void]$row.Append("<td style='color:$smbClr;font-size:11px'>$($h.SmbSigning)</td>")
    [void]$row.Append("<td style='min-width:180px;vertical-align:top;padding:6px 10px'>")
    [void]$row.Append($portsHtmlOut)
    [void]$row.Append('</td>')
    [void]$row.Append("<td>$risks</td>")
    $macCell = if ($macStr) {
        "<td style='font-family:Courier New,monospace;font-size:10px;vertical-align:top;padding:6px 10px'>" +
        "<span style='color:#00d4ff'>" + $macStr + "</span>" +
        $(if ($vendorStr) { "<br><span style='color:#6e6e80;font-size:9px'>" + $vendorStr + "</span>" } else { "" }) +
        "</td>"
    } else { "<td style='color:#3a3a55;font-size:10px'>-</td>" }
    [void]$row.Append($macCell)
    [void]$row.Append('</tr>')
    $row.ToString()
}

$osDistRows = ($osDist | ForEach-Object {
    $pct = [Math]::Round($_.Count / $statsTotal * 100)
    $bar = [Math]::Round($pct * 1.4)
    $clr = if ($_.Name -match 'EOL') { '#ff2d55' } elseif ($_.Name -match 'Windows') { '#00d4ff' } elseif ($_.Name -match 'Linux') { '#30d158' } else { '#6e6e80' }
    "<tr><td style='color:$clr;font-size:11px'>$($_.Name)</td><td>$($_.Count)</td><td><div style='background:#181828;border-radius:3px;height:6px;width:140px'><div style='background:$clr;height:6px;border-radius:3px;width:${bar}px'></div></div></td><td style='color:#6e6e80;font-size:10px'>$pct%</td></tr>"
}) -join "`n"

$portDistRows = ($topPorts | ForEach-Object {
    $sn  = if ($portServices[$_.Name]) { $portServices[$_.Name] } else { '' }
    $pct = [Math]::Round($_.Value / $statsTotal * 100)
    $bar = [Math]::Round($pct * 1.4)
    $clr = if ($_.Name -in $riskyPorts) { '#ff6b00' } else { '#00d4ff' }
    "<tr><td style='color:$clr;font-family:Courier New,monospace;font-size:11px'>$($_.Name)$(if($sn){`"/$sn`"})</td><td>$($_.Value)</td><td><div style='background:#181828;border-radius:3px;height:6px;width:140px'><div style='background:$clr;height:6px;border-radius:3px;width:${bar}px'></div></div></td><td style='color:#6e6e80;font-size:10px'>$pct%</td></tr>"
}) -join "`n"

$subnetStr = $Subnets -join ', '

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Inventory - $subnetStr</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#07070e;color:#e2e2e8;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.6}
header{background:linear-gradient(135deg,#07070e,#0c0c1a);border-bottom:1px solid #181828;padding:22px 40px;display:flex;align-items:center;gap:20px}
.logo{font-size:14px;font-weight:700;font-family:'Courier New',monospace;letter-spacing:4px;white-space:nowrap;text-transform:uppercase;text-shadow:0 0 10px #f5c51860,0 0 25px #f5c51830}.logo span{color:#f5c518;letter-spacing:4px;text-shadow:0 0 8px #f5c518cc,0 0 20px #f5c51880,0 0 40px #f5c51840}.logo em{color:#c8a020;font-style:normal;letter-spacing:4px;text-shadow:0 0 8px #f5c51880,0 0 20px #f5c51840}
.hi h1{font-size:16px;font-weight:600}
.hi p{color:#6e6e80;font-size:11px;margin-top:3px}
.main{padding:26px 40px;max-width:1900px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;margin-bottom:20px}
.sc{background:#0e0e1a;border:1px solid #181828;border-radius:10px;padding:12px 14px}
.sc .n{font-size:24px;font-weight:800;font-family:'Courier New',monospace}
.sc .l{font-size:9px;color:#6e6e80;text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px}
.panel{background:#0e0e1a;border:1px solid #181828;border-radius:10px;padding:14px 18px}
.panel-title{font-size:10px;font-weight:700;color:#6e6e80;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #181828}
.st{font-size:11px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #181828;margin-top:20px}
table{width:100%;border-collapse:collapse;background:#0e0e1a;border-radius:10px;overflow:hidden;border:1px solid #181828;font-size:11px}
.port-tbl{width:auto!important;background:transparent!important;border:none!important;border-radius:0!important;overflow:visible!important}
.port-tbl{border-collapse:collapse!important}.port-tbl tr{border:none!important}.port-tbl td{border:none!important;outline:none!important;padding:2px 5px 2px 0!important;vertical-align:middle!important;background:transparent!important;line-height:1.5}
.tbl-inner{width:100%;border-collapse:collapse;font-size:11px}
th{background:#08081a;color:#6e6e80;font-size:9px;text-transform:uppercase;letter-spacing:1px;padding:8px 10px;text-align:left;font-weight:700;white-space:nowrap}
td{padding:8px 10px;border-top:none;vertical-align:middle;font-size:11px}
tr:hover td{background:#0d0d20}
#hostTbody tr{border-bottom:2px solid #2a2a45}
#hostTbody tr td:first-child{border-left:3px solid transparent}
#hostTbody tr:hover td:first-child{border-left:3px solid #00d4ff}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.5px;color:#fff;white-space:nowrap}
.ip{font-family:'Courier New',monospace;font-size:11px;color:#00d4ff;white-space:nowrap}
.hn{font-family:'Courier New',monospace;font-size:10px;color:#a0a0c0;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dom{font-size:10px;color:#6e6e80}
.ports{max-width:240px;line-height:1;display:block}
.eol-tag{background:#ff2d55;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;margin-left:4px}
.risk-tag{background:#1a1020;border:1px solid #3a1028;color:#ff9eb0;padding:1px 6px;border-radius:3px;font-size:9px;white-space:nowrap;margin:1px}
.svc{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;margin:1px}
.rdp{background:#1a0a2e;color:#a78bfa}.winrm{background:#0a1a2e;color:#00d4ff}
.ssh{background:#0a2e1a;color:#30d158}.smb{background:#2e1a0a;color:#ff6b00}
.db{background:#2e0a0a;color:#ff2d55}
.search-bar{background:#0e0e1a;border:1px solid #181828;border-radius:8px;padding:10px 16px;margin-bottom:14px;display:flex;gap:10px;align-items:center}
.search-bar input{background:#07070e;border:1px solid #282838;border-radius:6px;color:#e2e2e8;padding:6px 12px;font-size:12px;flex:1;outline:none}
.search-bar input::placeholder{color:#444466}
.filter-btn{background:#181828;border:1px solid #282838;border-radius:6px;color:#a0a0c0;padding:5px 12px;font-size:11px;cursor:pointer}
.filter-btn:hover{background:#282838}
footer{margin-top:30px;padding:14px 40px;border-top:1px solid #181828;color:#6e6e80;font-size:11px;text-align:center}
</style>
</head>
<body>
<header>
  <div class="logo"><em>[ </em><span>netinv</span><em> ]</em></div>
  <div class="hi">
    <h1>Network Asset Inventory</h1>
    <p>Subnets: $subnetStr | Targets: $($allTargets.Count) | Live: $($liveArray.Count) | Profiled: $statsTotal | Scan: $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) | Duration: $duration</p>
  </div>
</header>
<div class="main">

  <div class="stats">
    <div class="sc"><div class="n" style="color:#00d4ff">$statsTotal</div><div class="l">Live Hosts</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$statsCritical</div><div class="l">Critical</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$statsHigh</div><div class="l">High Risk</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$statsEOL</div><div class="l">EOL OS</div></div>
    <div class="sc"><div class="n" style="color:#a78bfa">$statsRDP</div><div class="l">RDP Open</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$statsSMBUnsigned</div><div class="l">SMB Unsigned</div></div>
    <div class="sc"><div class="n" style="color:#30d158">$statsSSH</div><div class="l">SSH Open</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$statsDBOpen</div><div class="l">DB Exposed</div></div>
  </div>

  <div class="grid3">
    <div class="panel">
      <div class="panel-title">OS Distribution</div>
      <table class="tbl-inner">
        <thead><tr><th>OS</th><th>Count</th><th>Share</th><th>%</th></tr></thead>
        <tbody>$osDistRows</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Top Open Ports</div>
      <table class="tbl-inner">
        <thead><tr><th>Port/Service</th><th>Hosts</th><th>Prevalence</th><th>%</th></tr></thead>
        <tbody>$portDistRows</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Quick Summary</div>
      <table class="tbl-inner">
        <tbody>
          <tr><td style="color:#6e6e80">Subnets scanned</td><td style="color:#00d4ff;font-family:Courier New,monospace">$($Subnets.Count)</td></tr>
          <tr><td style="color:#6e6e80">Total targets</td><td style="font-family:Courier New,monospace">$($allTargets.Count)</td></tr>
          <tr><td style="color:#6e6e80">Live hosts</td><td style="font-family:Courier New,monospace">$($liveArray.Count) ($([Math]::Round($liveArray.Count/$allTargets.Count*100))%)</td></tr>
          <tr><td style="color:#6e6e80">Windows hosts</td><td style="color:#00d4ff;font-family:Courier New,monospace">$statsWindows</td></tr>
          <tr><td style="color:#6e6e80">Linux/Unix hosts</td><td style="color:#30d158;font-family:Courier New,monospace">$statsLinux</td></tr>
          <tr><td style="color:#6e6e80">EOL OS detected</td><td style="color:#ff2d55;font-family:Courier New,monospace;font-weight:700">$statsEOL</td></tr>
          <tr><td style="color:#6e6e80">RDP exposed</td><td style="color:#a78bfa;font-family:Courier New,monospace">$statsRDP</td></tr>
          <tr><td style="color:#6e6e80">SMB signing disabled</td><td style="color:#ff6b00;font-family:Courier New,monospace;font-weight:700">$statsSMBUnsigned</td></tr>
          <tr><td style="color:#6e6e80">WinRM accessible</td><td style="font-family:Courier New,monospace">$statsWinRM</td></div></td></tr>
          <tr><td style="color:#6e6e80">DB ports exposed</td><td style="color:#ff2d55;font-family:Courier New,monospace">$statsDBOpen</td></tr>
          <tr><td style="color:#6e6e80">Ports scanned</td><td style="font-family:Courier New,monospace">$($Ports.Count)</td></tr>
          <tr><td style="color:#6e6e80">Scan duration</td><td style="font-family:Courier New,monospace">$duration</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="st">Host Inventory</div>
  <div class="search-bar">
    <input type="text" id="searchBox" placeholder="Filter by IP, hostname, OS, port, risk level..." oninput="filterTable()">
    <button class="filter-btn" onclick="filterRisk('CRITICAL')">CRITICAL</button>
    <button class="filter-btn" onclick="filterRisk('HIGH')">HIGH</button>
    <button class="filter-btn" onclick="filterRisk('EOL')">EOL</button>
    <button class="filter-btn" onclick="filterRisk('RDP')">RDP</button>
    <button class="filter-btn" onclick="filterRisk('SMB')">SMB Unsigned</button>
    <button class="filter-btn" onclick="clearFilter()">Clear</button>
    <button class="filter-btn" onclick="exportCSV()" style="margin-left:auto;background:#1a2a1a;border-color:#30d158;color:#30d158">&#8595; Export CSV</button>
  </div>
  <table id="hostTable">
    <thead>
      <tr>
        <th>Risk</th><th>IP</th><th>Hostname</th><th>OS</th><th>Domain</th>
        <th>SMB Sign</th><th>Open Ports</th><th>Risk Indicators</th><th>MAC / Vendor</th>
      </tr>
    </thead>
    <tbody id="hostTbody">
$($hostRows -join "`n")
    </tbody>
  </table>

</div>

<script>
function filterTable() {
    var q = document.getElementById('searchBox').value.toLowerCase();
    var rows = document.getElementById('hostTbody').getElementsByTagName('tr');
    for (var i = 0; i < rows.length; i++) {
        rows[i].style.display = rows[i].textContent.toLowerCase().indexOf(q) > -1 ? '' : 'none';
    }
}
function filterRisk(r) {
    document.getElementById('searchBox').value = r.toLowerCase();
    filterTable();
}
function clearFilter() {
    document.getElementById('searchBox').value = '';
    filterTable();
}
function exportCSV() {
    var rows = document.getElementById('hostTbody').getElementsByTagName('tr');
    var cols = ['Risk','IP','Hostname','OS','Domain','SMB_Sign','Open_Ports','Risk_Indicators','MAC','Vendor'];
    var csv = [cols.join(',')];
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].style.display === 'none') continue;
        var cells = rows[i].getElementsByTagName('td');
        if (cells.length < 2) continue;
        // Risk
        var risk = cells[0].innerText.trim();
        // IP
        var ip = cells[1].innerText.trim();
        // Hostname
        var hn = cells[2].innerText.trim();
        // OS
        var os = cells[3].innerText.replace('EOL','').trim();
        // Domain
        var dom = cells[4].innerText.trim();
        // SMB Sign
        var smb = cells[5].innerText.trim();
        // Open Ports - collect port numbers and service names from inner table
        var portTbls = cells[6].getElementsByTagName('tr');
        var ports = [];
        for (var p = 0; p < portTbls.length; p++) {
            var ptds = portTbls[p].getElementsByTagName('td');
            if (ptds.length >= 2) {
                var pnum = ptds[0].innerText.trim();
                var psvc = ptds[1].innerText.trim();
                ports.push(pnum + (psvc ? '/' + psvc : ''));
            }
        }
        var portsStr = ports.join(' | ');
        // Risk indicators - collect from inner table
        var riskTbls = cells[7].getElementsByTagName('tr');
        var risks = [];
        for (var r = 0; r < riskTbls.length; r++) {
            var rt = riskTbls[r].innerText.trim();
            if (rt) risks.push(rt);
        }
        var risksStr = risks.join(' | ');
        // MAC and Vendor - split on newline
        var macCell = cells[8] ? cells[8].innerText.trim() : '';
        var macParts = macCell.split(/\n/).map(function(s){return s.trim();}).filter(Boolean);
        var mac = macParts[0] || '';
        var vendor = macParts[1] || '';
        var row = [risk,ip,hn,os,dom,smb,portsStr,risksStr,mac,vendor];
        csv.push(row.map(function(v){ return '"' + v.replace(/"/g,'""') + '"'; }).join(','));
    }
    var bom = '\uFEFF';
    var blob = new Blob([bom + csv.join('\n')], {type:'text/csv;charset=utf-8;'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'NetworkInventory_' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
}
</script>

<footer>
  Generated: $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) | Zavet-Sec-NetworkInventory v1.0 | Subnets: $subnetStr | CONFIDENTIAL - SOC/IS USE ONLY &nbsp;&nbsp;|&nbsp;&nbsp; <a href='https://github.com/zavetsec' style='color:#3a3a55;text-decoration:none;font-size:10px' onmouseover="this.style.color='#f5c518'" onmouseout="this.style.color='#3a3a55'">github.com/zavetsec</a>
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force


$sep = "-" * 60
Write-Host ""; Write-Host $sep -ForegroundColor DarkGray
Write-Host "  SCAN COMPLETE" -ForegroundColor White
Write-Host $sep -ForegroundColor DarkGray
Write-Host "  Subnets  : $($Subnets -join ', ')"  -ForegroundColor Gray
Write-Host "  Live     : $($liveArray.Count) / $($allTargets.Count)" -ForegroundColor Gray
Write-Host "  Duration : $duration" -ForegroundColor Gray
Write-Host ""
Write-Host "  CRITICAL  : $statsCritical" -ForegroundColor $(if($statsCritical -gt 0){'Red'}else{'Green'})
Write-Host "  HIGH      : $statsHigh"     -ForegroundColor $(if($statsHigh -gt 0){'Red'}else{'Green'})
Write-Host "  MEDIUM    : $statsMedium"   -ForegroundColor $(if($statsMedium -gt 0){'Yellow'}else{'Green'})
Write-Host "  EOL OS    : $statsEOL"      -ForegroundColor $(if($statsEOL -gt 0){'Red'}else{'Green'})
Write-Host "  SMB Unsgn : $statsSMBUnsigned" -ForegroundColor $(if($statsSMBUnsigned -gt 0){'Yellow'}else{'Green'})
Write-Host ""
Write-Host "  HTML  : $OutputPath" -ForegroundColor Cyan
Write-Host "  CSV   : $CsvPath"    -ForegroundColor Cyan
Write-Host $sep -ForegroundColor DarkGray

$open = Read-Host "Open HTML report in browser? [Y/N]"
if ($open -match '^[Yy]') { Start-Process $OutputPath }
