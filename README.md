# ZavetSec-NetworkInventory

> **PowerShell network scanner and asset inventory for SOC/IR teams — no installation, no dependencies, runs fully offline.**
>
> Designed as a lightweight alternative to traditional scanners for Windows-centric environments.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-gold?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![ZavetSec](https://img.shields.io/badge/ZavetSec-DFIR%20Toolkit-orange?style=flat-square)

---

## Quick Start

```powershell
git clone https://github.com/zavetsec/ZavetSec-NetworkInventory
cd ZavetSec-NetworkInventory
.\Get-NetworkInventory.ps1 -Subnets '192.168.1.0/24'
```

Main script: `Get-NetworkInventory.ps1`
HTML report and CSV are saved in the script directory automatically.

---

## Report Preview

![HTML Report](docs/report.png)

> *Report preview will be added in the next update. Place your screenshot at `docs/report.png`.*

---

## Why not Nmap?

| | ZavetSec-NetworkInventory | Nmap |
|---|---|---|
| Installation required | ❌ No | ✅ Yes |
| Native Windows / PowerShell | ✅ | ⚠️ Requires install |
| Runs fully offline | ✅ | ⚠️ |
| HTML report built-in | ✅ | ❌ |
| CSV / SIEM export | ✅ | ❌ Requires additional scripting |
| Risk scoring | ✅ Automatic | ❌ |
| Unauthenticated access checks | ✅ | ❌ |
| MS17-010 detection | ✅ | ⚠️ Requires NSE scripts |
| Fits air-gapped environments | ✅ | ⚠️ |

> Built for Windows SOC environments where installing third-party tools is restricted or impractical.

---

## Use Cases

- **Network visibility** — discover all live hosts and open services across subnets
- **Incident response triage** — quickly profile a potentially compromised network segment
- **Internal security audits** — identify misconfigurations, risky exposures, and EOL systems
- **Shadow IT detection** — find unauthorized services (Redis, MongoDB, VNC, Docker, Grafana)
- **Compliance checks** — SMB signing enforcement, EOL OS, weak TLS, unauthenticated access

---

## Features

### Discovery & Scanning
- ICMP ping sweep + TCP fallback on 5 key ports when ICMP is blocked
- 120+ ports scanned by default, fully customizable
- Multithreaded via RunspacePool (recommended: 50–100 threads)

### Service Fingerprinting
- Banner grabbing on 15 key ports (SSH version, HTTP Server header, FTP banner)
- OS detection: TTL heuristics + WMI if credentials allow
- MAC address via ARP cache + vendor identification (local OUI database)
- Domain extraction from FQDN hostname (`HOST.corp.local` → `corp.local`)

### Security Checks
- **SMB signing** — Required / Enabled / Disabled
- **MS17-010 (EternalBlue)** — signature-based detection, read-only
- **SSL/TLS audit** — weak protocol (SSLv3/TLS1.0/1.1), expired cert, self-signed
- **Unauthenticated access** — FTP, Redis, Memcached, MongoDB
- **ICMP Timestamp** — OS time disclosure / policy violation
- **EOL OS detection** — XP, Server 2003/2008/2012, Windows 7/8

> All checks are **non-intrusive. No payloads, no exploitation techniques are used.**

### Reporting
- Interactive dark-themed HTML with search bar and quick filters
- CSV export ready for SIEM ingestion
- Automatic risk scoring per host: CRITICAL / HIGH / MEDIUM / LOW

---

## Usage

```powershell
# Interactive — prompts for subnet if not provided
.\Get-NetworkInventory.ps1

# Single subnet
.\Get-NetworkInventory.ps1 -Subnets '192.168.1.0/24'

# Multiple subnets
.\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24','10.0.1.0/24','172.16.0.0/24'

# Fast mode — discovery + port scan only, skips all vuln checks (~2-3x faster)
.\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -FastScan

# Skip ping — useful when ICMP is blocked by firewall
.\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -SkipPing

# Custom ports and thread count
.\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -Ports @(22,80,443,8080,8443) -Threads 100

# Full scan with SMB share enumeration
.\Get-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -ScanShares -Threads 75
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Subnets` | `string[]` | *(interactive prompt)* | One or more subnets in CIDR notation |
| `-Ports` | `int[]` | 120+ ports | Custom port list to scan |
| `-Threads` | `int` | `50` | Parallel scan threads (recommended: 50–100) |
| `-TimeoutMs` | `int` | `500` | TCP connect timeout in milliseconds |
| `-OutputPath` | `string` | *script directory* | HTML report output path |
| `-CsvPath` | `string` | *script directory* | CSV output path |
| `-SkipPing` | `switch` | `false` | Skip ICMP, probe TCP on all hosts directly |
| `-ScanShares` | `switch` | `false` | Enumerate SMB shares on discovered hosts |
| `-FastScan` | `switch` | `false` | Skip SSL/TLS, MS17-010, unauthenticated access, ICMP checks |

---

## Output

Reports are saved next to the script:
```
NetworkInventory_20260330_134500.html
NetworkInventory_20260330_134500.csv
```

### CSV Sample

```csv
IP,Hostname,OS,Domain,RiskLevel,PortCount,SmbSigning,IsEOL,HasRDP,HasSMB,OpenPorts,Risks
10.0.0.10,SRV-DC01,Windows Server 2019,corp.local,HIGH,5,Disabled,False,False,True,"445,135,139","SMB signing disabled | Risky ports: 445,139"
10.0.0.22,WORKSTATION-04,,corp.local,MEDIUM,2,N/A,False,True,False,"3389,80","Risky ports: 3389"
10.0.0.55,,,,CRITICAL,1,N/A,False,False,False,"23","Telnet open"
```

### HTML Report Sections

- **Stats bar** — Live hosts, Critical / High / EOL counts, RDP / SMB / SSH / DB exposure
- **OS Distribution** — breakdown with visual prevalence bars
- **Top Open Ports** — frequency ranking across all discovered hosts
- **Host Inventory** — filterable table with per-host detail:
  - Risk badge, IP, Hostname, OS, Domain, SMB signing
  - Open ports with service labels (risky ports highlighted in orange)
  - Risk indicators — vertical list, color-coded by severity
  - MAC address + vendor

---

## Risk Scoring

Risk level is derived from cumulative findings per host. Critical findings override lower levels.

```
CRITICAL  ← EOL OS detected
          ← Telnet open (port 23)
          ← MS17-010 VULNERABLE

HIGH      ← SMB signing Disabled
          ← Unauthenticated access confirmed (FTP / Redis / MongoDB / Memcached)
          ← 4+ risky ports open simultaneously

MEDIUM    ← 1–3 risky ports open
          ← Weak TLS protocol (SSLv3 / TLS 1.0 / TLS 1.1)
          ← Expired SSL certificate
          ← Self-signed SSL certificate
          ← ICMP Timestamp reply
          ← FTP service detected

LOW       ← No significant findings
```

**Risky ports** (trigger risk indicators when found open):

`23` `69` `111` `135` `137` `139` `161` `445` `512` `513` `514` `1080` `1099` `1433` `1434` `1521` `2049` `2375` `2376` `3128` `3306` `3389` `4444` `4445` `4848` `4899` `5432` `5900` `5901` `6379` `6666` `7001` `7002` `8009` `8161` `9200` `11211` `27017` `27018`

---

## Security Checks Detail

### MS17-010 (EternalBlue)
Sends SMB Negotiate → Session Setup → NT_TRANSACT and checks for `STATUS_INSUFF_SERVER_RESOURCES (0xC0000205)` — the known response signature of unpatched systems. No payloads, no exploitation techniques are used. Result is heuristic — treat as an indicator, not a confirmation.

### SSL/TLS Audit
Checks ports 443, 8443, 636, 993, 995, 465, 990, 9443. Reports: weak protocol version, certificate expiry, self-signed issuer.

### Unauthenticated Access

| Service | Port | Method |
|---|---|---|
| FTP | 21 | Anonymous login (`anonymous` / `scan@scan.local`) |
| Redis | 6379 | `PING` → expects `+PONG` without authentication |
| Memcached | 11211 | `stats` command response without authentication |
| MongoDB | 27017 | `isMaster` wire protocol query without authentication |

### ICMP Timestamp
Crafts ICMP Type 13 packet, checks for Type 14 reply. Indicates OS time disclosure — commonly blocked by security policy, flagged as MEDIUM risk when present.

---

## Performance

| Subnet | Hosts | Threads | Full Scan | `-FastScan` |
|---|---|---|---|---|
| /24 | 254 | 50 | ~2–3 min | ~45–90 sec |
| /23 | 510 | 100 | ~3–5 min | ~90–120 sec |
| /22 | 1022 | 150 | ~6–10 min | ~3–4 min |

> Times vary based on network latency, firewall rules, and host response rate.
> Higher thread counts may impact network stability on low-bandwidth environments.

---

## Limitations

- **No UDP scanning** — SNMP (161) and other UDP services require separate tooling
- **No full OS fingerprinting** — TTL heuristics only; accurate OS data requires WMI with admin credentials
- **MAC address only on local segment** — ARP does not cross routers; remote subnets show no MAC
- **MS17-010 is heuristic** — based on known SMB response signature, not a guaranteed result
- **WMI data requires privileges** — Hostname / OS / Domain via WMI only if scanner has admin rights on target
- **Raw sockets require elevation** — ICMP Timestamp check needs Administrator on the scanning host

---

## Requirements

- Windows OS with PowerShell 5.1 or later
- **Run as Administrator** — required for raw socket operations
- Network access to target subnets
- No external modules, no installations, no internet access required

---

## Changelog

### v1.0 — Initial Release
- Host discovery: ICMP + TCP fallback
- 120+ port scan with service banner grabbing
- SMB signing detection
- MS17-010 EternalBlue signature check
- SSL/TLS audit (protocol, expiry, self-signed)
- Unauthenticated access checks: FTP, Redis, Memcached, MongoDB
- ICMP Timestamp fingerprinting
- MAC address + vendor lookup via local OUI database
- Domain extraction from FQDN
- EOL OS detection
- `-FastScan` mode for rapid discovery
- Interactive subnet prompt
- Dark-themed HTML report with search and filters
- CSV export for SIEM ingestion
- Automatic risk scoring: CRITICAL / HIGH / MEDIUM / LOW

---

## Roadmap

- [ ] UDP scanning (SNMP, TFTP, NetBIOS-NS)
- [ ] JSON output format
- [ ] IPv6 support
- [ ] Delta report — compare with previous scan, highlight changes
- [ ] Optional alerting integrations on CRITICAL findings
- [ ] IP reputation check via VirusTotal / AbuseIPDB

---

## Legal Notice

> This tool is intended **only** for use on networks you own or have **explicit written authorization** to test.
> Unauthorized network scanning is illegal in most jurisdictions.
> The authors accept no responsibility for any misuse.

---

## ⭐ Support the Project

If you find this tool useful in your work, consider giving it a star — it helps others discover it.

---

## Part of ZavetSec Toolkit

`ZavetSec-NetworkInventory` is part of the [ZavetSec](https://github.com/zavetsec) open-source DFIR and InfoSec toolkit — self-contained, dependency-free tools built for Windows SOC environments.

| Tool | Description |
|---|---|
| `Invoke-ZavetSecTriage` | Windows live forensics — 17 modules, MITRE ATT&CK tagged |
| `Invoke-MBHashCheck` | MalwareBazaar / ThreatFox hash checker |
| `ZavetSec OSINT Toolkit` | Passive recon HTML app — Shodan, VirusTotal, AbuseIPDB, Hunter.io |
| `ZavetSec Vault` | Offline AES-256-GCM password manager with KeePass import/export |
| `ZavetSec DLP Agent` | C# endpoint DLP — clipboard, keylog, USB, file, network monitoring |

---

*Scan responsibly. Know your network.*
