# ZavetSec-NetworkInventory

> **PowerShell network scanner and asset inventory for SOC/IR teams — no installation, no dependencies, runs fully offline.**
>
> Offline-first DFIR toolkit for restricted and air-gapped environments.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-gold?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![ZavetSec](https://img.shields.io/badge/ZavetSec-DFIR%20Toolkit-orange?style=flat-square)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-success?style=flat-square)

---

## TL;DR

- Agentless network scanner for Windows — runs anywhere PowerShell works, no install
- Runs offline — ideal for air-gapped and restricted environments
- Built for Windows SOC / IR teams
- 120+ ports, multithreaded, banner grabbing, OS fingerprinting
- Security checks: MS17-010, SSL/TLS, SMB signing, unauthenticated access
- MAC vendor lookup: local OUI database + maclookup.app API fallback
- Dark-themed HTML report with one-click CSV export + SIEM-ready CSV
- Designed to fit directly into SOC triage and incident response workflows

---

> **Run a full network inventory and risk assessment in under 3 minutes — without installing anything.**

---

## Quick Start

```powershell
git clone https://github.com/zavetsec/ZavetSec-NetworkInventory
cd ZavetSec-NetworkInventory
# Run as Administrator (required for raw socket operations)
.\ZavetSec-NetworkInventory.ps1 -Subnets '192.168.1.0/24'
```

> No git? Download the ZIP from GitHub and run `.\ZavetSec-NetworkInventory.ps1` directly.

Main script: `ZavetSec-NetworkInventory.ps1`
Reports are saved in the script directory automatically.

---

## Report Preview

<img width="1866" height="880" alt="image" src="https://github.com/user-attachments/assets/68333505-7265-4919-a7f8-fc679ade2957" />

---

## How It Works

1. **Host discovery** — ICMP ping sweep + TCP fallback on 5 key ports
2. **Port scanning** — 120+ ports in parallel via RunspacePool
3. **Fingerprinting** — banner grabbing, TTL-based OS, WMI if accessible
4. **Security checks** — SMB signing, MS17-010, SSL/TLS, unauth access, ICMP
5. **MAC vendor lookup** — ARP cache → local OUI DB → maclookup.app API
6. **Risk scoring** — CRITICAL / HIGH / MEDIUM / LOW per host
7. **Report generation** — HTML (interactive) + CSV (SIEM-ready)

---

## Why not Nmap?

| | ZavetSec-NetworkInventory | Nmap |
|---|---|---|
| Installation required | ❌ No | ✅ Yes |
| Native Windows / PowerShell | ✅ | ⚠️ Requires install |
| Runs fully offline | ✅ | ⚠️ |
| HTML report built-in | ✅ | ❌ |
| One-click CSV export from report | ✅ | ❌ |
| SIEM-ready CSV | ✅ | ❌ Requires scripting |
| Risk scoring | ✅ Automatic | ❌ |
| Unauthenticated access checks | ✅ | ❌ |
| MS17-010 detection | ✅ | ⚠️ Requires NSE scripts |
| MAC vendor identification | ✅ OUI DB + API | ❌ |
| Fits air-gapped environments | ✅ | ⚠️ |

> Both tools solve different problems. Nmap is the right choice for large-scale enterprise scanning or deep protocol analysis. This tool is built for Windows SOC environments where you need **fast, dependency-free triage** with built-in reporting.
>
> **Use Nmap for depth. Use this tool for speed and accessibility.**

---

## Use Cases

- **Network visibility** — discover all live hosts and open services across subnets
- **Incident response triage** — quickly profile a compromised segment, prioritize response by risk level
- **Internal security audits** — identify misconfigurations, risky exposures, and EOL systems
- **Shadow IT detection** — find unauthorized services (Redis, MongoDB, VNC, Docker, Grafana)
- **Compliance checks** — SMB signing enforcement, EOL OS, weak TLS, unauthenticated access

---

## When NOT to Use This Tool

- **Large-scale enterprise scanning** (10,000+ hosts) — use Nmap / Masscan
- **Deep vulnerability assessment** — use Nessus / OpenVAS
- **UDP-heavy environments** — no UDP scanning support yet
- **Authenticated scanning** — no credential-based checks (WMI requires existing admin access)

---

## Features

### Discovery & Scanning
- ICMP ping sweep + TCP fallback on 5 key ports when ICMP is blocked
- 120+ ports scanned by default, fully customizable
- Multithreaded via RunspacePool (recommended: 50–100 threads)

### Service Fingerprinting
- Banner grabbing on 15 key ports (SSH version, HTTP Server header, FTP banner)
- OS detection: TTL heuristics + WMI if credentials allow
- MAC address via ARP cache + two-tier vendor lookup
- Domain extraction from FQDN hostname (`HOST.corp.local` → `corp.local`)

### MAC Vendor Identification
Two-tier lookup for maximum accuracy:

1. **Local OUI database** — instant offline lookup for 200+ well-known vendors (Cisco, Dell, HP, VMware, Mikrotik, Ubiquiti, etc.)
2. **maclookup.app API fallback** — for unknown OUIs, queries the IEEE-synchronized database for the exact registered company name. Requires internet; gracefully falls back to `Unknown` in air-gapped environments.

### Security Checks
- **SMB signing** — Required / Enabled / Disabled
- **MS17-010 (EternalBlue)** — signature-based detection, read-only
- **SSL/TLS audit** — weak protocol (SSLv3/TLS1.0/1.1), expired cert, self-signed
- **Unauthenticated access** — FTP, Redis, Memcached, MongoDB
- **ICMP Timestamp** — OS time disclosure / policy violation
- **EOL OS detection** — XP, Server 2003/2008/2012, Windows 7/8

> All checks are **non-intrusive. No payloads, no exploitation techniques are used.**
> Designed for safe internal use — suitable for compliance-aware and blue team environments.

### Reporting
- Interactive dark-themed HTML with search bar and quick filters
- **One-click CSV export from the HTML report** — exports currently visible rows (respects active filters)
- Automatic CSV saved next to script on scan completion
- Color-coded service badges by protocol category
- Automatic risk scoring per host: CRITICAL / HIGH / MEDIUM / LOW

---

## Usage

```powershell
# Interactive — prompts for subnet if not provided
.\ZavetSec-NetworkInventory.ps1

# Single subnet
.\ZavetSec-NetworkInventory.ps1 -Subnets '192.168.1.0/24'

# Multiple subnets
.\ZavetSec-NetworkInventory.ps1 -Subnets '10.0.0.0/24','10.0.1.0/24','172.16.0.0/24'

# Fast mode — discovery + port scan only, skips all vuln checks (~2-3x faster)
.\ZavetSec-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -FastScan

# Skip ping — useful when ICMP is blocked by firewall
.\ZavetSec-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -SkipPing

# Custom ports and thread count
.\ZavetSec-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -Ports @(22,80,443,8080,8443) -Threads 100

# Full scan with SMB share enumeration
.\ZavetSec-NetworkInventory.ps1 -Subnets '10.0.0.0/24' -ScanShares -Threads 75
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

### CSV Export

**Two ways to get CSV:**

1. **Automatic** — saved next to the script immediately after scan completion
2. **From HTML report** — click `↓ Export CSV` in the filter bar. Exports only visible rows — filter first to export a subset (e.g. only HIGH/CRITICAL hosts)

### CSV Sample

```csv
Risk,IP,Hostname,OS,Domain,SMB_Sign,Open_Ports,Risk_Indicators,MAC,Vendor
HIGH,10.0.0.10,SRV-DC01,Windows Server 2019,corp.local,Disabled,445/SMB|135/MS-RPC|139/NetBIOS,SMB signing disabled|Risky ports: 445,3C:C7:86:D6:CE:E8,DONGGUAN HUARONG
MEDIUM,10.0.0.22,WORKSTATION-04,,corp.local,N/A,3389/RDP|80/HTTP,Risky ports: 3389,04:7C:16:7B:B8:A8,HP
CRITICAL,10.0.0.55,,,,N/A,23/Telnet,Telnet open,,
```

### HTML Report Sections

- **Stats bar** — Live hosts, Critical / High / EOL counts, RDP / SMB / SSH / DB exposure
- **OS Distribution** — breakdown with visual prevalence bars
- **Top Open Ports** — frequency ranking across all discovered hosts
- **Host Inventory** — filterable table:
  - Risk badge, IP, Hostname, OS, Domain, SMB signing
  - Open ports with color-coded service badges (by protocol category)
  - Risk indicators — vertical list, color-coded by severity
  - MAC address + vendor (OUI DB or API lookup)

---

## Risk Scoring

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

**Risky ports** (trigger risk indicators):

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
| Redis | 6379 | `PING` → `+PONG` without authentication |
| Memcached | 11211 | `stats` response without authentication |
| MongoDB | 27017 | `isMaster` query without authentication |

### ICMP Timestamp
Crafts ICMP Type 13 packet, checks for Type 14 reply. Indicates OS time disclosure — flagged as MEDIUM risk when present.

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
- **No full OS fingerprinting** — TTL heuristics only; accurate OS requires WMI with admin credentials
- **MAC address only on local segment** — ARP does not cross routers
- **MAC API requires internet** — maclookup.app fallback unavailable in air-gapped environments
- **MS17-010 is heuristic** — based on SMB response signature, not a guaranteed result
- **WMI requires privileges** — Hostname / OS / Domain only if scanner has admin rights on target
- **Raw sockets require elevation** — ICMP Timestamp needs Administrator rights

---

## Requirements

- Windows OS with PowerShell 5.1 or later
- **Run as Administrator** — required for raw socket operations
- Network access to target subnets
- No external modules or installations required
- Internet access optional — used only for MAC vendor API lookup

---

## Changelog

### v1.0 — Initial Release
- Host discovery: ICMP + TCP fallback
- 120+ port scan with color-coded service banner grabbing
- SMB signing detection
- MS17-010 EternalBlue signature check
- SSL/TLS audit (protocol, expiry, self-signed)
- Unauthenticated access checks: FTP, Redis, Memcached, MongoDB
- ICMP Timestamp fingerprinting
- MAC address via ARP + two-tier vendor lookup (local OUI DB + maclookup.app API)
- Domain extraction from FQDN
- EOL OS detection
- `-FastScan` mode for rapid discovery
- Interactive subnet prompt
- Dark-themed HTML report with search, filters, one-click CSV export
- Automatic CSV on scan completion
- Automatic risk scoring: CRITICAL / HIGH / MEDIUM / LOW

---

## Roadmap

> Direction: moving from point-in-time scanning toward continuous network visibility.

- [ ] UDP scanning (SNMP, TFTP, NetBIOS-NS)
- [ ] JSON output format
- [ ] IPv6 support
- [ ] Delta report — compare with previous scan, highlight new/disappeared hosts
- [ ] Optional alerting integrations on CRITICAL findings (Telegram / Slack)
- [ ] IP reputation check via VirusTotal / AbuseIPDB

---

## Used In

- Internal SOC network audits and asset discovery
- Incident response triage — rapid profiling of compromised segments
- Compliance validation — SMB signing, EOL OS, weak TLS checks
- Shadow IT hunts — uncovering unauthorized services on corporate networks

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

`ZavetSec-NetworkInventory` is part of the [ZavetSec](https://github.com/zavetsec) open-source DFIR toolkit — self-contained, dependency-free tools built for Windows SOC environments.

| Tool | Description |
|---|---|
| [`ZavetSec-Vault`](https://github.com/zavetsec/ZavetSec-Vault) | Offline AES-256-GCM password manager — zero dependencies |
| [`Invoke-ZavetSecTriage`](https://github.com/zavetsec/Invoke-ZavetSecTriage) | Windows live forensics — MITRE ATT&CK tagged |
| [`ZavetSec-NetworkConnections`](https://github.com/zavetsec/ZavetSec-NetworkConnections) | Active network connections analyzer |
| [`ZavetSec-BrowserHistory`](https://github.com/zavetsec/ZavetSec-BrowserHistory) | Browser history extractor for DFIR |
| [`Invoke-MBHashCheck`](https://github.com/zavetsec/Invoke-MBHashCheck) | MalwareBazaar / ThreatFox hash checker |
| [`ZavetSec-HardeningBaseline`](https://github.com/zavetsec/ZavetSec-HardeningBaseline) | Windows hardening baseline — audit / apply / rollback |

---

*Scan responsibly. Know your network.*
