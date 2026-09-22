TL;DR

An Active Directory Domain Controller exposes an unauthenticated Redis 2.8.2402 instance. The Redis service account is leveraged three ways:

Lua dofile() file read — leaks the user flag via a parser error.
Lua dofile() on a UNC path — coerces the DC's SMB client to authenticate outbound to an attacker-controlled listener, capturing a NetNTLMv2 hash.
After cracking, valid domain credentials give write access to a share holding a scheduled PowerShell script, which is overwritten with a reverse shell.

Final privilege escalation abuses SeImpersonatePrivilege via GodPotato to reach NT AUTHORITY\SYSTEM.

Kill chain: unauth Redis → Lua dofile UNC coercion → NetNTLMv2 → crack → SMB share script overwrite → foothold shell → GodPotato → SYSTEM
