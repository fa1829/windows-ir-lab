# Detection Reference — windows-ir-lab

Each detection in `parse_events.py`, explained: the event data it uses, why it
works, its false-positive profile, and how to talk about it in an interview.

---

## Detection 1 — Brute Force + Success Correlation
**MITRE ATT&CK:** T1110 (Brute Force), with T1078 (Valid Accounts) on success.
**Events:** Security 4625 (failed logon), 4624 (successful logon).

**Logic:** Count 4625 failures grouped by Source Network Address. Flag any
source with ≥10 failures, then check whether that same source produced a 4624
success afterward.

**Why it works:** a handful of failed logons is normal (mistyped passwords);
10+ from one external source in a short span is automated guessing. The success
check is what turns a low-value "someone failed to log in" alert into a
high-value "an external source guessed a password and is now inside."

**False-positive profile:** a user repeatedly failing then succeeding after a
password reset can trip the volume threshold — which is why the source-address
grouping and the "external address" context matter. In production you'd tune the
threshold and whitelist known sources.

**Interview line:** *"The detection isn't 'count failed logons' — it's 'did the
brute force succeed.' That failed-to-success pivot is the first question an
incident responder asks, so I built it into the detection itself."*

---

## Detection 2 — Suspicious PowerShell
**MITRE ATT&CK:** T1059.001 (PowerShell).
**Events:** Sysmon 1 (process create) and/or PowerShell 4104 (script block).

**Logic:** Regex for high-signal PowerShell abuse patterns: `-enc` /
`-encodedcommand` (base64 obfuscation), `-w hidden` (hidden window), `-nop`
(no profile), and download cradles like `IEX (New-Object Net.WebClient).DownloadString`.

**Why it works:** legitimate admins rarely combine hidden-window, no-profile,
and base64-encoded command flags — that combination is a hallmark of malicious
or post-exploitation PowerShell. Download cradles are the classic
fileless-malware delivery pattern.

**False-positive profile:** some legitimate management tooling uses encoded
commands; the detection is intentionally high-signal but would need environment
tuning. Enabling PowerShell script-block logging (4104) gives the actual
decoded content, which sharply reduces false positives.

**Interview line:** *"Encoded-and-hidden PowerShell is one of the highest-signal
Windows detections there is — attackers reach for it constantly, and defenders
can catch it cheaply if script-block logging is on."*

---

## Detection 3 — Account Creation + Privilege Escalation
**MITRE ATT&CK:** T1136 (Create Account), T1098 (Account Manipulation).
**Events:** Security 4720 (user created), 4732 (added to security group).

**Logic:** Flag every 4720 (new account), and every 4732 where the target group
is Administrators.

**Why it works:** attacker persistence frequently involves creating a new
account and granting it admin rights so they retain access even if the original
foothold is closed. A new account being added to Administrators outside a normal
provisioning process is a strong indicator.

**False-positive profile:** legitimate IT provisioning creates accounts and adds
admins — so this detection is most valuable when correlated with *who* did it
and *when* (e.g. admin creation at 3am by a non-IT account is far more
suspicious). Baseline your environment's normal provisioning.

**Interview line:** *"Create-account-then-add-to-admins is a classic persistence
and privilege-escalation combo — I flag the pair, and in production I'd correlate
it with the acting account and time-of-day to cut false positives."*

---

## Detection 4 — Credential Dumping (LSASS)
**MITRE ATT&CK:** T1003.001 (LSASS Memory).
**Events:** Sysmon process-create (ideally Sysmon 10, process access, with full config).

**Logic:** Flag processes referencing `lsass` together with known dumping tools
or methods (procdump, comsvcs.dll, mimikatz).

**Why it works:** LSASS holds credentials in memory; dumping it is one of the
most common credential-theft techniques. Legitimate processes rarely read LSASS
memory, so access by procdump/comsvcs/unusual tools is high-signal.

**False-positive profile:** some security and backup tools legitimately touch
LSASS; a real deployment whitelists those. This is why the detection keys on the
*tooling pattern*, not just any LSASS reference.

**Interview line:** *"LSASS access is where credential theft happens on Windows —
if I can only pick a few Windows detections to get right, this is one of them."*

---

## Detection 5 — Service Install Persistence
**MITRE ATT&CK:** T1543.003 (Windows Service).
**Events:** System 7045 (service installed).

**Logic:** Flag 7045 events where the service binary path is in a suspicious
location — Users\Public, Temp, or AppData — rather than the normal
Program Files / System32.

**Why it works:** installing a service is a durable persistence mechanism
(auto-starts on boot, runs with high privileges). Legitimate services live in
protected system paths; a service binary running from a world-writable or user
path is a strong persistence indicator.

**False-positive profile:** some legitimate software installs services from
unusual paths; the path heuristic is a starting filter, not a verdict. Pairing
with binary reputation/signing checks would harden it.

**Interview line:** *"Service installs are a favourite persistence trick because
they survive reboot and run privileged — I flag the ones whose binary lives
somewhere a legitimate service normally wouldn't."*

---

## Cross-cutting talking points
- **Native logging vs. Sysmon**: detections 1, 3, 5 work from built-in Windows
  logs; 2 and 4 are far richer with Sysmon. Knowing which detections need Sysmon
  shows real Windows-telemetry understanding.
- **Detection-as-code**: these live in version-controlled Python, so they're
  reviewable and testable — the modern alternative to GUI-clicked rules. A
  natural next step is exporting them to **Sigma** format for SIEM portability.
- **Coverage thinking**: mapping each detection to an ATT&CK technique lets you
  answer "what can't you detect yet?" — e.g. this lab doesn't yet cover Kerberos
  attacks (T1558) or lateral movement (T1021), which an AD environment would add.
- **Honesty**: synthetic-by-default, real-host-capable, not a live attack range.
  The demonstrated skill is Windows telemetry analysis and ATT&CK-mapped
  detection authoring.
