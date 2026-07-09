# windows-ir-lab

A hands-on Windows incident-response and detection lab that runs entirely on a
**Windows host with WSL** — no separate virtual machine required. It collects
real Windows event logs (Security, Sysmon, PowerShell, System) with PowerShell,
then analyzes them in WSL with a Python detection engine whose rules are mapped to
the **MITRE ATT&CK** framework. A synthetic log generator is included so the full
pipeline runs and can be validated immediately, before any real logs are exported.

The lab is self-contained and reproducible: the synthetic dataset embeds attacks
at known locations so every detection can be verified against a definite ground
truth, and the same detection engine runs unchanged on real host telemetry.

---

## Table of contents

1. [Background: Windows telemetry and why it matters](#1-background)
2. [Core concepts](#2-core-concepts)
3. [Repository contents](#3-repository-contents)
4. [The detections](#4-the-detections)
5. [Procedure: running the lab end to end](#5-procedure)
6. [How the detections work](#6-how-the-detections-work)
7. [Real-telemetry handling and troubleshooting](#7-real-telemetry-handling-and-troubleshooting)
8. [Validation results](#8-validation-results)
9. [Design notes and limitations](#9-design-notes-and-limitations)
10. [Requirements](#10-requirements)
11. [Possible extensions](#11-possible-extensions)

---

## 1. Background

### Why Windows telemetry matters

Windows endpoints and Active Directory are the dominant environment in most
enterprises, and a large share of intrusion activity leaves traces in Windows
event logs — a burst of failed logons, an account suddenly added to the
administrators group, an unusual PowerShell command, a new service installed from
an unexpected location. Effective endpoint detection depends on being able to read
these logs, recognize the attacker techniques within them, and express the
resulting detections as reviewable, testable rules rather than one-off manual
queries.

### What this lab is

An end-to-end, file-based detection pipeline with three stages:

1. **Collection** — a PowerShell script exports Windows event logs to JSON.
2. **Generation (optional)** — a Python script produces synthetic logs containing
   known attack techniques, so the detections can be validated deterministically.
3. **Detection** — a Python engine reads the JSON (real or synthetic) and applies
   a set of ATT&CK-mapped detection rules, printing alerts and a summary.

The pipeline is deliberately lightweight: the detection engine uses only the
Python standard library, and the log format is identical whether the input is real
or synthetic, so the same rules run unchanged against either source.

---

## 2. Core concepts

These concepts underpin every detection in the lab. Reading this section first
makes the detection logic in step 6 straightforward to follow.

### Windows event IDs are the vocabulary

Windows security monitoring is built on numbered event IDs. A small set carries
most of the value for endpoint detection:

- **4624** — successful logon
- **4625** — failed logon
- **4672** — special privileges assigned to a logon
- **4720** — a user account was created
- **4732** — a member was added to a security-enabled group
- **7045** — a new service was installed

Knowing this handful of high-value IDs is foundational to Windows detection, and
this lab keys its rules on them.

### Sysmon versus native logging

Native Windows auditing records logons and account changes well, but is thin on
process-level detail. **Sysmon** (System Monitor, a free Microsoft Sysinternals
tool) supplements it with rich process-creation, network-connection, and
image-load events. This distinction matters in practice: several of the most
valuable detections — suspicious process command lines, credential-access
patterns — depend on the process-level visibility Sysmon provides. Understanding
why Sysmon is deployed is itself a marker of Windows-detection maturity.

### Correlation over single events

The strongest detections do not stop at a single event. Counting failed logons is
useful; checking whether the same source *subsequently succeeded* is what
distinguishes an attempted intrusion from a successful one. Designing detections
around that follow-up question — the one an incident responder asks next — is
central to effective detection engineering, and appears explicitly in the brute
force detection below.

### Mapping to MITRE ATT&CK

**MITRE ATT&CK** is a public, standardized catalogue of adversary techniques, each
with a stable identifier (for example `T1110` for brute force). Mapping detections
to ATT&CK technique IDs allows reasoning about *coverage* — which attacker
techniques are actually observable — rather than merely counting alerts. Every
detection in this lab cites the technique it addresses.

### Detection-as-code

The detections live in a version-controlled Python file rather than a graphical
console. This makes them reviewable, testable, and diffable — the "detection-as-code"
approach used by modern detection tooling, in contrast to rules clicked together in
a UI that cannot be version-controlled or peer-reviewed.

---

## 3. Repository contents

```
windows-ir-lab/
├── collect_logs.ps1        # PowerShell: export real event logs from a Windows host
├── generate_sample.py      # Python: generate synthetic logs with embedded attacks
├── parse_events.py         # Python: detection engine (MITRE ATT&CK-mapped)
├── detections/
│   └── DETECTIONS.md       # Detection reference: logic, ATT&CK mapping, FP profile
├── README.md
└── .gitignore
```

`detections/DETECTIONS.md` is the detection reference for this lab — the
human-readable counterpart to the executable rules in `parse_events.py`. For each
detection it records the technique and its ATT&CK ID, the event sources and IDs the
rule consumes, the detection logic in plain language, the false-positive profile,
and tuning notes. The relationship is one-to-one: every rule in `parse_events.py`
has a corresponding entry in `DETECTIONS.md`. The Python file is the engine; the
Markdown file is the catalogue that explains what each rule does and why.

---

## 4. The detections

| # | Technique | ATT&CK | Signal |
|---|---|---|---|
| 1 | Brute force + success correlation | T1110, T1078 | Ten or more failed logons (4625) from one source, then a 4624 success from the same source |
| 2 | Suspicious PowerShell | T1059.001 | `-enc`, `-w hidden`, `-nop`, download cradles, `IEX (New-Object Net.WebClient)` |
| 3 | Account creation + privilege escalation | T1136, T1098 | 4720 new account, 4732 add to Administrators |
| 4 | Credential dumping | T1003.001 | LSASS access via procdump / comsvcs / mimikatz patterns |
| 5 | Service persistence | T1543.003 | 7045 service install from a suspicious path (Users\Public, Temp, AppData) |

Full logic and mapping for each is documented in `detections/DETECTIONS.md`.

---

## 5. Procedure

The detection engine runs in WSL; log collection runs in PowerShell on the Windows
side. The steps proceed from a synthetic self-test, to collecting real logs, to
analyzing them.

### Step 1 — Validate the pipeline with synthetic data (no export required)

In WSL:

```bash
python3 generate_sample.py          # writes synthetic logs to exported_logs/
python3 parse_events.py exported_logs/
```

`generate_sample.py` embeds all five techniques; running the engine against its
output fires every detection, including the brute-force→success correlation. This
provides a deterministic self-test with no dependencies beyond the Python standard
library.

### Step 2 — Collect real logs (PowerShell, Windows side)

Run PowerShell **as Administrator** (required to read the Security log), then:

```powershell
powershell -ExecutionPolicy Bypass -File collect_logs.ps1
```

This exports the last seven days of Security, Sysmon (if installed), PowerShell,
and System events into an `exported_logs\` folder as JSON. The script is read-only
and does not modify the system.

### Step 3 — Install Sysmon (optional, recommended)

Sysmon adds the process-level telemetry that native logging lacks. It is installed
with a configuration file; the SwiftOnSecurity `sysmonconfig-export.xml` is a
common baseline:

```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Detections 1, 3, and 5 work from native Security/System logs without Sysmon;
detections 2 and 4 (process-level) are substantially richer with it. If Sysmon is
already installed, apply a new configuration with the update flag instead:

```powershell
sysmon64.exe -c sysmonconfig-export.xml
```

### Step 4 — Analyze the real logs (WSL)

Copy the exported folder into the project directory and run the engine:

```bash
python3 parse_events.py exported_logs/
```

The same detections now run against the real event logs.

### Step 5 — Generate benign test telemetry (optional)

To observe detections firing on real logs without running any malicious tooling,
benign commands that produce the same event patterns can be executed on a system
that the operator owns and is authorized to test — for example:

```powershell
powershell.exe -nop -w hidden -Command "Get-Date"
```

This is a harmless command that still produces the `-nop -w hidden`
process-creation pattern that detection 2 matches. Re-collecting and re-analyzing
afterward shows the detection firing on genuine Sysmon telemetry.

---

## 6. How the detections work

This section summarizes the logic for each detection. Full detail — including the
false-positive profile for each — is in `detections/DETECTIONS.md`.

### Detection 1 — Brute force with success correlation (T1110, T1078)

Failed logons (event 4625) are counted per source. A source exceeding a threshold
well above normal user error is flagged, and the detection then checks whether that
same source *also* produced a successful logon (4624). A handful of failures is
ordinary mistyping; many failures from one source followed by a success is the
signature of a successful password-guessing attack. The failed→success check is
what escalates the finding from *attempted* to *successful* compromise.

### Detection 2 — Suspicious PowerShell (T1059.001)

Process-creation and script-block events are matched against high-signal PowerShell
abuse patterns: `-enc` / `-encodedcommand` (base64 obfuscation), `-w hidden`
(hidden window), `-nop` (no profile), and download cradles such as
`IEX (New-Object Net.WebClient).DownloadString`. Legitimate administration rarely
combines these flags; the combination is a hallmark of malicious or
post-exploitation PowerShell.

### Detection 3 — Account creation and privilege escalation (T1136, T1098)

New-account events (4720) are flagged, as are additions to the Administrators group
(4732). Attacker persistence frequently involves creating an account and granting
it administrative rights so that access survives even if the original foothold is
closed.

### Detection 4 — Credential dumping (T1003.001)

Processes that reference LSASS together with known dumping tools or methods
(procdump, comsvcs, mimikatz) are flagged. LSASS holds credentials in memory, and
dumping it is one of the most common credential-theft techniques; legitimate
processes rarely access LSASS memory in this way.

### Detection 5 — Service install persistence (T1543.003)

Service-install events (7045) whose binary path is in a suspicious location —
`Users\Public`, `Temp`, or `AppData` rather than `Program Files` or `system32` —
are flagged. Installing a service is a durable persistence mechanism, and a service
binary running from a world-writable or user path is a strong indicator.

---

## 7. Real-telemetry handling and troubleshooting

Running against real PowerShell-exported logs surfaces several format issues that
synthetic JSON does not. The engine handles each; they are documented here because
they are common friction points when processing genuine Windows telemetry.

**UTF-8 BOM.** PowerShell's `Out-File -Encoding utf8` prepends a UTF-8 byte-order
mark to the file. A standard `json.load` rejects this with
`Unexpected UTF-8 BOM (decode using utf-8-sig)`. The loader opens files with the
`utf-8-sig` encoding, which strips the BOM transparently.

**PowerShell date serialization.** `ConvertTo-Json` serializes `DateTime` values as
`/Date(1783415941558)/` (Unix milliseconds), not as ISO strings. The engine detects
this format and converts it to a readable `YYYY-MM-DD HH:MM:SS` timestamp; plain ISO
strings from the synthetic generator are passed through unchanged.

**Nested UserId objects.** Real Security events serialize `UserId` as a nested
object (`{"Value": "S-1-5-…"}`) rather than a flat string. The detections that
matter key on the event `Message` text and event ID, so this nesting does not affect
them; it is noted here because it can surprise naive field extraction.

**Single-event arrays.** When a log query returns exactly one event, `ConvertTo-Json`
emits a bare object instead of a one-element array. The loader normalizes this so
downstream code always receives a list.

**Quoted service paths.** Service binary paths in 7045 events are frequently quoted
and contain spaces (for example `"C:\Program Files\...\svc.exe"`). Naive
whitespace-based extraction truncates these at the first space. The service-install
detection parses the full quoted path so the suspicious-path check evaluates the
complete binary location.

**Sysmon already registered.** Attempting to install Sysmon when it is already
present returns `The service Sysmon64 is already registered. Uninstall Sysmon before
reinstalling.` This indicates a prior successful install. To apply a new
configuration to an already-installed Sysmon, use the update flag
(`sysmon64.exe -c sysmonconfig-export.xml`) rather than the install flag.

**Administrator requirement.** The Security log cannot be read without elevated
privileges. If `collect_logs.ps1` returns few or no Security events, confirm the
PowerShell session is elevated.

---

## 8. Validation results

The pipeline was validated in two directions:

- **True positives:** run against `generate_sample.py` output, the engine fires all
  five detections, including the brute-force→success correlation, against the
  embedded synthetic attacks.
- **False positives:** run against 5,650 real events exported from a live host
  (2,229 Security, 3,000 Sysmon, 415 PowerShell, 6 System), the engine produced
  zero alerts. All service installs present (for example a browser updater and a
  virtualization driver) were correctly classified `INFO` rather than `ALERT`,
  because each binary ran from a legitimate `Program Files` or `system32` path
  rather than a suspicious location.

A subsequent run after installing Sysmon and executing a benign
`powershell.exe -nop -w hidden` command showed detection 2 firing on the resulting
real process-creation event, confirming the process-level detections operate on
genuine Sysmon telemetry.

Keeping the false-positive rate at zero across a large volume of ordinary host
activity, while still catching every planted technique, is the primary quality
criterion for this kind of detection logic.

---

## 9. Design notes and limitations

This lab runs on synthetic logs by default and on real host logs when they are
exported. It is not a live attack range with adversary tooling. It demonstrates
reading Windows event telemetry, recognizing attacker techniques within it, and
expressing ATT&CK-mapped detections as code. Coverage is limited to the five
techniques listed; it does not currently include Active Directory-specific
techniques such as Kerberoasting, or lateral-movement detection.

The lab complements log-based network detection: where a network-focused SIEM
analyzes authentication, web, and firewall telemetry, this lab adds the
Windows/endpoint half with the same ATT&CK-mapped, correlation-first approach —
together covering detection across both major telemetry domains.

---

## 10. Requirements

- Windows host (for log collection) with PowerShell.
- WSL with Python 3.10+ (the detection engine uses the standard library only).
- Optional: Sysmon (Microsoft Sysinternals) for process-level telemetry.

### Data handling

Exported logs may contain host-specific data (machine names, account SIDs,
installed-software paths, and command lines that can include sensitive arguments).
The included `.gitignore` excludes `exported_logs/` and `real_logs/` so real
telemetry is not committed. Only synthetic data and code are intended for version
control.

---

## 11. Possible extensions

- Add detections for Kerberos abuse (events 4768/4769 — AS-REP roasting,
  Kerberoasting) against an Active Directory test environment.
- Export the detections to **Sigma** rule format for portability across SIEM
  platforms.
- Add network-connection (Sysmon event 3) and image-load (event 7) detections for
  broader process-behaviour coverage.
- Add a detection for secrets exposed in process command lines (T1552.001), tuned
  to exclude benign look-alikes such as .NET public key tokens.
- Forward collected logs to a SIEM (for example the Elastic Stack) for correlation
  with network-telemetry detections.

---

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
