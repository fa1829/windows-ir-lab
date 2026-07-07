# windows-ir-lab

A Windows incident-response and detection lab that runs entirely on a
**Windows host with WSL** — no separate virtual machine required. It collects
real Windows event logs (Security, Sysmon, PowerShell, System) using PowerShell,
then analyzes them in WSL with a Python detection engine whose rules are mapped
to the **MITRE ATT&CK** framework. A synthetic log generator is included so the
full pipeline runs and can be validated immediately, before any real logs are
exported.

---

## What this is

An end-to-end, file-based detection pipeline with three stages:

1. **Collection** — a PowerShell script exports Windows event logs to JSON.
2. **Generation (optional)** — a Python script produces synthetic logs containing
   known attack techniques, so the detections can be validated deterministically.
3. **Detection** — a Python engine reads the JSON (real or synthetic) and applies
   a set of ATT&CK-mapped detection rules, printing alerts and a summary.

The pipeline is deliberately lightweight: the detection engine uses only the
Python standard library, and the log format is identical whether the input is
real or synthetic, so the same rules run unchanged against either source.

---

## Why this exists — importance

Windows endpoints and Active Directory are the dominant environment in most
enterprises, and a large share of intrusion activity is visible in Windows event
logs. Effective detection therefore depends on being able to:

- read the high-value Windows Security, Sysmon, and PowerShell event types,
- recognize attacker techniques within them,
- express detections as reviewable, testable code rather than one-off manual
  queries, and
- keep false positives low against the large volume of benign activity a normal
  host generates.

This project demonstrates each of those capabilities on a self-contained,
reproducible dataset, and shows that the detection logic behaves correctly on
both planted attacks (true positives) and ordinary host activity (no false
positives).

---

## Repository contents

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

### How `detections/DETECTIONS.md` works as the reference

`DETECTIONS.md` is the human-readable **detection reference** for this tool — the
documentation counterpart to the executable rules in `parse_events.py`. For each
detection it records:

- the technique name and its **MITRE ATT&CK** ID(s),
- the exact event sources and event IDs the rule consumes,
- the detection logic in plain language,
- the **false-positive profile** (what benign activity could trip it and how it
  is bounded), and
- notes on tuning and limitations.

The relationship is one-to-one: every detection implemented in `parse_events.py`
has a corresponding entry in `DETECTIONS.md`. The Python file is the *engine*;
the Markdown file is the *catalogue* that explains what each rule does and why.
When a rule changes, its `DETECTIONS.md` entry is updated to match, so the
reference stays authoritative rather than drifting from the code.

---

## The detections

| # | Technique | ATT&CK | Signal |
|---|---|---|---|
| 1 | Brute force + success correlation | T1110 | ≥10 failed logons (event 4625) from one source, then a 4624 success from the same source |
| 2 | Suspicious PowerShell | T1059.001 | `-enc`, `-w hidden`, `-nop`, download cradles, `IEX (New-Object Net.WebClient)` |
| 3 | Account creation + privilege escalation | T1136 / T1098 | 4720 new account, 4732 add to Administrators |
| 4 | Credential dumping | T1003.001 | LSASS access via procdump / comsvcs / mimikatz patterns |
| 5 | Service persistence | T1543.003 | 7045 service install from a suspicious path (Users\Public, Temp, AppData) |

Full logic and mapping for each is documented in `detections/DETECTIONS.md`.

---

## How it works — running the pipeline

### Quick validation with synthetic data (no export required)

In WSL:

```bash
python3 generate_sample.py          # writes synthetic logs to exported_logs/
python3 parse_events.py exported_logs/
```

`generate_sample.py` embeds all five techniques above; running the engine against
its output fires every detection, including the brute-force→success correlation.
This provides a deterministic self-test of the detection logic.

### Analyzing real logs from a Windows host

**Step 1 — Collect (PowerShell, Windows side).** Run PowerShell as Administrator
(required to read the Security log), then:

```powershell
powershell -ExecutionPolicy Bypass -File collect_logs.ps1
```

This exports the last seven days of Security, Sysmon (if installed), PowerShell,
and System events into `exported_logs\` as JSON. The script is read-only and does
not modify the system.

**Step 2 — Install Sysmon (optional, recommended).** Sysmon adds detailed
process-creation, network, and file/registry events that native Windows logging
does not capture. It is installed with a configuration file (the SwiftOnSecurity
`sysmonconfig-export.xml` is a common baseline):

```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Detections 1, 3, and 5 work from native Security/System logs without Sysmon;
detections 2 and 4 (process-level) are substantially richer with it.

**Step 3 — Analyze (WSL).** Copy the exported folder into the project directory
and run the engine:

```bash
python3 parse_events.py exported_logs/
```

The same detections now run against the real event logs.

### Generating benign test telemetry

To observe detections firing on real logs without running any malicious tooling,
benign commands that produce the same event patterns can be executed on a system
the operator owns and is authorized to test — for example:

```powershell
powershell.exe -nop -w hidden -Command "Get-Date"
```

This is a harmless command that still produces the `-nop -w hidden` process-creation
pattern that detection 2 matches. Re-collecting and re-analyzing afterward shows
the detection firing on genuine Sysmon telemetry.

---

## Core concepts

**Windows event IDs are the vocabulary.** Windows security monitoring is built on
numbered event IDs — for example 4624 (logon success), 4625 (logon failure), 4672
(special privileges), 4720 (account created), 4732 (added to a group), and 7045
(service installed). This lab keys on the highest-value IDs for the techniques it
covers.

**Sysmon versus native logging.** Native Windows auditing captures logons and
account changes but is thin on process-level detail. Sysmon adds rich
process-creation, network-connection, and image-load events, which is why most
serious Windows endpoint detection depends on it.

**Correlation over single events.** Detection 1 does not merely count failed
logons; it checks whether the same source subsequently *succeeded*. That
failed→success correlation distinguishes an attempted intrusion from a successful
one, which is the first question an incident responder asks. Building detections
around that follow-up question, rather than around a single raw event, is central
to detection engineering.

**Mapping to MITRE ATT&CK.** Each detection cites a technique ID. This allows
reasoning about *coverage* — which attacker techniques are observable — rather
than simply counting alerts, and is standard practice on detection teams.

**Detection-as-code.** The detections live in a version-controlled Python file
rather than a GUI, making them reviewable, testable, and diffable — the
detection-as-code approach used by modern detection tooling.

---

## Real-telemetry handling and troubleshooting

Running against real PowerShell-exported logs surfaces several format issues that
synthetic JSON does not. The engine handles each; they are documented here because
they are common friction points when processing genuine Windows telemetry.

**UTF-8 BOM.** PowerShell's `Out-File -Encoding utf8` prepends a UTF-8 byte-order
mark to the file. A standard `json.load` rejects this with
`Unexpected UTF-8 BOM (decode using utf-8-sig)`. The loader opens files with the
`utf-8-sig` encoding, which strips the BOM transparently.

**PowerShell date serialization.** `ConvertTo-Json` serializes `DateTime` values
as `/Date(1783415941558)/` (Unix milliseconds), not as ISO strings. The engine
detects this format and converts it to a readable `YYYY-MM-DD HH:MM:SS` timestamp;
plain ISO strings from the synthetic generator are passed through unchanged.

**Nested UserId objects.** Real Security events serialize `UserId` as a nested
object (`{"Value": "S-1-5-…"}`) rather than a flat string. The detections that
matter key on the event `Message` text and event ID, so this nesting does not
affect them; it is noted here because it can surprise naive field extraction.

**Single-event arrays.** When a log query returns exactly one event,
`ConvertTo-Json` emits a bare object instead of a one-element array. The loader
normalizes this so downstream code always receives a list.

**Quoted service paths.** Service binary paths in 7045 events are frequently
quoted and contain spaces (e.g. `"C:\Program Files\...\svc.exe"`). Naive
whitespace-based extraction truncates these at the first space. The service-install
detection parses the full quoted path so the suspicious-path check evaluates the
complete binary location.

**Sysmon already registered.** Attempting to install Sysmon when it is already
present returns `The service Sysmon64 is already registered. Uninstall Sysmon
before reinstalling.` This indicates a prior successful install. To apply a new
configuration to an already-installed Sysmon, use the update flag rather than the
install flag:

```powershell
sysmon64.exe -c sysmonconfig-export.xml
```

**Administrator requirement.** The Security log cannot be read without elevated
privileges. If `collect_logs.ps1` returns few or no Security events, confirm the
PowerShell session is elevated.

---

## Validation

The pipeline was validated in two directions:

- **True positives:** run against `generate_sample.py` output (117 events with five
  embedded techniques), the engine fires all five detections, including the
  brute-force→success correlation.
- **False positives:** run against 5,650 real events exported from a live host
  (2,229 Security, 3,000 Sysmon, 415 PowerShell, 6 System), the engine produces
  zero alerts. All service installs present (Google Updater, Intel HAXM, and
  others) are correctly classified `INFO` rather than `ALERT`, because each binary
  runs from a legitimate `Program Files` or `system32` path rather than a
  suspicious location.

A subsequent run after installing Sysmon and executing a benign
`powershell.exe -nop -w hidden` command showed detection 2 firing on the resulting
real process-creation event, confirming the process-level detections operate on
genuine Sysmon telemetry.

Keeping the false-positive rate at zero across a large volume of ordinary host
activity, while still catching every planted technique, is the primary quality
criterion for this kind of detection logic.

---

## Scope and limitations

This project runs on synthetic logs by default and on real host logs when they are
exported. It is not a live attack range with adversary tooling. It demonstrates
reading Windows event telemetry, recognizing attacker techniques within it, and
expressing ATT&CK-mapped detections as code. Coverage is limited to the five
techniques listed; it does not currently include Active Directory-specific
techniques such as Kerberoasting, or lateral-movement detection.

---

## Possible extensions

- Add detections for Kerberos abuse (events 4768/4769 — AS-REP roasting,
  Kerberoasting) against an Active Directory test environment.
- Export the detections to **Sigma** rule format for portability across SIEM
  platforms.
- Add network-connection (Sysmon event 3) and image-load (event 7) detections for
  broader process-behaviour coverage.
- Forward collected logs to a SIEM (e.g. Elastic) for correlation with
  network-telemetry detections.

---

## Requirements

- Windows host (for log collection) with PowerShell.
- WSL with Python 3.10+ (detection engine uses the standard library only).
- Optional: Sysmon (Microsoft Sysinternals) for process-level telemetry.

## Data handling

Exported logs may contain host-specific data (machine names, account SIDs,
installed-software paths). The included `.gitignore` excludes `exported_logs/` and
`real_logs/` so real telemetry is not committed. Only synthetic data and code are
intended for version control.
