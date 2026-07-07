"""
parse_events.py — Windows event log detection engine

Reads the JSON exported by collect_logs.ps1 (real logs) or generate_sample.py
(synthetic), then runs a set of detections mapped to MITRE ATT&CK. Works
identically on real or synthetic input because the schema is the same.

Usage:
  python3 parse_events.py exported_logs/

Each detection prints: technique, ATT&CK ID, matched events, and why it fired.
"""
import json, sys, os, re
from collections import defaultdict, Counter

def load(folder, name):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        return []
    # 'utf-8-sig' transparently strips the BOM that PowerShell's
    # Out-File -Encoding utf8 prepends. Plain utf-8 would choke on it.
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    # PowerShell ConvertTo-Json emits a bare object (not a list) when there's
    # exactly one event — normalize that here.
    return data if isinstance(data, list) else [data]

def field(msg, key):
    """Extract 'Key: value' style fields from an event Message string."""
    m = re.search(rf"{re.escape(key)}\s*[:=]\s*([^\s]+)", msg or "")
    return m.group(1) if m else None

def fmt_time(tc):
    """Render a TimeCreated value. PowerShell exports it as '/Date(ms)/';
    synthetic data uses a plain ISO string. Handle both."""
    if not tc:
        return "unknown-time"
    m = re.search(r"/Date\((\d+)\)/", str(tc))
    if m:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)\
            .strftime("%Y-%m-%d %H:%M:%S")
    return str(tc)

def banner(title, atk):
    print("\n" + "=" * 68)
    print(f"  {title}   [{atk}]")
    print("=" * 68)

def run(folder):
    security = load(folder, "security.json")
    sysmon   = load(folder, "sysmon.json")
    powershell = load(folder, "powershell.json")
    system   = load(folder, "system.json")

    findings = 0

    # ---- Detection 1: Failed-logon brute force + success (T1110) ----
    banner("Brute Force: repeated failed logons + success", "T1110")
    fails = [e for e in security if e.get("Id") == 4625]
    by_src = defaultdict(int)
    for e in fails:
        src = field(e["Message"], "Source Network Address") or "unknown"
        by_src[src] += 1
    flagged_src = [s for s, c in by_src.items() if c >= 10]
    for s in flagged_src:
        print(f"  [ALERT] {by_src[s]} failed logons from {s}")
        # did any of them later succeed from the same source?
        succ = [e for e in security if e.get("Id") == 4624 and s in (e.get("Message") or "")]
        if succ:
            acct = field(succ[0]["Message"], "Account Name")
            print(f"          -> FOLLOWED BY SUCCESSFUL LOGON as '{acct}' — likely compromise")
        findings += 1
    if not flagged_src:
        print("  (no brute-force pattern)")

    # ---- Detection 2: Encoded / suspicious PowerShell (T1059.001) ----
    banner("Suspicious PowerShell (encoded / download cradle)", "T1059.001")
    ps_sources = sysmon + powershell
    for e in ps_sources:
        msg = e.get("Message", "")
        if re.search(r"-enc\b|-encodedcommand|-nop\b|-w hidden|DownloadString|IEX ?\(", msg, re.I):
            snippet = msg[:130]
            print(f"  [ALERT] {fmt_time(e.get('TimeCreated'))}  {snippet}")
            findings += 1

    # ---- Detection 3: New account created + added to admins (T1136 / T1098) ----
    banner("Account creation and privilege escalation", "T1136 / T1098")
    created = [e for e in security if e.get("Id") == 4720]
    added   = [e for e in security if e.get("Id") == 4732]
    for e in created:
        acct = field(e["Message"], "New Account Name") or field(e["Message"], "Account Name")
        print(f"  [ALERT] account created: {acct}")
        findings += 1
    for e in added:
        if "Administrators" in e.get("Message", ""):
            acct = field(e["Message"], "Member Account Name") or "?"
            print(f"  [ALERT] '{acct}' ADDED TO Administrators group")
            findings += 1
    if not created and not added:
        print("  (no account-management activity)")

    # ---- Detection 4: LSASS access / credential dumping (T1003.001) ----
    banner("Credential dumping indicators (LSASS access)", "T1003.001")
    for e in sysmon:
        msg = e.get("Message", "")
        if re.search(r"lsass", msg, re.I) and re.search(r"procdump|dump|comsvcs|mimikatz", msg, re.I):
            print(f"  [ALERT] {fmt_time(e.get('TimeCreated'))}  {msg[:130]}")
            findings += 1

    # ---- Detection 5: Service install for persistence (T1543.003) ----
    banner("New service install (possible persistence)", "T1543.003")
    for e in system:
        if e.get("Id") == 7045:
            msg = e.get("Message", "")
            # Service Name and File Name can contain spaces / be quoted, so
            # grab everything up to the next known field label.
            nm = re.search(r"Service Name:\s*(.+?)\s+Service File Name:", msg)
            pm = re.search(r"Service File Name:\s*(.+?)\s+Service Type:", msg)
            name = nm.group(1).strip() if nm else "?"
            path = pm.group(1).strip().strip('"') if pm else "?"
            suspicious = bool(re.search(r"\\Users\\Public|\\Temp|\\AppData", path, re.I))
            tag = "  <-- suspicious path" if suspicious else ""
            print(f"  [{'ALERT' if suspicious else 'INFO '}] service '{name}' -> {path}{tag}")
            if suspicious:
                findings += 1

    # ---- Summary ----
    print("\n" + "=" * 68)
    print(f"  SUMMARY: {findings} detection hit(s) across "
          f"{len(security)+len(sysmon)+len(powershell)+len(system)} events")
    print("=" * 68)

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "exported_logs"
    if not os.path.isdir(folder):
        print(f"Folder not found: {folder}\nRun generate_sample.py first, or pass your exported_logs path.")
        sys.exit(1)
    run(folder)
