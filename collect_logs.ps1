# collect_logs.ps1
# Windows IR Lab - log collection
# Run this in PowerShell ON THE WINDOWS SIDE (not WSL), then analyze the
# exported JSON in WSL with parse_events.py.
#
# This exports REAL event logs from your own machine — Security, Sysmon
# (if installed), and PowerShell operational logs — into JSON the Python
# analyzer can read. It is read-only: it does not change your system.
#
# Usage (PowerShell, from the folder you want the output in):
#   powershell -ExecutionPolicy Bypass -File collect_logs.ps1
#
# If you want richer telemetry, install Sysmon first (optional, see README).

$outDir = ".\exported_logs"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host "Windows IR Lab - collecting event logs..." -ForegroundColor Cyan

# --- How many events / how far back ---
$maxEvents = 3000
$startTime = (Get-Date).AddDays(-7)

function Export-Log($logName, $outFile, $ids) {
    try {
        $filter = @{ LogName = $logName; StartTime = $startTime }
        if ($ids) { $filter.Id = $ids }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $maxEvents -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName,
                          MachineName, UserId,
                          @{N='Message';E={$_.Message -replace "`r`n"," "}}
        $events | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 "$outDir\$outFile"
        Write-Host ("  {0,-28} {1} events -> {2}" -f $logName, $events.Count, $outFile) -ForegroundColor Green
    } catch {
        Write-Host ("  {0,-28} skipped ({1})" -f $logName, $_.Exception.Message) -ForegroundColor Yellow
    }
}

# 1. Security log — logon events, account management, privilege use
#    4624 success logon, 4625 failed logon, 4634 logoff, 4672 special privileges,
#    4720 user created, 4726 user deleted, 4732 added to security group
Export-Log "Security" "security.json" @(4624,4625,4634,4672,4720,4726,4732,4740)

# 2. Sysmon — only present if Sysmon is installed (optional but recommended)
#    1 process create, 3 network connect, 11 file create, 13 registry set
Export-Log "Microsoft-Windows-Sysmon/Operational" "sysmon.json" @(1,3,11,13)

# 3. PowerShell operational — script block logging (4104), engine start (4103)
Export-Log "Microsoft-Windows-PowerShell/Operational" "powershell.json" @(4103,4104)

# 4. System log — service installs (7045) often used for persistence
Export-Log "System" "system.json" @(7045)

Write-Host "`nDone. Copy the exported_logs folder into your WSL project:" -ForegroundColor Cyan
Write-Host "  cp -r /mnt/c/path/to/exported_logs ~/projects/windows-ir-lab/" -ForegroundColor White
Write-Host "Then run:  python3 parse_events.py exported_logs/" -ForegroundColor White
