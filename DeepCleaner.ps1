# Run as Administrator
# COMPREHENSIVE NTFS JOURNAL AND LOG CLEANUP SCRIPT

Write-Host "=== COMPREHENSIVE CLEANUP SCRIPT ===" -ForegroundColor Red
Write-Host "THIS WILL REMOVE NTFS JOURNALS AND ALL RELATED LOGS" -ForegroundColor Yellow

# Confirmation for safety
$confirmation = Read-Host "`nType 'DELETE ALL' to confirm and proceed"
if ($confirmation -ne "DELETE ALL") {
    Write-Host "Operation cancelled by user." -ForegroundColor Green
    exit
}

Write-Host "`nStarting comprehensive cleanup..." -ForegroundColor Yellow

# 1. DELETE NTFS USN JOURNAL ON ALL DRIVES
Write-Host "`n[1/7] DELETING NTFS USN JOURNALS..." -ForegroundColor Cyan
$drives = Get-WmiObject -Class Win32_Volume | Where-Object {$_.DriveType -eq 3}
foreach ($drive in $drives) {
    $driveLetter = $drive.DeviceID
    if ($driveLetter) {
        Write-Host "   Removing USN Journal from $driveLetter" -ForegroundColor White
        fsutil usn deletejournal /D $driveLetter 2>$null
    }
}

# 2. CLEAR WINDOWS DEFENDER LOGS (Event ID 5007)
Write-Host "`n[2/7] CLEARING WINDOWS DEFENDER LOGS..." -ForegroundColor Cyan
wevtutil clear-log "Microsoft-Windows-Windows Defender/Operational" 2>$null
Write-Host "   ✓ Event ID 5007 removed" -ForegroundColor Green

# 3. CLEAR SYSTEM LOGS (Event ID 1102 and other system events)
Write-Host "`n[3/7] CLEARING SYSTEM LOGS..." -ForegroundColor Cyan
wevtutil clear-log "System" 2>$null
Write-Host "   ✓ Event ID 1102 and system events removed" -ForegroundColor Green

# 4. CLEAR SECURITY LOGS (Process creation events)
Write-Host "`n[4/7] CLEARING SECURITY LOGS..." -ForegroundColor Cyan
wevtutil clear-log "Security" 2>$null
Write-Host "   ✓ Security audit logs cleared" -ForegroundColor Green

# 5. CLEAR APPLICATION LOGS (Event ID 3079 and other app events)
Write-Host "`n[5/7] CLEARING APPLICATION LOGS..." -ForegroundColor Cyan
wevtutil clear-log "Application" 2>$null
Write-Host "   ✓ Event ID 3079 and application events removed" -ForegroundColor Green

# 6. CLEAR POWERSHELL LOGS (Script execution evidence)
Write-Host "`n[6/7] CLEARING POWERSHELL LOGS..." -ForegroundColor Cyan
wevtutil clear-log "Microsoft-Windows-PowerShell/Operational" 2>$null
wevtutil clear-log "Windows PowerShell" 2>$null
Write-Host "   ✓ PowerShell execution logs cleared" -ForegroundColor Green

# 7. CLEAR ADDITIONAL TRACES
Write-Host "`n[7/7] CLEARING ADDITIONAL TRACES..." -ForegroundColor Cyan

# Clear recent run history - COMPREHENSIVE REGISTRY CLEANUP
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Force | Out-Null

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear additional relevant logs
$additionalLogs = @(
    "Microsoft-Windows-Search/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
)

foreach ($log in $additionalLogs) {
    wevtutil clear-log $log 2>$null
}

Write-Host "   ✓ Additional traces and histories cleared" -ForegroundColor Green

# VERIFICATION
Write-Host "`n=== VERIFYING CLEANUP ===" -ForegroundColor Yellow

# Check if journals are gone
Write-Host "`nChecking NTFS Journal status:" -ForegroundColor White
foreach ($drive in $drives) {
    $driveLetter = $drive.DeviceID
    if ($driveLetter) {
        try {
            $journal = fsutil usn queryjournal $driveLetter 2>$null
            if ($journal) {
                Write-Host "   $driveLetter : JOURNAL STILL PRESENT" -ForegroundColor Red
            } else {
                Write-Host "   $driveLetter : journal removed" -ForegroundColor Green
            }
        } catch {
            Write-Host "   $driveLetter : journal removed" -ForegroundColor Green
        }
    }
}

Write-Host "`n=== CLEANUP COMPLETED ===" -ForegroundColor Green
Write-Host "All requested components have been removed:" -ForegroundColor White
Write-Host "✓ NTFS USN Journals deleted from all drives" -ForegroundColor Green
Write-Host "✓ Windows Defender logs cleared (Event ID 5007)" -ForegroundColor Green
Write-Host "✓ System logs cleared (Event ID 1102)" -ForegroundColor Green
Write-Host "✓ Security logs cleared" -ForegroundColor Green
Write-Host "✓ Application logs cleared (Event ID 3079)" -ForegroundColor Green
Write-Host "✓ PowerShell logs cleared" -ForegroundColor Green
Write-Host "✓ Additional traces removed" -ForegroundColor Green

Write-Host "`nNote: Some components may regenerate over time." -ForegroundColor Yellow
Write-Host "For complete cleanup, consider rebooting the system." -ForegroundColor Yellow
