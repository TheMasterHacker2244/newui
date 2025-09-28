# Define your keywords (case-insensitive)
$keywords = @(
    'matcha','evolve','software','loader','exploit','hack','mooze','isabelle',
    'matrix','severe','assembly','tsar','melatonin','external','dx9','serotonin',
    'aimmy','valex','vector','photon','nezur','thunder client','yebra','haze/myst',
    'haze','myst','horizon','havoc','colorbot','xeno','solara','wave','awp',
    'olduimatrix','autoexe','bin','workspace','monkeyaim','thunderaim',
    'thunderclient','celex','zarora','juju','nezure','fluxus','clumsy','build',
    'triggerbot','matcha.exe','triggerbot.exe','aimmy.exe','mystw','mystw\.exe',
    'dx9ware.exe','fusionhacks.zip','release.zip','build.zip','build.rar',
    'bootstrapper','bootstrappernew','santoware','mapper','bootstrappernew\.exe',
    'bootstrapper.exe','xeno.exe','xenoui.exe','solara.exe','mapper.exe',
    'loader.exe','evolve.exe','app.exe','bitcoin','boostrapper.exe',
    'boostrappernew\.exe','authenticator.exe','inject','release','cloudy',
    'tupical','celery','software.exe','update.exe','upgrade.exe','launcher',
    'fast','launch','nigger','nigga','silent','ming','key','A:\\','B:\\','D:\\',
    'E:\\','F:\\','G:\\','H:\\','I:\\','J:\\','K:\\','L:\\','M:\\','N:\\','O:\\',
    'P:\\','Q:\\','R:\\','S:\\','T:\\','U:\\','V:\\','W:\\','X:\\','Y:\\','Z:\\'
)

# Whitelist - processes/files that should NOT be deleted even if they match keywords
$whitelist = @('NVIDIA APP.EXE','obs64.exe','obs32.exe','obs.exe','obs','obs-studio','obsproject')

# Convert to lowercase for case-insensitive matching
$keywords = $keywords | ForEach-Object { $_.ToLower() }
$whitelist = $whitelist | ForEach-Object { $_.ToLower() }

# Function to check if text contains any of the keywords (excluding whitelist)
function Contains-Keyword {
    param ([string]$text)
    
    $textLower = $text.ToLower()
    
    # First check if it matches any whitelist item (don't delete if it does)
    foreach ($whiteItem in $whitelist) {
        if ($textLower -match [regex]::Escape($whiteItem)) {
            return $false
        }
    }
    
    # Then check for keywords
    foreach ($keyword in $keywords) {
        if ($textLower -match [regex]::Escape($keyword)) {
            return $true
        }
    }
    return $false
}

# ----------------------------------------
# Section 1: Delete Registry Keys with specified keywords (excluding whitelist)
# ----------------------------------------

# Get all registry paths to scan
$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            $subkeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            foreach ($subkey in $subkeys) {
                $name = $subkey.PSChildName
                $shouldDelete = $false
                
                # Check subkey name first
                if (Contains-Keyword $name) {
                    $shouldDelete = $true
                }
                
                # Check values if not already marked for deletion
                if (-not $shouldDelete) {
                    try {
                        $properties = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue
                        if ($properties) {
                            $values = $properties.PSObject.Properties | Where-Object { 
                                $_.MemberType -eq 'NoteProperty' -and $_.Name -notlike 'PS*' 
                            }
                            foreach ($val in $values) {
                                $content = $val.Value
                                if ($content -and (Contains-Keyword $content.ToString())) {
                                    $shouldDelete = $true
                                    break
                                }
                            }
                        }
                    } catch {
                        # Skip if we can't read properties
                        continue
                    }
                }
                
                if ($shouldDelete) {
                    Remove-Item -Path $subkey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "Deleted registry key: $($subkey.PSPath)" -ForegroundColor Red
                }
            }
        }
    } catch {
        continue
    }
}

# ----------------------------------------
# Section 2: Delete files in Prefetch with keywords (excluding whitelist)
# ----------------------------------------

# Delete files in Prefetch folder
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name
        if (Contains-Keyword $fileName) {
            try {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "Deleted prefetch file: $($_.FullName)" -ForegroundColor Red
            } catch {}
        }
    }
}

# ----------------------------------------
# Section 3: Clear various system logs
# ----------------------------------------

# Clear PowerShell logs
$psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistoryPath) {
    Remove-Item -Path $psHistoryPath -Force -ErrorAction SilentlyContinue
    Write-Host "Cleared PowerShell history" -ForegroundColor Yellow
}

# Clear Command Prompt history
$cmdHistoryPath = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
if (Test-Path $cmdHistoryPath) {
    Get-ChildItem -Path $cmdHistoryPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        if (Contains-Keyword $_.Name) {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# Clear Windows Event Logs that might contain PowerShell/command traces
$eventLogs = @(
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
)

foreach ($log in $eventLogs) {
    try {
        wevtutil.exe clear-log $log 2>&1 | Out-Null
        Write-Host "Cleared event log: $log" -ForegroundColor Yellow
    } catch {
        Write-Host "Failed to clear event log: $log" -ForegroundColor DarkYellow
    }
}

# Clear File System Journal (USN Journal)
try {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
    foreach ($drive in $drives) {
        fsutil usn deletejournal /D $drive.Root 2>&1 | Out-Null
        Write-Host "Cleared USN Journal on drive: $($drive.Root)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Failed to clear USN Journal" -ForegroundColor DarkYellow
}

# Clear Recent Items
$recentItemsPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentItemsPath) {
    Get-ChildItem -Path $recentItemsPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        if (Contains-Keyword $_.Name) {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Cleared recent items" -ForegroundColor Yellow
}

# Clear Temporary Files
$tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp")
foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            if (Contains-Keyword $_.Name) {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
Write-Host "Cleared temporary files" -ForegroundColor Yellow

Write-Host "Registry, Prefetch, and Log cleanup completed." -ForegroundColor Green
