# Run as Administrator check
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Restarting as Administrator..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$keywords = @(
    'matcha','evolve','mooze','isabelle','matrix','tsar','melatonin','serotonin',
    'aimmy','valex','vector','photon','nezur','yebra','haze/myst','haze','myst',
    'horizon','havoc','colorbot','xeno','solara','olduimatrix','monkeyaim',
    'thunderaim','thunderclient','celex','zarora','juju','nezure','fluxus','clumsy',
    'matcha\.exe','triggerbot\.exe','aimmy\.exe','mystw\.exe','dx9ware\.exe',
    'fusionhacks\.zip','release\.zip','build\.zip','build\.rar','bootstrappernew',
    'santoware','bootstrappernew\.exe','xeno\.exe','xenoui\.exe','solara\.exe',
    'mapper\.exe','evolve\.exe','boostrapper\.exe','mathshard','clean\.exe',
    'boostrappernew\.exe','authenticator\.exe','thing\.exe'
)

$keywords = $keywords | ForEach-Object { $_.ToLower() }

function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) {
        return $false
    }
    
    $lowerText = $text.ToLower()
    foreach ($keyword in $keywords) {
        # More flexible matching for file paths and registry values
        if ($lowerText -match [regex]::Escape($keyword) -or 
            $lowerText -match "\\$keyword\\" -or 
            $lowerText -match "\\$keyword\.exe" -or 
            $lowerText -eq $keyword) {
            return $true
        }
    }
    return $false
}

function Should-Delete-RegistryValue {
    param ([string]$value)
    
    if ([string]::IsNullOrEmpty($value)) {
        return $false
    }
    
    $lowerValue = $value.ToLower()
    
    foreach ($keyword in $keywords) {
        # More comprehensive matching for registry values
        if ($lowerValue -match [regex]::Escape($keyword) -or 
            $lowerValue -match ".*\\$keyword\\.*" -or 
            $lowerValue -match ".*\\$keyword\.exe.*" -or
            $lowerValue -match ".*$keyword.*") {
            return $true
        }
    }
    return $false
}

Write-Host "Starting comprehensive cleanup..." -ForegroundColor Green

# Get current user SID more reliably
$currentUserSID = (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$env:USERNAME" }).SID
if (-not $currentUserSID) {
    $currentUserSID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "*$env:USERNAME*"}).PSChildName
}

Write-Host "User SID: $currentUserSID" -ForegroundColor Yellow

$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\ApplicationAssociationStore",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps"
)

# Add user-specific paths if SID is available
if ($currentUserSID) {
    $registryPaths += @(
        "Registry::HKEY_USERS\$currentUserSID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\Shell\Associations\ApplicationAssociationStore",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
    )
}

# Registry cleanup with improved logic
$totalRemoved = 0
foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            Write-Host "`nProcessing registry path: $path" -ForegroundColor Cyan
            
            # Process main key properties
            $mainKeyProperties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($mainKeyProperties) {
                $propertyNames = $mainKeyProperties.PSObject.Properties | Where-Object { 
                    $_.MemberType -eq 'NoteProperty' -and $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                } | Select-Object -ExpandProperty Name
                
                foreach ($propName in $propertyNames) {
                    $propValue = $mainKeyProperties.$propName
                    
                    if (($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) -or 
                        (Contains-Keyword $propName)) {
                        try {
                            Remove-ItemProperty -Path $path -Name $propName -Force -ErrorAction SilentlyContinue
                            Write-Host "✓ Removed registry value: $propName" -ForegroundColor Green
                            $totalRemoved++
                        } catch {
                            Write-Host "✗ Failed to remove value $propName from $path : $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            }
            
            # Process subkeys recursively
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Recurse
            
            foreach ($item in $items) {
                try {
                    $subKeyPath = $item.PSPath
                    $subKeyProperties = Get-ItemProperty -Path $subKeyPath -ErrorAction SilentlyContinue
                    
                    if ($subKeyProperties) {
                        $propertyNames = $subKeyProperties.PSObject.Properties | Where-Object { 
                            $_.MemberType -eq 'NoteProperty' -and $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                        } | Select-Object -ExpandProperty Name
                        
                        $deleteEntireKey = $false
                        
                        foreach ($propName in $propertyNames) {
                            $propValue = $subKeyProperties.$propName
                            
                            if (($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) -or 
                                (Contains-Keyword $propName)) {
                                try {
                                    Remove-ItemProperty -Path $subKeyPath -Name $propName -Force -ErrorAction SilentlyContinue
                                    Write-Host "✓ Removed registry value: $subKeyPath\$propName" -ForegroundColor Green
                                    $deleteEntireKey = $true
                                    $totalRemoved++
                                } catch {
                                    Write-Host "✗ Failed to remove value $propName from $subKeyPath : $($_.Exception.Message)" -ForegroundColor Red
                                }
                            }
                        }
                        
                        # Check if the key name itself contains keywords
                        if (Contains-Keyword $subKeyPath) {
                            $deleteEntireKey = $true
                        }
                        
                        if ($deleteEntireKey) {
                            try {
                                Remove-Item -Path $subKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                                Write-Host "✓ Removed registry key: $subKeyPath" -ForegroundColor Green
                                $totalRemoved++
                            } catch {
                                Write-Host "✗ Failed to remove key $subKeyPath : $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }
                    }
                } catch {
                    Write-Host "Error processing subkey: $($_.Exception.Message)" -ForegroundColor Red
                    continue
                }
            }
        }
    } catch {
        Write-Host "Error processing path $path : $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

Write-Host "`nRegistry cleanup completed. Total items removed: $totalRemoved" -ForegroundColor Yellow

# Enhanced Prefetch cleanup - COMPREHENSIVE VERSION
Write-Host "`nStarting comprehensive Prefetch cleanup..." -ForegroundColor Cyan
$prefetchCount = 0

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "Cleaning Prefetch directory: $prefetchPath" -ForegroundColor Yellow
    
    # Method 1: Delete all prefetch files (most thorough)
    try {
        Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $prefetchCount++
            } catch {
                # Skip files that are locked or in use
            }
        }
        Write-Host "✓ Removed $prefetchCount generic .pf files" -ForegroundColor Green
    } catch {
        Write-Host "✗ Error removing generic prefetch files: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Method 2: Targeted deletion based on keywords
    $targetedCount = 0
    Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name.ToLower()
        
        foreach ($keyword in $keywords) {
            $cleanKeyword = $keyword.Replace('.exe', '').Replace('\.exe', '').Replace('.', '')
            if ($fileName -match [regex]::Escape($cleanKeyword)) {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed targeted prefetch file: $($_.Name)" -ForegroundColor Green
                    $targetedCount++
                    break
                } catch {
                    Write-Host "✗ Failed to remove targeted prefetch file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    # Method 3: Clean layout.ini and other prefetch-related files
    try {
        $layoutFile = "$prefetchPath\layout.ini"
        if (Test-Path $layoutFile) {
            Remove-Item $layoutFile -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Removed layout.ini file" -ForegroundColor Green
            $prefetchCount++
        }
    } catch {
        Write-Host "✗ Failed to remove layout.ini" -ForegroundColor Red
    }
    
    Write-Host "Prefetch cleanup completed. Total files removed: $($prefetchCount + $targetedCount)" -ForegroundColor Yellow
} else {
    Write-Host "Prefetch path not found: $prefetchPath" -ForegroundColor Red
}

# Recent files cleanup
$recentPaths = @(
    "$env:APPDATA\Microsoft\Windows\Recent",
    "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
    "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
)

foreach ($recentPath in $recentPaths) {
    if (Test-Path $recentPath) {
        Write-Host "`nCleaning Recent files: $recentPath" -ForegroundColor Cyan
        $recentCount = 0
        Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            $fileName = $_.Name.ToLower()
            $shouldRemove = $false
            
            foreach ($keyword in $keywords) {
                if ($fileName -match [regex]::Escape($keyword)) {
                    $shouldRemove = $true
                    break
                }
            }
            
            # Additional suspicious patterns
            if ($fileName -match "windowsdefender.*threat" -or 
                $fileName -match "storage" -or 
                $fileName -match "prefetch" -or 
                $fileName -match "settings" -or 
                $fileName -match "lastactivitycheckcleaner") {
                $shouldRemove = $true
            }
            
            if ($shouldRemove) {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed recent file: $($_.Name)" -ForegroundColor Green
                    $recentCount++
                } catch {
                    Write-Host "✗ Failed to remove recent file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            # Check .lnk files for suspicious targets
            if ($_.Extension -eq '.lnk') {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($_.FullName)
                    $targetPath = $shortcut.TargetPath
                    
                    if ($targetPath -and !$targetPath.StartsWith('C:\') -and !$targetPath.StartsWith('C:\Windows')) {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "✓ Removed suspicious shortcut: $($_.Name)" -ForegroundColor Green
                        $recentCount++
                    }
                } catch {
                    # Ignore errors reading shortcuts
                }
            }
        }
        Write-Host "Recent files cleanup completed for $recentPath. Files removed: $recentCount" -ForegroundColor Yellow
    }
}

# PowerShell history cleanup
Write-Host "`nCleaning PowerShell history..." -ForegroundColor Cyan
$historyPaths = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\VisualStudioCode_host_history.txt",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell_host_history.txt"
)

foreach ($historyPath in $historyPaths) {
    if (Test-Path $historyPath) {
        try {
            Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Removed PowerShell history: $historyPath" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to remove PowerShell history $historyPath : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Event log clearing
Write-Host "`nClearing event logs..." -ForegroundColor Cyan
$eventLogs = @('Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'System', 'Application')

foreach ($log in $eventLogs) {
    try {
        wevtutil cl $log 2>&1 | Out-Null
        Write-Host "✓ Cleared event log: $log" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to clear event log $log : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Additional cleanup: Temp files
Write-Host "`nCleaning temporary files..." -ForegroundColor Cyan
$tempPaths = @("$env:TEMP", "$env:SystemRoot\Temp")
foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($keyword in $keywords) {
                if ($_.Name.ToLower() -match [regex]::Escape($keyword)) {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "✓ Removed temp file: $($_.Name)" -ForegroundColor Green
                        break
                    } catch {
                        # Ignore deletion errors for temp files
                    }
                }
            }
        }
    }
}

Write-Host "`n" + "="*50 -ForegroundColor Green
Write-Host "COMPREHENSIVE CLEANUP COMPLETED!" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Green
Write-Host "Total registry items removed: $totalRemoved" -ForegroundColor Yellow
Write-Host "Total prefetch files removed: $prefetchCount" -ForegroundColor Yellow
Write-Host "Recommendation: Restart your computer to complete the cleanup process." -ForegroundColor Yellow
