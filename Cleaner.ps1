# Run as Administrator check
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Restarting as Administrator..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$keywords = @(
    'matcha','evolve','mooze','isabelle','matrix','tsar','melatonin','serotonin',
    'aimmy','aimbot','valex','vector','photon','nezur','yebra','haze/myst','haze','myst',
    'horizon','havoc','colorbot','xeno','solara','olduimatrix','monkeyaim',
    'thunderaim','thunderclient','celex','zarora','juju','nezure','fluxus','clumsy',
    'matcha\.exe','triggerbot\.exe','aimmy\.exe','mystw\.exe','thing\.exe','dx9ware\.exe',
    'fusionhacks\.zip','release\.zip','build\.zip','build\.rar','bootstrappernew',
    'santoware','bootstrappernew\.exe','xeno\.exe','xenoui\.exe','solara\.exe',
    'mapper\.exe','map\.exe','evolve\.exe','boostrapper\.exe','mathshard','clean\.exe',
    'boostrappernew\.exe','authenticator\.exe','thing\.exe','app.exe','update.exe','updater.exe','upgrade','threat-','cleaner',
    "J:","A:","B:","D:","E:","F:","G:","H:","I:","J:","K:","L:","M:",
    "N:","O:","P:","Q:","R:","S:","T:","U:","V:","W:","X:","Y:","Z:",
    "Aura","loader","MainRunner","usermode"
)

$keywords = $keywords | ForEach-Object { $_.ToLower() }

function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) {
        return $false
    }
    
    $lowerText = $text.ToLower()
    foreach ($keyword in $keywords) {
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
        if ($lowerValue -match [regex]::Escape($keyword) -or 
            $lowerValue -match ".*\\$keyword\\.*" -or 
            $lowerValue -match ".*\\$keyword\.exe.*" -or
            $lowerValue -match ".*$keyword.*") {
            return $true
        }
    }
    return $false
}

function Is-NonC-Drive-Path {
    param ([string]$path)
    
    if ([string]::IsNullOrEmpty($path)) {
        return $false
    }
    
    if ($path -match '^[A-BD-Z]:\\') {
        return $true
    }
    
    if ($path -match '\\\\\?\\[A-BD-Z]:' -or $path -match '^[A-BD-Z]:\\') {
        return $true
    }
    
    return $false
}

function Get-ShortcutTarget {
    param ([string]$shortcutPath)
    
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        return $shortcut.TargetPath
    } catch {
        return $null
    }
}

function Remove-BamAllKeywords {
    Write-Host "`nStarting BAM/Registry cleanup for ALL keywords..." -ForegroundColor Cyan
    
    $scriptPath = "$env:ProgramData\DelBamKeywords.ps1"
    
    # Create a script that checks ALL keywords
    $keywordsString = $keywords -join "','"
    @"
`$keywords = @('$keywordsString')

function Contains-Keyword {
    param ([string]`$text)
    
    if ([string]::IsNullOrEmpty(`$text)) {
        return `$false
    }
    
    `$lowerText = `$text.ToLower()
    foreach (`$keyword in `$keywords) {
        if (`$lowerText -match [regex]::Escape(`$keyword) -or 
            `$lowerText -match "\\\\`$keyword\\\\" -or 
            `$lowerText -match "\\\\`$keyword\\.exe") {
            return `$true
        }
    }
    return `$false
}

# Clean BAM registry
`$root = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path `$root) {
    Get-ChildItem `$root | ForEach-Object {
        `$sidKeyPath = `$_.PsPath
        `$key = Get-Item `$sidKeyPath
        foreach (`$prop in `$key.Property) {
            if (Contains-Keyword `$prop) {
                Write-Host "Deleting BAM entry: `$prop in `$sidKeyPath"
                Remove-ItemProperty -Path `$sidKeyPath -Name `$prop -Force
            }
        }
    }
}

# Clean additional registry paths
`$additionalPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\WinRAR\DialogEditHistory",
    "HKCU:\SOFTWARE\WinRAR\ArcHistory",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKLM:\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
)

foreach (`$path in `$additionalPaths) {
    if (Test-Path `$path) {
        try {
            `$key = Get-Item `$path -ErrorAction SilentlyContinue
            if (`$key) {
                foreach (`$prop in `$key.Property) {
                    if (Contains-Keyword `$prop) {
                        Write-Host "Deleting from `$path: `$prop"
                        Remove-ItemProperty -Path `$path -Name `$prop -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            # Also check subkeys
            Get-ChildItem `$path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                `$subKeyPath = `$_.PsPath
                try {
                    `$subKey = Get-Item `$subKeyPath -ErrorAction SilentlyContinue
                    if (`$subKey) {
                        foreach (`$prop in `$subKey.Property) {
                            if (Contains-Keyword `$prop) {
                                Write-Host "Deleting from `$subKeyPath: `$prop"
                                Remove-ItemProperty -Path `$subKeyPath -Name `$prop -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                } catch {}
            }
        } catch {}
    }
}
"@ | Set-Content -Path $scriptPath -Encoding ASCII

    # Create and run scheduled task
    $taskName = "DelBamKeywords"
    $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    schtasks /Create /TN $taskName /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /TR "$tr" /F
    schtasks /Run /TN $taskName
    Start-Sleep -Seconds 3
    schtasks /Delete /TN $taskName /F
    
    # Clean up script
    if (Test-Path $scriptPath) {
        Remove-Item $scriptPath -Force
    }
    
    Write-Host "BAM/Registry cleanup completed." -ForegroundColor Green
}

Write-Host "Starting comprehensive cleanup..." -ForegroundColor Green

$currentUserSID = (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq "C:\Users\$env:USERNAME" }).SID
if (-not $currentUserSID) {
    $currentUserSID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "*$env:USERNAME*"}).PSChildName
}

Write-Host "User SID: $currentUserSID" -ForegroundColor Yellow

# Updated registry paths with the new additions
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
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
    "HKCU:\SOFTWARE\WinRAR\DialogEditHistory",
    "HKCU:\SOFTWARE\WinRAR\ArcHistory",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
    "HKLM:\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications"
)

# Add user-specific paths if SID is available
if ($currentUserSID) {
    $registryPaths += @(
        "Registry::HKEY_USERS\$currentUserSID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\Shell\Associations\ApplicationAssociationStore",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps",
        "Registry::HKEY_USERS\$currentUserSID\Software\WinRAR\DialogEditHistory",
        "Registry::HKEY_USERS\$currentUserSID\Software\WinRAR\ArcHistory",
        "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    )
}

$totalRemoved = 0
foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            Write-Host "`nProcessing registry path: $path" -ForegroundColor Cyan
            
            # Check and delete the main key if it matches keywords
            if (Contains-Keyword $path) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed entire registry key (keyword match): $path" -ForegroundColor Green
                    $totalRemoved++
                    continue
                } catch {
                    Write-Host "✗ Failed to remove key $path : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
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
        } else {
            Write-Host "Skipping (not found): $path" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Error processing path $path : $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

Write-Host "`nRegistry cleanup completed. Total items removed: $totalRemoved" -ForegroundColor Yellow

Write-Host "`nStarting TARGETED Prefetch cleanup (keywords only)..." -ForegroundColor Cyan
$prefetchCount = 0

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "Scanning Prefetch directory: $prefetchPath" -ForegroundColor Yellow
    
    Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name.ToLower()
        $fileDeleted = $false
        
        foreach ($keyword in $keywords) {
            $cleanKeyword = $keyword.Replace('.exe', '').Replace('\.exe', '').Replace('.', '')
            if ($fileName -match [regex]::Escape($cleanKeyword)) {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed targeted prefetch file: $($_.Name)" -ForegroundColor Green
                    $prefetchCount++
                    $fileDeleted = $true
                    break
                } catch {
                    Write-Host "✗ Failed to remove targeted prefetch file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        
        if (-not $fileDeleted) {
            $suspiciousPatterns = @(
                'matcha', 'evolve', 'aimmy', 'myst', 'haze', 'xeno', 'solara', 
                'thing', 'triggerbot', 'dx9ware', 'bootstrapper', 'authenticator', 
                'mainrunner', 'aimbot', 'usermode'
            )
            
            foreach ($pattern in $suspiciousPatterns) {
                if ($fileName -match $pattern) {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "✓ Removed suspicious prefetch file: $($_.Name)" -ForegroundColor Green
                        $prefetchCount++
                        break
                    } catch {
                        Write-Host "✗ Failed to remove suspicious prefetch file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }
    
    if ($prefetchCount -eq 0) {
        Write-Host "No prefetch files matching keywords were found." -ForegroundColor Yellow
    } else {
        Write-Host "Targeted Prefetch cleanup completed. Files removed: $prefetchCount" -ForegroundColor Yellow
    }
} else {
    Write-Host "Prefetch path not found: $prefetchPath" -ForegroundColor Red
}

Write-Host "`nStarting Enhanced Recent files cleanup (C++, AHK, USB content, Keywords)..." -ForegroundColor Cyan
$recentCount = 0

$recentRoot  = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
$autoDest    = Join-Path $recentRoot 'AutomaticDestinations'
$customDest  = Join-Path $recentRoot 'CustomDestinations'

Write-Host "Scanning main Recent folder for keyword matches..." -ForegroundColor Yellow
Get-ChildItem -Path $recentRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object { 
    $_.Name -like "*MainRunner*" -or (Contains-Keyword $_.Name)
} | ForEach-Object {
    try {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Removed recent file (keyword match): $($_.Name)" -ForegroundColor Green
        $recentCount++
    } catch {
        Write-Host "✗ Failed to remove recent file $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
    }
}

foreach ($folder in @($autoDest, $customDest)) {
    if (Test-Path $folder) {
        Write-Host "Scanning destination folder for content matches: $folder" -ForegroundColor Yellow
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            try {
                $contentMatch = $false
                $matchedKeyword = ""
                
                foreach ($keyword in @('MainRunner', 'aimbot', 'usermode') + $keywords) {
                    if (Select-String -Path $file.FullName -Pattern $keyword -SimpleMatch -Quiet -ErrorAction SilentlyContinue) {
                        $contentMatch = $true
                        $matchedKeyword = $keyword
                        break
                    }
                }
                
                if ($contentMatch) {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed destination file (content match: $matchedKeyword): $($file.Name)" -ForegroundColor Green
                    $recentCount++
                }
            } catch {
                Write-Host "✗ Error processing destination file $($file.Name) : $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`nPerforming enhanced file type and location checks..." -ForegroundColor Yellow
$recentPaths = @($recentRoot, $autoDest, $customDest)

foreach ($recentPath in $recentPaths) {
    if (Test-Path $recentPath) {
        Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            $name = $file.Name.ToLower()
            $delete = $false

            if ($name -match 'thing' -or $name -match 'storage') {
                $delete = $true
            }

            if ($file.Extension -eq '.cpp' -or $name -match '\.cpp$') {
                $delete = $true
                Write-Host "✓ Found C++ file in recent: $($file.Name)" -ForegroundColor Yellow
            }

            if ($file.Extension -eq '.ahk' -or $name -match '\.ahk$') {
                $delete = $true
                Write-Host "✓ Found AHK file in recent: $($file.Name)" -ForegroundColor Yellow
            }

            if ($file.Extension -eq '.lnk') {
                try {
                    $targetPath = (Get-ShortcutTarget $file.FullName)
                    
                    if ($targetPath) {
                        if (Is-NonC-Drive-Path $targetPath) {
                            $delete = $true
                            Write-Host "✓ Found USB shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                        
                        if ($targetPath -match '\.ahk$') {
                            $delete = $true
                            Write-Host "✓ Found AHK shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                        
                        if (Contains-Keyword $targetPath) {
                            $delete = $true
                            Write-Host "✓ Found keyword in shortcut target: $targetPath" -ForegroundColor Yellow
                        }
                    }
                } catch {
                }
            }

            if ($delete) {
                try {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "✓ Removed recent file: $($file.Name)" -ForegroundColor Green
                    $recentCount++
                } catch {
                    Write-Host "✗ Failed to remove recent file $($file.Name) : $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

Write-Host "Enhanced Recent files cleanup completed. Files removed: $recentCount" -ForegroundColor Yellow

# Updated BAM cleanup function
Remove-BamAllKeywords

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
                    }
                }
            }
        }
    }
}

Write-Host "`n" + "="*50 -ForegroundColor Green
Write-Host "ENHANCED TARGETED CLEANUP COMPLETED!" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Green
Write-Host "Total registry items removed: $totalRemoved" -ForegroundColor Yellow
Write-Host "Total prefetch files removed: $prefetchCount" -ForegroundColor Yellow
Write-Host "Total recent files removed: $recentCount" -ForegroundColor Yellow
Write-Host "Detection capabilities:" -ForegroundColor Cyan
Write-Host "  • Keyword targeting (ALL keywords including aimbot, usermode, MainRunner, etc.)" -ForegroundColor White
Write-Host "  • C++ files (.cpp)" -ForegroundColor White
Write-Host "  • AHK files and shortcuts" -ForegroundColor White
Write-Host "  • USB drive content (non-C: drives)" -ForegroundColor White
Write-Host "  • File content scanning in destination folders" -ForegroundColor White
Write-Host "  • Enhanced BAM/Registry cleanup for ALL keywords" -ForegroundColor White
Write-Host "  • Added registry paths: DeviceGuard, WinRAR history, TypedPaths, RADAR, etc." -ForegroundColor White
Write-Host "Recommendation: Restart your computer to complete the cleanup process." -ForegroundColor Yellow
