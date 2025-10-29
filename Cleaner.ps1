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
        if ($lowerText -match "\\$keyword\\" -or $lowerText -match "\\$keyword\.exe" -or $lowerText -eq $keyword) {
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
        if ($lowerValue -match ".*\\$keyword\\.*" -or $lowerValue -match ".*\\$keyword\.exe.*") {
            return $true
        }
    }
    return $false
}

$currentUserSID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "*$env:USERNAME*"}).PSChildName

$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
)

if ($currentUserSID) {
    $registryPaths += "Registry::HKEY_USERS\$currentUserSID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    $registryPaths += "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    $registryPaths += "Registry::HKEY_USERS\$currentUserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
}

foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            Write-Host "Processing registry path: $path"
            
            $mainKeyProperties = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($mainKeyProperties) {
                $propertyNames = $mainKeyProperties.PSObject.Properties | Where-Object { 
                    $_.MemberType -eq 'NoteProperty' -and $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
                } | Select-Object -ExpandProperty Name
                
                foreach ($propName in $propertyNames) {
                    $propValue = $mainKeyProperties.$propName
                    
                    if ($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) {
                        try {
                            Remove-ItemProperty -Path $path -Name $propName -Force -ErrorAction SilentlyContinue
                            Write-Host "Removed registry value: $path\$propName"
                        } catch {
                            Write-Host "Failed to remove value $propName from $path : $($_.Exception.Message)"
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
                            
                            if ($propValue -is [string] -and (Should-Delete-RegistryValue $propValue)) {
                                try {
                                    Remove-ItemProperty -Path $subKeyPath -Name $propName -Force -ErrorAction SilentlyContinue
                                    Write-Host "Removed registry value: $subKeyPath\$propName"
                                    $deleteEntireKey = $true
                                } catch {
                                    Write-Host "Failed to remove value $propName from $subKeyPath : $($_.Exception.Message)"
                                }
                            }
                        }
                        
                        if ($deleteEntireKey) {
                            try {
                                Remove-Item -Path $subKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                                Write-Host "Removed registry key: $subKeyPath"
                            } catch {
                                Write-Host "Failed to remove key $subKeyPath : $($_.Exception.Message)"
                            }
                        }
                    }
                } catch {
                    Write-Host "Error processing subkey: $($_.Exception.Message)"
                    continue
                }
            }
        }
    } catch {
        Write-Host "Error processing path $path : $($_.Exception.Message)"
        continue
    }
}

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name.ToLower()
        
        if ($fileName -match "matcha|evolve|aimmy|myst|haze|xeno|solara|thing\.exe") {
            try {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "Removed prefetch file: $($_.FullName)"
            } catch {
                Write-Host "Failed to remove prefetch file $($_.FullName) : $($_.Exception.Message)"
            }
        }
    }
}

$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $fileName = $_.Name.ToLower()
        if ($fileName -match "matcha|evolve|aimmy|myst|haze|xeno|solara|thing\.exe|windowsdefender--threat-|storage|prefetch|settings|lastactivitycheckcleaner") {
            try {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "Removed recent file: $($_.FullName)"
            } catch {
                Write-Host "Failed to remove recent file $($_.FullName) : $($_.Exception.Message)"
            }
        }
        
        if ($_.Extension -eq '.lnk') {
            try {
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($_.FullName)
                $targetPath = $shortcut.TargetPath
                
                if ($targetPath -and !$targetPath.StartsWith('C:\')) {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    Write-Host "Removed suspicious shortcut (non-C: drive target): $($_.FullName)"
                }
            } catch {
                Write-Host "Could not read shortcut target for $($_.FullName) : $($_.Exception.Message)"
            }
        }
    }
}

$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    try {
        Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
        Write-Host "Removed PowerShell history"
    } catch {
        Write-Host "Failed to remove PowerShell history: $($_.Exception.Message)"
    }
}

@('Windows PowerShell','Microsoft-Windows-PowerShell/Operational') | ForEach-Object {
    try {
        wevtutil cl $_ 2>&1 | Out-Null
        Write-Host "Cleared event log: $_"
    } catch {
        Write-Host "Failed to clear event log $_ : $($_.Exception.Message)"
    }
}

Write-Host "Selective cleanup completed!"
