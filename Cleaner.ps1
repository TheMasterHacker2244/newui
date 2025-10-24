$keywords = @(
    'matcha','evolve','software','loader','exploit','hack','mooze','isabelle',
    'matrix','severe','assembly','tsar','melatonin','external','dx9','serotonin',
    'aimmy','valex','vector','photon','nezur','thunder client','yebra','haze/myst',
    'haze','myst','horizon','havoc','colorbot','xeno','solara','wave','awp',
    'olduimatrix','autoexe','bin','workspace','monkeyaim','thunderaim',
    'thunderclient','celex','zarora','juju','nezure','fluxus','clumsy','build',
    'triggerbot','matcha.exe','triggerbot.exe','aimmy.exe','mystw','mystw\.exe',
    'dx9ware.exe','fusionhacks.zip','release.zip','build.zip','build.rar',
    'bootstrapper','bootstrappernew','santoware','mapper','bootstrappernew\.exe','updater.exe',
    'bootstrapper.exe','xeno.exe','xenoui.exe','solara.exe','mapper.exe',
    'loader.exe','evolve.exe','app.exe','bitcoin','boostrapper.exe','mathshard','clean.exe',
    'boostrappernew\.exe','authenticator.exe','inject','thing','thing.exe','A:','B:','D:','E:','F:',
    'G:','H:','I:','J:','K:','L:','M:','N:','O:','P:','Q:','R:','S:','T:','U:',
    'V:','W:','X:','Y:','Z:'
)

$keywords = $keywords | ForEach-Object { $_.ToLower() }

function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) {
        return $false
    }
    
    foreach ($keyword in $keywords) {
        if ($text -match [regex]::Escape($keyword)) {
            return $true
        }
    }
    return $false
}

$currentUserSID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.ProfileImagePath -like "*$env:USERNAME*"}).PSChildName

$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
)

if ($currentUserSID) {
    $registryPaths += "Registry::HKEY_USERS\$currentUserSID\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
}

foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
            
            foreach ($item in $items) {
                try {
                    $properties = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
                    if ($properties) {
                        $propertyNames = $properties.PSObject.Properties | Where-Object { 
                            $_.MemberType -eq 'NoteProperty' -or $_.MemberType -eq 'Property' 
                        } | Select-Object -ExpandProperty Name
                        
                        $shouldDelete = $false
                        $keyName = $item.PSChildName.ToLower()
                        
                        # Check the key name itself
                        if (Contains-Keyword $keyName) {
                            $shouldDelete = $true
                        }
                        
                        # Check property values
                        foreach ($propName in $propertyNames) {
                            if ($propName -ne 'PSPath' -and $propName -ne 'PSParentPath' -and $propName -ne 'PSChildName' -and $propName -ne 'PSDrive' -and $propName -ne 'PSProvider') {
                                $propValue = $properties.$propName
                                
                                # Handle different data types
                                if ($propValue -is [string]) {
                                    if (Contains-Keyword $propValue.ToLower()) {
                                        $shouldDelete = $true
                                        break
                                    }
                                } elseif ($propValue -is [int] -or $propValue -is [long]) {
                                    # Convert numeric values to string for keyword checking
                                    if (Contains-Keyword $propValue.ToString()) {
                                        $shouldDelete = $true
                                        break
                                    }
                                } elseif ($propValue -is [byte[]]) {
                                    # Convert byte arrays to string (hex representation)
                                    $hexString = [System.BitConverter]::ToString($propValue).Replace('-', '')
                                    if (Contains-Keyword $hexString) {
                                        $shouldDelete = $true
                                        break
                                    }
                                }
                            }
                        }
                        
                        if ($shouldDelete) {
                            Remove-Item -Path $item.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Host "Removed registry key: $($item.PSPath)"
                        }
                    }
                } catch {
                    # Continue to next item if we can't process this one
                    continue
                }
            }
        }
    } catch {
        Write-Host "Error processing path $path : $($_.Exception.Message)"
        continue
    }
}

# The rest of your file operations remain the same
$prefetchPath = "$env:SystemRoot\Prefetch"
Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
    $fileName = $_.Name.ToLower()
    if (Contains-Keyword $fileName) {
        try {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "Removed prefetch file: $($_.FullName)"
        } catch {}
    }
}

$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
    $fileName = $_.Name.ToLower()
    if (Contains-Keyword $fileName) {
        try {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "Removed recent file: $($_.FullName)"
        } catch {}
    }
}

$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue
    Write-Host "Removed PowerShell history"
}

@('Windows PowerShell','Microsoft-Windows-PowerShell/Operational') | ForEach-Object {
    try {
        wevtutil cl $_ 2>&1 | Out-Null
        Write-Host "Cleared event log: $_"
    } catch {}
}

# Handle the Services DWORD properly
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\SysTray'
$name = 'Services'

try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $cur = Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
    if ($cur -ne $null) {
        $curValue = $cur.$name
        Set-ItemProperty -Path $regPath -Name "${name}_Backup" -Value $curValue -Type DWord -ErrorAction SilentlyContinue
        
        $newValue = $curValue -band (-bnot 0x02)
        Set-ItemProperty -Path $regPath -Name $name -Value $newValue -Type DWord -ErrorAction SilentlyContinue
        Write-Host "Updated Services DWORD value"
    }
} catch {
    Write-Host "Error updating Services DWORD: $($_.Exception.Message)"
}
