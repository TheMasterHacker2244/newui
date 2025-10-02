$keywords = @(
    'matcha','evolve','software','loader','exploit','hack','mooze','isabelle',
    'matrix','severe','assembly','tsar','melatonin','external','dx9','serotonin',
    'aimmy','valex','vector','photon','nezur','thunder client','yebra',
    'thunderclient','celex','zarora','juju','nezure','fluxus','clumsy','build',
    'triggerbot','matcha.exe','triggerbot.exe','aimmy.exe','mystw','mystw\.exe',
    'dx9ware.exe','fusionhacks.zip','release.zip','build.zip','build.rar',
    'bootstrapper','bootstrappernew','santoware','mapper','bootstrappernew\.exe',
    'bootstrapper.exe','xeno.exe','xenoui.exe','solara.exe','mapper.exe',
    'loader.exe','evolve.exe','app.exe','bitcoin','boostrapper.exe',
    'boostrappernew\.exe','authenticator.exe','inject','release','cloudy',
    'tupical','celery','software.exe','update.exe','upgrade.exe','launcher',
    'fast','launch','nigger','nigga','silent','ming','key','E:','F:','G:','H:',
    'I:','J:','K:','L:','M:','N:','O:','P:','Q:','R:','S:','T:','U:','V:','W:',
    'X:','Y:','Z:','A:','B:','D:'
)

$keywords = $keywords | ForEach-Object { $_.ToLower() }

function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) { return $false }
    
    $textLower = $text.ToLower()
    
    foreach ($keyword in $keywords) {
        if ($textLower -match [regex]::Escape($keyword)) {
            return $true
        }
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

function Clean-RecentFolder {
    $recentPath = "C:\Users\$env:USERNAME\Recent"
    
    if (-not (Test-Path $recentPath)) {
        Write-Host "Recent folder not found: $recentPath" -ForegroundColor Yellow
        return
    }
    
    $shortcuts = Get-ChildItem -Path $recentPath -Filter "*.lnk" -Force -ErrorAction SilentlyContinue
    Write-Host "Found $($shortcuts.Count) shortcuts in Recent folder" -ForegroundColor Gray
    
    foreach ($shortcut in $shortcuts) {
        $shouldDelete = $false
        
        if (Contains-Keyword $shortcut.Name) {
            $shouldDelete = $true
            Write-Host "MATCH SHORTCUT NAME: $($shortcut.Name)" -ForegroundColor Magenta
        }
        
        if (-not $shouldDelete) {
            $targetPath = Get-ShortcutTarget -shortcutPath $shortcut.FullName
            if ($targetPath) {
                $targetExtension = [System.IO.Path]::GetExtension($targetPath).ToLower()
                
                if ($targetExtension -in '.cpp', '.ahk') {
                    $shouldDelete = $true
                    Write-Host "MATCH TARGET EXTENSION: $targetPath" -ForegroundColor Magenta
                }
                
                if (-not $shouldDelete -and $targetPath -notlike "C:\*" -and $targetPath -match "^[A-Z]:\\") {
                    $shouldDelete = $true
                    Write-Host "MATCH NON-C DRIVE: $targetPath" -ForegroundColor Magenta
                }
                
                if (-not $shouldDelete -and (Contains-Keyword $targetPath)) {
                    $shouldDelete = $true
                    Write-Host "MATCH TARGET PATH: $targetPath" -ForegroundColor Magenta
                }
            }
        }
        
        if ($shouldDelete) {
            Remove-Item -Path $shortcut.FullName -Force -ErrorAction SilentlyContinue
            Write-Host "DELETED SHORTCUT: $($shortcut.FullName)" -ForegroundColor Red
        }
    }
}

function Clean-RegistryPath {
    param ([string]$registryPath)
    
    Write-Host "Scanning: $registryPath" -ForegroundColor Cyan
    
    if (-not (Test-Path $registryPath)) {
        Write-Host "Path does not exist: $registryPath" -ForegroundColor Yellow
        return
    }
    
    try {
        $regKey = Get-Item -Path $registryPath -ErrorAction Stop
        $valueNames = $regKey.GetValueNames()
        
        Write-Host "Found $($valueNames.Count) values to check..." -ForegroundColor Gray
        
        foreach ($valueName in $valueNames) {
            try {
                $valueData = $regKey.GetValue($valueName)
                $shouldDelete = $false
                
                if (Contains-Keyword $valueName) {
                    $shouldDelete = $true
                    Write-Host "MATCH VALUE NAME: $valueName" -ForegroundColor Magenta
                }
                
                if (-not $shouldDelete -and $valueData -ne $null) {
                    if ($valueData -is [byte[]]) {
                        $hexString = [System.BitConverter]::ToString($valueData)
                        $asciiString = [System.Text.Encoding]::ASCII.GetString($valueData)
                        
                        if (Contains-Keyword $hexString) { 
                            $shouldDelete = $true
                            Write-Host "MATCH BINARY HEX: $hexString" -ForegroundColor Magenta
                        }
                        elseif (Contains-Keyword $asciiString) { 
                            $shouldDelete = $true
                            Write-Host "MATCH BINARY ASCII: $asciiString" -ForegroundColor Magenta
                        }
                    }
                    elseif ($valueData -is [string[]]) {
                        $combinedString = $valueData -join " "
                        if (Contains-Keyword $combinedString) { 
                            $shouldDelete = $true
                            Write-Host "MATCH MULTI-STRING: $combinedString" -ForegroundColor Magenta
                        }
                    }
                    else {
                        $stringValue = $valueData.ToString()
                        if (Contains-Keyword $stringValue) { 
                            $shouldDelete = $true
                            Write-Host "MATCH VALUE DATA: $stringValue" -ForegroundColor Magenta
                        }
                    }
                }
                
                if ($shouldDelete) {
                    Remove-ItemProperty -Path $registryPath -Name $valueName -Force -ErrorAction SilentlyContinue
                    Write-Host "DELETED: $registryPath\$valueName" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error processing value: $valueName - $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }
        
        if ($registryPath -like "*AppSwitched*") {
            $subkeys = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue
            Write-Host "Found $($subkeys.Count) subkeys to check..." -ForegroundColor Gray
            
            foreach ($subkey in $subkeys) {
                $subkeyName = $subkey.PSChildName
                if (Contains-Keyword $subkeyName) {
                    try {
                        Remove-Item -Path $subkey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "DELETED SUBKEY: $($subkey.PSPath)" -ForegroundColor Red
                    } catch {
                        Write-Host "Failed to delete subkey: $subkeyName - $($_.Exception.Message)" -ForegroundColor DarkYellow
                    }
                }
            }
        }
        
    } catch {
        Write-Host "Error accessing registry path: $registryPath - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Starting cleanup..." -ForegroundColor Green

$targetPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", 
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
)

Write-Host "Scanning Recent folder..." -ForegroundColor Green
Clean-RecentFolder

Write-Host "Scanning Registry..." -ForegroundColor Green
foreach ($path in $targetPaths) {
    Clean-RegistryPath -registryPath $path
}

Write-Host "Cleanup completed!" -ForegroundColor Green
