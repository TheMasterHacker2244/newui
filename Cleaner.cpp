# Define your keywords (case-insensitive)
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

# Convert to lowercase for case-insensitive matching
$keywords = $keywords | ForEach-Object { $_.ToLower() }

# Function to check if text contains any of the keywords
function Contains-Keyword {
    param ([string]$text)
    
    if ([string]::IsNullOrEmpty($text)) { return $false }
    
    $textLower = $text.ToLower()
    
    # Check for keywords - NO WHITELIST for these specific registry paths
    foreach ($keyword in $keywords) {
        if ($textLower -match [regex]::Escape($keyword)) {
            return $true
        }
    }
    return $false
}

# Function to scan and clean registry path
function Clean-RegistryPath {
    param ([string]$registryPath)
    
    Write-Host "Scanning: $registryPath" -ForegroundColor Cyan
    
    if (-not (Test-Path $registryPath)) {
        Write-Host "Path does not exist: $registryPath" -ForegroundColor Yellow
        return
    }
    
    try {
        # Get the registry key
        $regKey = Get-Item -Path $registryPath -ErrorAction Stop
        
        # Get all value names in this key
        $valueNames = $regKey.GetValueNames()
        
        Write-Host "Found $($valueNames.Count) values to check..." -ForegroundColor Gray
        
        foreach ($valueName in $valueNames) {
            try {
                $valueData = $regKey.GetValue($valueName)
                $shouldDelete = $false
                
                # Check value name
                if (Contains-Keyword $valueName) {
                    $shouldDelete = $true
                    Write-Host "MATCH VALUE NAME: $valueName" -ForegroundColor Magenta
                }
                
                # Check value data
                if (-not $shouldDelete -and $valueData -ne $null) {
                    if ($valueData -is [byte[]]) {
                        # Binary data - convert to multiple formats for checking
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
                        # Multi-string - join for checking
                        $combinedString = $valueData -join " "
                        if (Contains-Keyword $combinedString) { 
                            $shouldDelete = $true
                            Write-Host "MATCH MULTI-STRING: $combinedString" -ForegroundColor Magenta
                        }
                    }
                    else {
                        # Single string, DWORD, etc.
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
        
        # For AppSwitched path, also check subkeys
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

# ----------------------------------------
# MAIN EXECUTION - Only the three specified paths
# ----------------------------------------

Write-Host "Starting aggressive registry cleanup..." -ForegroundColor Green
Write-Host "NO WHITELIST - All matches will be deleted!" -ForegroundColor Red
Write-Host "Focusing only on the three specified registry paths" -ForegroundColor Yellow

$targetPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", 
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
)

foreach ($path in $targetPaths) {
    Clean-RegistryPath -registryPath $path
}

Write-Host "Aggressive registry cleanup completed!" -ForegroundColor Green
Write-Host "Scanned paths:" -ForegroundColor White
foreach ($path in $targetPaths) {
    Write-Host "  - $path" -ForegroundColor White
}
