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
    'boostrappernew\.exe','authenticator.exe','inject','A:','B:','D:','E:','F:',
    'G:','H:','I:','J:','K:','L:','M:','N:','O:','P:','Q:','R:','S:','T:','U:',
    'V:','W:','X:','Y:','Z:'
)

# Convert keywords to lowercase for case-insensitive matching
$keywords = $keywords | ForEach-Object { $_.ToLower() }

# Function to check if text contains any of the keywords
function Contains-Keyword {
    param ([string]$text)
    foreach ($keyword in $keywords) {
        if ($text -match [regex]::Escape($keyword)) {
            return $true
        }
    }
    return $false
}

# ----------------------------------------
# Section 1: Delete Registry Keys with specified keywords
# ----------------------------------------

# Get all registry paths to scan
$registryPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatIDDefaultAction",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
)

foreach ($path in $registryPaths) {
    try {
        $subkeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        if ($subkeys) {
            foreach ($subkey in $subkeys) {
                $name = $subkey.PSChildName.ToLower()
                $values = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                $valueContent = ""
                foreach ($val in $values) {
                    try {
                        $content = (Get-ItemProperty -Path $subkey.PSPath -Name $val -ErrorAction SilentlyContinue).$val
                        if ($content) {
                            $valueContent += " $content"
                        }
                    } catch {}
                }
                if (Contains-Keyword $name -or (Contains-Keyword $valueContent)) {
                    Remove-Item -Path $subkey.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        continue
    }
}

# ----------------------------------------
# Section 2: Delete files in Prefetch and Recent items with keywords
# ----------------------------------------

# Delete files in Prefetch folder
$prefetchPath = "$env:SystemRoot\Prefetch"
Get-ChildItem -Path $prefetchPath -File -ErrorAction SilentlyContinue | ForEach-Object {
    $fileName = $_.Name.ToLower()
    if (Contains-Keyword $fileName) {
        try {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

# Delete files in Recent items
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue | ForEach-Object {
    $fileName = $_.Name.ToLower()
    if (Contains-Keyword $fileName) {
        try {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        } catch {}
    }
}

# ----------------------------------------
# Section 3: Remove PowerShell traces
# ----------------------------------------

# Remove PowerShell history
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Remove-Item -Path $historyPath -Force -ErrorAction SilentlyContinue

# Clear PowerShell event logs
@('Windows PowerShell','Microsoft-Windows-PowerShell/Operational') | ForEach-Object {
    try {
        wevtutil cl $_ 2>&1 | Out-Null
    } catch {}
}

# ----------------------------------------
# Section 4: Manage USB tray icon and refresh tray
# ----------------------------------------

# Hide USB tray icon
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\SysTray'
$name = 'Services'

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$cur = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name
if ($null -eq $cur) { $cur = 0x1F }

Set-ItemProperty -Path $regPath -Name "${name}_Backup" -Value ([int]$cur) -Type DWord -ErrorAction SilentlyContinue

$new = $cur -band (-bnot 0x02)
Set-ItemProperty -Path $regPath -Name $name -Value ([int]$new) -Type DWord -ErrorAction SilentlyContinue
