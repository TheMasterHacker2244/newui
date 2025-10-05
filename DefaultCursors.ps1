Add-Type -Namespace Win32 -Name API -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SystemParametersInfo(uint action, uint param, System.IntPtr vparam, uint init);
"@
[Win32.API]::SystemParametersInfo(0x0057, 0, [System.IntPtr]::Zero, 0)
Write-Host "System cursors restored to default."
