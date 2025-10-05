Add-Type -Namespace Win32 -Name API -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint="LoadCursorW")]
public static extern System.IntPtr LoadCursor(System.IntPtr h, int n);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern System.IntPtr CopyIcon(System.IntPtr h);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetSystemCursor(System.IntPtr h, uint id);
"@
$arrow=[Win32.API]::LoadCursor([System.IntPtr]::Zero,32512)
[Win32.API]::SetSystemCursor([Win32.API]::CopyIcon($arrow),32650)
[Win32.API]::SetSystemCursor([Win32.API]::CopyIcon($arrow),32514)
Write-Host "Loading cursors set to normal arrow."
