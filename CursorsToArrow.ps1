Add-Type -Namespace Win32 -Name API -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint="LoadCursorW")]
public static extern System.IntPtr LoadCursor(System.IntPtr h, int n);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern System.IntPtr CopyIcon(System.IntPtr h);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool SetSystemCursor(System.IntPtr h, uint id);
"@

$arrow = [Win32.API]::LoadCursor([System.IntPtr]::Zero, 32512)

$copy1 = [Win32.API]::CopyIcon($arrow)
$success1 = [Win32.API]::SetSystemCursor($copy1, 32650)

$copy2 = [Win32.API]::CopyIcon($arrow) 
$success2 = [Win32.API]::SetSystemCursor($copy2, 32514)

Write-Host "Loading cursors set to normal arrow. AppStarting: $success1, Wait: $success2"
