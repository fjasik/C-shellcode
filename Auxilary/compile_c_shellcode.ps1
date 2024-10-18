param(
    [Parameter(Mandatory = $true)]
    [string]$InputFilepath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Win32", "x64")]
    [string]$Architecture,

    [switch]$DebugPrint,
    [switch]$Optimize,
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $InputFilePath)) {
    throw "Error: The provided path does not exist"
}
if ((Get-Item $InputFilePath).PSIsContainer -eq $true) {
    throw "Error: Path is a directory"
}

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

$inputFileName = [System.IO.Path]::GetFileNameWithoutExtension($InputFilePath)
$repoRootDirectory = Resolve-Path -Path "$PSScriptRoot\.."

$compiledShellcodeDirectory = "$repoRootDirectory\out\shellcode\bin"
$compiledExeDirectory = "$repoRootDirectory\out\shellcode\exe"
$tempDirectory = "$repoRootDirectory\out\shellcode\temp\$inputFileName"

New-Item -ItemType Directory -Force -Path $compiledShellcodeDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $compiledExeDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $tempDirectory | Out-Null

Write-Host "Compiling shellcode based on $InputFilepath" -ForegroundColor Green
Write-Host "Chosen architecture: $Architecture" -ForegroundColor Yellow

$filenameSuffix = ""
$clArgumentArray = @()

if ($DebugPrint.IsPresent) {
    Write-Host "Assembling shellcode with debug printing on" -ForegroundColor Yellow

    $filenameSuffix += "_dbg"
    $clArgumentArray += "/DDEBUG_PRINT=1"
}
else {
    Write-Host "Assembling shellcode without debug printing" -ForegroundColor Yellow
}

if ($Optimize.IsPresent) {
    Write-Host "Compiler optimizations enabled (O1 - optimizing for size)" -ForegroundColor Yellow

    $filenameSuffix += "_opt"
    $clArgumentArray += @("/O1", "/DOPTIMIZE=1")
}
else {
    Write-Host "Compiler optimizations disabled" -ForegroundColor Yellow
}

if ($Optimize.IsPresent -and $DebugPrint.IsPresent) {
    Write-Host "WARNING:" -ForegroundColor Yellow
    Write-Host "Optimization and debug printing don't work well together" -ForegroundColor Yellow
}

if ($Architecture -eq "x64") {
    $filenameSuffix += "_x64"
    $exeEntryName = "preMainAlign"    
    $asmAmendPythonScriptName = "amend_asm_x64.py"

    $clArgumentArray += @("/DWIN64=1", "/D_WIN64=1", "/D_HAS_EXCEPTIONS=0", "/GR-", "/favor:AMD64", "/Zl", "/EHs-c-")
}
else {
    $filenameSuffix += "_x86"
    $exeEntryName = "main"
    $asmAmendPythonScriptName = "amend_asm_x86.py"
}

$outputAsmFilepath = "$tempDirectory\${inputFileName}${filenameSuffix}.asm"
$outputObjectFilepath = "$tempDirectory\${inputFileName}${filenameSuffix}.obj"

Write-Host
Write-Host "Compiling C code down to assembly..." -ForegroundColor Yellow

if ($Interactive.IsPresent) {
    Wait-UserInputOverwriteMessage
}

$clArgumentArray += @("/c", "/GS-", "/Fo${outputObjectFilepath}", "/FAs", "/Fa${outputAsmFilepath}", $InputFilePath)

cl @clArgumentArray
if ($LastExitCode -ne 0) {
    Write-Host "cl.exe failed, see above for error" -ForegroundColor Red
    exit 1
}

Write-Host "Assembly listing generated" -ForegroundColor Green
Write-Host
Write-Host "Amending the assembly..." -ForegroundColor Yellow

$asmAmendPythonScriptPath = "$repoRootDirectory\Auxilary\$asmAmendPythonScriptName"
$outputAmendedAsmFilepath = "$tempDirectory\${inputFileName}${filenameSuffix}_amend.asm"

if ($Interactive.IsPresent) {
    Wait-UserInputOverwriteMessage
}

python "$asmAmendPythonScriptPath" "$outputAsmFilepath" "$outputAmendedAsmFilepath"
if ($LastExitCode -ne 0) {
    Write-Host "Could not ammend the assembly generated" -ForegroundColor Red
    exit 2
}

Write-Host "Assembly amended" -ForegroundColor Green
Write-Host
Write-Host "Assembling..." -ForegroundColor Yellow

if ($Interactive.IsPresent) {
    Wait-UserInputOverwriteMessage
}

if ($Architecture -eq "x64") { 
    ml64 /c /Fo"$outputObjectFilepath" "$outputAmendedAsmFilepath"
}
else {
    ml /c /Fo"$outputObjectFilepath" "$outputAmendedAsmFilepath"
}

if ($LastExitCode -ne 0) {
    Write-Host "ml.exe or ml64.exe failed, see above for error" -ForegroundColor Red
    exit 3
}

Write-Host "Object file generated" -ForegroundColor Green
Write-Host
Write-Host "Linking the executable..." -ForegroundColor Yellow

$executableFilepath = "$compiledExeDirectory\${inputFileName}${filenameSuffix}.exe"

if ($Interactive.IsPresent) {
    Wait-UserInputOverwriteMessage
}

link "$outputObjectFilepath" /entry:$exeEntryName /NODEFAULTLIB:LIBCMT /NODEFAULTLIB:OLDNAMES /OUT:"$executableFilepath"

if ($LastExitCode -ne 0) {
    Write-Host "link.exe failed, see above for error" -ForegroundColor Red
    exit 4
}

Write-Host "Executable compiled and linked, location:" -ForegroundColor Green
Write-Host $executableFilepath -ForegroundColor Green
Write-Host
Write-Host "Extrtacting the shellcode..." -ForegroundColor Yellow

$shellcodeFilepath = "$compiledShellcodeDirectory\${inputFileName}${filenameSuffix}.bin"

if ($Interactive.IsPresent) {
    Wait-UserInputOverwriteMessage
}

python "$PSScriptRoot\extract_text_section.py" "$executableFilepath" --output $shellcodeFilepath
if ($LastExitCode -ne 0) {
    Write-Host "Could not extract the .text section" -ForegroundColor Red
    exit 5
}

Write-Host
Write-Host "Shellcode generated successfully, location:" -ForegroundColor Green
Write-Host $shellcodeFilepath -ForegroundColor Green
Write-Host
Write-Host "Finished" -ForegroundColor Green

exit 0