#include <WinSock2.h>
#include <Windows.h>

#include <iostream>
#include <vector>

#include <intrin.h>

#define REPORT_AND_RETURN_LAST_ERROR(message) \
    std::cout << message << ": " << GetLastError() << std::endl; \
    return GetLastError()

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Path to shellcode binary file required "
            "as command line parameter" << std::endl;
        return 1;
    }
    
#pragma comment(lib, "ws2_32.lib")
    LoadLibraryA("ws2_32.dll");

#pragma comment(lib, "user32.lib")
    LoadLibraryA("user32.dll");

    std::string shellcodePath = argv[1];

    const auto shellcodeFileHandle = CreateFileA(
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

    // This is a pseudo handle and doesn't need to be closed
    const auto processHandle = GetCurrentProcess();
    if (!processHandle) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to open self process");
    }

    std::cout << "Self process handle opened" << std::endl;

    const auto remoteBuffer = VirtualAlloc(
        NULL, 
        shellcodeBuffer.size(), 
        (MEM_RESERVE | MEM_COMMIT), 
        PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to allocate memory");
    }

    std::cout << "Memory allocated for shellcode at address: 0x" 
        << std::hex << remoteBuffer << std::endl;
    std::cout << "Size of allocation: " 
        << std::dec << shellcodeBuffer.size() << " B" << std::endl;

    success = WriteProcessMemory(
        processHandle, 
        remoteBuffer, 
        shellcodeBuffer.data(), 
        shellcodeBuffer.size(), 
        NULL);
    if (!success) {
        REPORT_AND_RETURN_LAST_ERROR("Failed to write memory");
    }

    std::cout << "Shellcode written to process memory" << std::endl;
    std::cout << "Executing..." << std::endl;

    const auto shellcodeFunctionPtr = (int(*)())remoteBuffer;
    const auto result = shellcodeFunctionPtr();

    std::cout << "Shellcode executed" << std::endl;

    std::cout << "Shellcode exit code: 0x" << std::hex << result << std::endl;

    Sleep(1000);

    std::cout << "Done" << std::endl;

    return result;
}