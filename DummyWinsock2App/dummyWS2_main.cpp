#include <WinSock2.h>
#include <Windows.h>

#include <iostream>

#pragma comment(lib, "ws2_32.lib")

SOCKET OpenSocket() {
    WSADATA wsaData = { 0 };

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "WSAStartup failed" << std::endl;
        return INVALID_SOCKET;
    }

    // Create a socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cout << "Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();

        return INVALID_SOCKET;
    }

    return sock;
}

int main() {
    SOCKET mySocket = OpenSocket();

    if (mySocket == INVALID_SOCKET) {
        std::cout << "Failed to create socket" << std::endl;
        return 1;
    }

    std::cout << "Socket created successfully" << std::endl;

    DWORD currentProcessId = GetCurrentProcessId();
    std::cout << "Current Process ID: " << currentProcessId << std::endl;

    std::cout << "Looping forever..." << std::endl;

    bool debuggerDetected = false;
    while (1) {
        if (IsDebuggerPresent() && !debuggerDetected) {
            debuggerDetected = true;
            std::cout << "Debugger detected!" << std::endl;
        }
        Sleep(1000);
    }

    closesocket(mySocket);
    WSACleanup();

    return 0;
}