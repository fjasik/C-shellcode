#pragma once

#include <Windows.h>

inline void* ReadFileIntoMemory(const char* filepath) {
	HANDLE hFile = CreateFileA(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return 0;
	}

	void* buffer = VirtualAlloc(NULL, fileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buffer == NULL) {
		CloseHandle(hFile);
		return 0;
	}

	DWORD bytesRead;
	if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	if (bytesRead != fileSize) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 0;
	}

	CloseHandle(hFile);
	return buffer;
}