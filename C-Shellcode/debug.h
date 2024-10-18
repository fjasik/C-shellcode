#pragma once

// Use this macro to toggle debug printing on and off
//#define DEBUG_PRINT

#ifdef DEBUG_PRINT

#include "peb_lookup_string.h"

#define JOIN_TOKEN2(t1, t2) t1 ## t2
#define JOIN_TOKEN(t1, t2) JOIN_TOKEN2(t1, t2)

#define DebugInitialise(kernel32ModuleHandle) DebugResources _debug = _InitDebug(kernel32ModuleHandle)

// Declares a stack-based null terminated char array and prints it to debug's std output
#define DebugWriteChars(...) \
	do { \
		const char JOIN_TOKEN(message, __LINE__)[] = { __VA_ARGS__, '\0' }; \
		_debug.writeFileFuncPtr( \
			_debug.stdHandle, \
			JOIN_TOKEN(message, __LINE__), \
			sizeof(JOIN_TOKEN(message, __LINE__)), \
			&_debug.bytesWritten, NULL); \
	} while(0)

// Declares a stack-based null terminated char array, prints it to debug's std output 
// and then flushes the std output buffer
#define DebugWriteCharsAndFlush(...) \
	do { \
		const char JOIN_TOKEN(message, __LINE__)[] = { __VA_ARGS__, '\0' }; \
		_debug.writeFileFuncPtr( \
			_debug.stdHandle, \
			JOIN_TOKEN(message, __LINE__), \
			sizeof(JOIN_TOKEN(message, __LINE__)), \
			&_debug.bytesWritten, NULL); \
		_debug.flushFileBuffersFuncPtr(_debug.stdHandle); \
	} while(0)

// Creates a stack-based char array buffer that holds the decimal representation of 
// the number (DWORD) and prints it to debug's std output, appends a new line
#define DebugWriteIntAndFlush(number) _DebugWriteIntAndFlush(&_debug, number)

#define DebugWriteLastError() \
	do { \
		const DWORD lastError = _debug.getLastErrorFuncPtr(); \
		const char JOIN_TOKEN(message, __LINE__)[] = { 'E', 'r', 'r', '\n', '\0' }; \
		_debug.writeFileFuncPtr( \
			_debug.stdHandle, \
			JOIN_TOKEN(message, __LINE__), \
			sizeof(JOIN_TOKEN(message, __LINE__)), \
			&_debug.bytesWritten, NULL); \
		DebugWriteIntAndFlush(lastError); \
	} while(0)

typedef HANDLE(WINAPI* _GetStdHandle)(
	_In_ DWORD nStdHandle
);

typedef BOOL(WINAPI* _WriteFile)(
	_In_ HANDLE hFile,
	_In_ LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* _FlushFileBuffers)(
	_In_ HANDLE hFile
);

typedef DWORD(WINAPI* _GetLastError)();

typedef struct {
	DWORD bytesWritten;
	HANDLE stdHandle;
	_WriteFile writeFileFuncPtr;
	_FlushFileBuffers flushFileBuffersFuncPtr;
	_GetLastError getLastErrorFuncPtr;
} DebugResources;

DebugResources _InitDebug(HANDLE kernel32ModuleHandle) {
	char GetStdHandleName[] = { 'G', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', '\0' };
	char WriteFileName[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0' };
	char FlushFileBuffersName[] = { 'F', 'l', 'u', 's', 'h', 'F', 'i', 'l', 'e', 'B', 'u', 'f', 'f', 'e', 'r', 's', '\0' };
	char GetLastErrorName[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r','r', 'o', 'r', '\0'};

	_GetStdHandle GetStdHandleFuncPtr 
		= (_GetStdHandle)GetFunctionByName(kernel32ModuleHandle, GetStdHandleName);

	DebugResources _debug;

	_debug.stdHandle = GetStdHandleFuncPtr(STD_OUTPUT_HANDLE);
	_debug.writeFileFuncPtr 
		= (_WriteFile)GetFunctionByName(kernel32ModuleHandle, WriteFileName);
	_debug.flushFileBuffersFuncPtr
		= (_FlushFileBuffers)GetFunctionByName(kernel32ModuleHandle, FlushFileBuffersName);
	_debug.getLastErrorFuncPtr
		= (_GetLastError)GetFunctionByName(kernel32ModuleHandle, GetLastErrorName);

	DebugWriteCharsAndFlush('d', 'e', 'b', 'u', 'g', '\n');

	return _debug;
}

void _DebugWriteIntAndFlush(DebugResources* debug, unsigned long number) {
	char buffer[] = { '0', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '\n', 0 };
	int temp = number;
	int digitCount = 0;

	// Count the number of digits in the number
	while (temp != 0) {
		temp /= 10;
		digitCount++;
	}

	temp = number;

	// Convert each digit into a character and store it in the array
	for (int i = digitCount - 1; i >= 0; i--) {
		buffer[i] = (temp % 10) + '0';
		temp /= 10;
	}

	debug->writeFileFuncPtr(debug->stdHandle, buffer, sizeof(buffer), &debug->bytesWritten, NULL);
	debug->flushFileBuffersFuncPtr(debug->stdHandle);
}

#else

#define DebugInitialise(...) void* _debug = 0
#define DebugWriteChars(...)
#define DebugWriteCharsAndFlush(...)
#define DebugWriteIntAndFlush(...) 
#define DebugWriteLastError(...) 

#endif