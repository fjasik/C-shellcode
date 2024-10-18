#include "peb_lookup.h"
#include "debug.h"

#include <Windows.h>

typedef int(WINAPI *_MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

int main() {
	// kernel32.dll - lowercase hash
	void *kernel32Module = GetModuleByHash(0x7040ee75);
	if (!kernel32Module) {
		return 1;
	}

	// Initialise debug printing
	DebugInitialise(kernel32Module);

	// user32.dll - lowercase hash
	// user32.dll is not loaded into all processes
	void *user32Module = GetModuleByHash(0x5a6bd3f3);
	if (!user32Module) {
		return 2;
	}

	// Case sensitive hash
	DefineImportedFuncPtrByHash(user32Module, MessageBoxA, 0x384f14b4);
	if (!MessageBoxAFuncPtr) {
		return 3;
	}

	char title[] = {'T', 'e', 's', 't', ' ', 't', 'i', 't', 'l', 'e', '\0'};
	char message[] = {'M', 'e', 's', 's', 'a', 'g', 'e', '\0'};

	int result = MessageBoxAFuncPtr(NULL, message, title, MB_OK | MB_ICONINFORMATION);

	DebugWriteChars('L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', '\n');
	DebugWriteIntAndFlush(result);
	DebugWriteChars('D', 'o', 'n', 'e', '\n');

	return 0;
}