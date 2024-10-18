#include "peb_lookup_string.h"
#include "debug.h"

#include <Windows.h>

typedef int (WINAPI* _MessageBoxA)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCSTR lpText,
	_In_opt_ LPCSTR lpCaption,
	_In_ UINT uType);

int main() {
	// kernel32.dll
	wchar_t kernel32ModuleName[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	void* kernel32Module = GetModuleByName(kernel32ModuleName);
	if (!kernel32Module) {
		return 1;
	}

	// Initialise debug printing
	DebugInitialise(kernel32Module);

	// user32.dll is not loaded into all processes
	wchar_t user32ModuleName[] = { L'u', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0'};
	void* user32Module = GetModuleByName(user32ModuleName);
	if (!user32Module) {
		return 2;
	}

	char MessageBoxAName[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0' };
	DefineImportedFuncPtrByName(user32Module, MessageBoxA);
	if (!MessageBoxAFuncPtr) {
		return 3;
	}

	char title[] = { 'T', 'e', 's', 't', ' ', 't', 'i', 't', 'l', 'e', '\0' };
	char message[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', '\0' };

	int result = MessageBoxAFuncPtr(NULL, message, title, MB_OK | MB_ICONINFORMATION);

	DebugWriteChars('L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', '\n');
	DebugWriteIntAndFlush(result);
	DebugWriteChars('D', 'o', 'n', 'e', '\n');

	return 0;
}