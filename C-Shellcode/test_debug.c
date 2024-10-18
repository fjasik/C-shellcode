#include "peb_lookup_string.h"
#include "debug.h"

int main() {
	wchar_t kernel32ModuleName[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
	void* kernel32Module = GetModuleByName(kernel32ModuleName);
	if (!kernel32Module) {
		return 1;
	}

	DebugInitialise(kernel32Module);
	DebugWriteChars('o', 'k', '\n');

	return 0;
}