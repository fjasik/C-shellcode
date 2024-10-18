#pragma once

#include <windows.h>
#include <winternl.h>

#ifndef LDR_DATA_DEFINED
#define LDR_DATA_DEFINED

// Enhanced version of LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY1 {
	LIST_ENTRY  InLoadOrderLinks;
	LIST_ENTRY  InMemoryOrderLinks;
	LIST_ENTRY  InInitializationOrderLinks;
	void* DllBase;
	void* EntryPoint;
	ULONG   SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	SHORT   LoadCount;
	SHORT   TlsIndex;
	HANDLE  SectionHandle;
	ULONG   CheckSum;
	ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY1, * PLDR_DATA_TABLE_ENTRY1;

#endif

#ifndef TO_LOWERCASE_W

#define TO_LOWERCASE(out, c1) (out = (c1 >= 'A' && c1 <= 'Z') ? (c1 - 'A') + 'a' : c1)
#define TO_LOWERCASE_W(out, c1) (out = (c1 >= L'A' && c1 <= L'Z') ? (c1 - L'A') + L'a' : c1)

#endif

#ifndef bool

typedef int bool;
#define true 1
#define false 0

#endif

#define DefineImportedFuncPtrByName(hmodule, name) _ ## name name ## FuncPtr = GetFunctionByName(hmodule, name ## Name)

inline bool AreStringsEqual(const char* const str1, const char* const str2) {
	size_t i = 0;
	for (i = 0; str1[i] != '\0' && str2[i] != '\0'; i++) {
		if (str1[i] != str2[i]) {
			return false;
		}
	}

	// If we have looped through both strings and we have 
	// a null terminator in both strings, we have a match
	return (str1[i] == '\0' && str2[i] == '\0');
}

inline bool AreStringsEqualCaseInsensitive(const char* const str1, const char* const str2) {
	size_t i = 0;
	for (i = 0; str1[i] != '\0' && str2[i] != '\0'; i++) {
		char c1, c2;
		TO_LOWERCASE(c1, str1[i]);
		TO_LOWERCASE(c2, str2[i]);

		if (c1 != c2) {
			return false;
		}
	}

	// If we have looped through both strings and we have 
	// a null terminator in both strings, we have a match
	return (str1[i] == '\0' && str2[i] == '\0');
}

inline bool AreWStringsEqualCaseInsensitive(const wchar_t* const str1, const wchar_t* const str2) {
	size_t i = 0;
	for (i = 0; str1[i] != L'\0' && str2[i] != L'\0'; i++) {
		wchar_t c1, c2;
		TO_LOWERCASE_W(c1, str1[i]);
		TO_LOWERCASE_W(c2, str2[i]);

		if (c1 != c2) {
			return false;
		}
	}

	return (str1[i] == L'\0' && str2[i] == L'\0');
}

inline LPVOID GetModuleByName(WCHAR* searchedModuleName) {
	PPEB peb = NULL;

	// PEB pointer can be found in the TEB (Thread Environment Block)
	// TEB pointer is in the KPCR (Kernel Processor Control Region),
	// at its very beginning. A pointer to that is held in the
	// segment registers: FS for x86 and GS for x64.
	// We therefore simply need to read the correct register and 
	// take the correct offset: the offset of PEB inside of TEB
	// Not really sure how that works, 
	// can also use NtCurrentTeb()->ProcessEnvironmentBlock
#if defined(_M_X64) || defined(_M_AMD64)
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA loaderData = peb->Ldr;
	LIST_ENTRY moduleList = loaderData->InMemoryOrderModuleList;

	// Now loop through the module list and find the module with the matching name
	PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&moduleList));
	PLDR_DATA_TABLE_ENTRY currentModule = Flink;
	while (currentModule != NULL && currentModule->DllBase != NULL) {
		LDR_DATA_TABLE_ENTRY1* enhancedCurrentModule 
			= CONTAINING_RECORD(currentModule, LDR_DATA_TABLE_ENTRY1, InMemoryOrderLinks);
		if (enhancedCurrentModule->BaseDllName.Buffer == NULL) {
			currentModule = (PLDR_DATA_TABLE_ENTRY)enhancedCurrentModule->InMemoryOrderLinks.Flink;
			continue;
		}

		WCHAR* currentModuleName = enhancedCurrentModule->BaseDllName.Buffer;

		if (AreWStringsEqualCaseInsensitive(currentModuleName, searchedModuleName)) {
			return enhancedCurrentModule->DllBase;
		}

		// Not found, try next
		currentModule = (PLDR_DATA_TABLE_ENTRY)enhancedCurrentModule->InMemoryOrderLinks.Flink;
	}

	return NULL;
}

inline LPVOID GetFunctionByName(LPVOID module, char* functionName) {
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
	IMAGE_DATA_DIRECTORY* exportsDir = &(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (exportsDir->VirtualAddress == NULL) {
		return NULL;
	}

	DWORD expAddr = exportsDir->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
	SIZE_T namesCount = exp->NumberOfNames;
	DWORD funcsListRVA = exp->AddressOfFunctions;
	DWORD funcNamesListRVA = exp->AddressOfNames;
	DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

	// Go through names, again, manually comparing characters
	for (SIZE_T i = 0; i < namesCount; i++) {
		DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
		WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
		DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));
		LPSTR currentName = (LPSTR)(*nameRVA + (BYTE*)module);

		if (AreStringsEqual(functionName, currentName)) {
			// Found it
			return (BYTE*)module + (*funcRVA);
		}
	}

	return NULL;
}