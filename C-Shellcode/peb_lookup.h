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

#define DefineImportedFuncPtrByHash(hmodule, name, hash) \
	_ ## name name ## FuncPtr = GetFunctionByHash(hmodule, hash)

unsigned char ConvertToLower(unsigned char ch) {
	return (ch >= 'A' && ch <= 'Z') ? (ch + ('a' - 'A')) : ch;
}

// The param size is used here for hashing of wchar_t buffers: since we're hashing
// module names, and Windows is little endian (least significant byte goes first),
// every second byte will be zero, so we skip it, to make the hash uniform with
// the hash of a non wide string
// Finally, we want the hash to be case insensitive, for different capialization
// of dll names in the import table
inline DWORD HashBufferLowercase(unsigned char* buffer, size_t length, size_t size) {
	DWORD hash = 5381;

	for (size_t i = 0; i < length; i += size) {
		hash = ((hash << 5) + hash) + ConvertToLower(buffer[i]);
	}

	return hash;
}

// This can so easily seg fault
// Btw, we don't use ConvertToLower here because we need the function names
// to be case sensitive, as they are defined in the dll exports
inline DWORD HashUntilNull(unsigned char* buffer, size_t size) {
	DWORD hash = 5381;

	for (; *buffer != 0; buffer += size) {
		hash = ((hash << 5) + hash) + *buffer;
	}

	return hash;
}

inline LPVOID GetModuleByHash(DWORD hash) {
	PPEB peb = NULL;

	// PEB pointer can be found in the TEB (Thread Environment Block)
	// TEB pointer is in the KPCR (Kernel Processor Control Region),
	// at its very beginning. A pointer to that is held in the
	// segment registers: FS for x86 and GS for x64.
	// We therefore simply need to read the correct register and 
	// take the correct offset: the offset of PEB inside of TEB
	// Not really sure how that works, 
	// can also use NtCurrentTeb()->ProcessEnvironmentBlock
#ifdef _WIN64
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
			currentModule 
				= (PLDR_DATA_TABLE_ENTRY)enhancedCurrentModule->InMemoryOrderLinks.Flink;
			continue;
		}

		DWORD currentModuleNameHash = HashBufferLowercase(
			(unsigned char*)(enhancedCurrentModule->BaseDllName.Buffer),
			enhancedCurrentModule->BaseDllName.Length,
			sizeof(wchar_t));

		if (currentModuleNameHash == hash) {
			return enhancedCurrentModule->DllBase;
		}

		// Not found, try next
		currentModule 
			= (PLDR_DATA_TABLE_ENTRY)enhancedCurrentModule->InMemoryOrderLinks.Flink;
	}

	return NULL;
}

inline LPVOID GetFunctionByHash(LPVOID module, DWORD functionHash) {
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
	IMAGE_DATA_DIRECTORY* exportsDir 
		= &(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (exportsDir->VirtualAddress == NULL) {
		return NULL;
	}

	DWORD expAddr = exportsDir->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
	SIZE_T namesCount = exp->NumberOfNames;
	DWORD funcsListRVA = exp->AddressOfFunctions;
	DWORD funcNamesListRVA = exp->AddressOfNames;
	DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

	// Loop through all exported function names and try to find the matching hash
	for (SIZE_T i = 0; i < namesCount; i++) {
		DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
		WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
		DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));
		LPSTR currentName = (LPSTR)(*nameRVA + (BYTE*)module);

		DWORD currentNameHash = HashUntilNull(
			(unsigned char*)currentName,
			sizeof(char));

		if (currentNameHash == functionHash) {
			return (BYTE*)module + (*funcRVA);
		}
	}

	return NULL;
}