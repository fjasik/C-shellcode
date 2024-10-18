#include "peb_lookup.h"
#include "debug.h"

//#include "test.h"

#include <intrin.h>
#include <Windows.h>

typedef HMODULE(WINAPI* _LoadLibraryA)(
	_In_ LPCSTR lpLibFileName);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect);

typedef BOOL(WINAPI* _VirtualFree)(
	_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType);

typedef BOOL(WINAPI* _VirtualProtect)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect);

typedef INT(WINAPI* _GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* DLLEntry)(
	HINSTANCE hinstDLL, 
	DWORD fdwReason, 
	LPVOID lpvReserved);

// This can be optimised by using bitshift magic
inline DWORD GetMemoryPermissionFlag(BOOL isReadable, BOOL isWritable, BOOL isExecutable) {
	if (isReadable) {
		if (isWritable) {
			if (isExecutable) {
				return PAGE_EXECUTE_READWRITE;
			}
			return PAGE_READWRITE;
		}
		if (isExecutable) {
			return PAGE_EXECUTE_READ;
		}
		return PAGE_READONLY;
	}
	if (isWritable) {
		if (isExecutable) {
			return PAGE_EXECUTE_WRITECOPY;
		}
		return PAGE_WRITECOPY;
	}
	if (isExecutable) {
		return PAGE_EXECUTE;
	}
	return PAGE_NOACCESS;
}

// We have to wrap the _ReturnAddress call in another function,
// as _ReturnAddress gives the address where we will go upon returning from the current function
// Don't we want to force NON inline this ?
__declspec(noinline) void* CurrentAddress() {
	return _ReturnAddress();
}

// We have no access to memcpy, CopyMemory or even RtlCopyMemory, 
// so we need to reimplement our own. Do note that this function 
// performs exactly 0 (zero) checks
// We have to mark this function as without optimizations, 
// because the compiler will automatically replace this with a call to memcpy
//#pragma optimize("", off)
//inline void CustomMemCopy(unsigned char* restrict destination, const unsigned char* restrict source, SIZE_T size) {
//	for (SIZE_T i = 0; i < size; i++) {
//		destination[i] = source[i];
//	}
//}
//#pragma optimize("", on)

// Some ChatGPT magic
inline void optimized_memcpy(void* dest, const void* src, size_t n) {
	unsigned char* d = (unsigned char*)dest;
	const unsigned char* s = (const unsigned char*)src;

	// Copy bytes until the destination is aligned to 16 bytes
	while (((uintptr_t)d & 15) && n) {
		*d++ = *s++;
		n--;
	}

	// Use SSE2 intrinsics to copy 16 bytes at a time
	__m128i* d128 = (__m128i*)d;
	const __m128i* s128 = (const __m128i*)s;
	while (n >= 16) {
		_mm_store_si128(d128++, _mm_loadu_si128(s128++));
		n -= 16;
	}

	// Copy any remaining bytes
	d = (unsigned char*)d128;
	s = (const unsigned char*)s128;
	while (n--) {
		*d++ = *s++;
	}
}

#define BYTE_OFFSET_AS(type, ptr, count) (type)((BYTE*)(ptr) + (count))

int main() {
	// Get the concatenated dll pointer by adding an offset to the current instruction pointer value
	const void* currentAddressPointer = CurrentAddress();

	// If O1 optimizations are ON,
	// DLL offset should be: sizeof(this entire shellcode) - 0xA
	// If O1 optimizations are OFF,
	// DLL offset should be: sizeof(this entire shellcode) - 0xE
	// (0xE comes from the instructions until setting the currentAddressPointer, in debug)
	// When .text section size is 4096 B: kDllOffset should be 0xff2
	//							  3584 B:					   0xdf2
	//							  3072 B:					   0xbf2
	// And so on...

	// For x64 need to take into account the injected stack aligning assembly,
	// which is 0x16 (22) bytes long
#ifdef WIN64
	#ifdef OPTIMIZE
		const unsigned int currentInstructionPointerOffset = 0x0;
	#else
		const unsigned int currentInstructionPointerOffset = 0x24;
	#endif
#else
	#ifdef OPTIMIZE
		const unsigned int currentInstructionPointerOffset = 0xa;
	#else
		const unsigned int currentInstructionPointerOffset = 0xe;
	#endif
#endif

#ifdef WIN64
	#ifdef OPTIMIZE
		const unsigned int kShellcodeLength = 0x0;
	#else
		#ifdef DEBUG_PRINT
			const unsigned int kShellcodeLength = 0x1800;
		#else
			const unsigned int kShellcodeLength = 0x0;
		#endif
	#endif
	
#else
	#ifdef OPTIMIZE
		const unsigned int kShellcodeLength = 0x600;
	#else
		#ifdef DEBUG_PRINT
			const unsigned int kShellcodeLength = 0x1200;
		#else
			const unsigned int kShellcodeLength = 0xa00;
		#endif
	#endif
#endif

	const unsigned int kDllOffset = kShellcodeLength - currentInstructionPointerOffset;
	const void* concatDllBytesPtr
		= BYTE_OFFSET_AS(const void*, currentAddressPointer, kDllOffset);
	//const void* concatenatedDllBytesPtr 
	//	= ReadFileIntoMemory("C:\\Users\\frane\\Documents\\code\\Reflective\\out\\bin\\x64\\Release\\DummyDLL.dll");

	// kernel32.dll
	void* module = GetModuleByHash(0x7040ee75);
	if (!module) {
		return 1;
	}

	DebugInitialise(module);

	DefineImportedFuncPtrByHash(module, LoadLibraryA, 0x5fbff0fb);
	DefineImportedFuncPtrByHash(module, VirtualAlloc, 0x382c0f97);
	DefineImportedFuncPtrByHash(module, VirtualFree, 0x668fcf2e);
	DefineImportedFuncPtrByHash(module, VirtualProtect, 0x844ff18d);
	//DefineImportedFuncPtrByHash(module, GetCurrentProcess, 0xca8d7527);
	//DefineImportedFuncPtrByHash(module, ReadProcessMemory, 0xb8932459);
	DefineImportedFuncPtrByHash(module, GetProcAddress, 0xcf31bb1f);

	// Get pointers to in-memory DLL headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(concatDllBytesPtr);
	PIMAGE_NT_HEADERS pNtHeader 
		= BYTE_OFFSET_AS(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
	const DWORD dllImageSize = pNtHeader->OptionalHeader.SizeOfImage;

	// This should print MZ
	DebugWriteChars(
		((char*)&pDosHeader->e_magic)[0], 
		((char*)&pDosHeader->e_magic)[1], 
		'\n');

	if (pDosHeader->e_magic != 0x5A4D) {
		DebugWriteCharsAndFlush('m', 'i', 's', 'a', 'l', 'i', 'g', 'n', '\n');
		return 2;
	}

	DWORD_PTR dllBasePointer = VirtualAllocFuncPtr(
		(LPVOID)pNtHeader->OptionalHeader.ImageBase,
		dllImageSize, 
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_READWRITE);

	if (!dllBasePointer) {
		// Failed to allocate memory at DLL's preferred address
		// Try somewhere else
		dllBasePointer = (DWORD_PTR)VirtualAllocFuncPtr(NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!dllBasePointer) {
			return 3;
		}
	}

	DebugWriteCharsAndFlush('m', 'e', 'm', 'c', 'o', 'p', 'y', '\n');

	// Difference between the prefered address, and where the space was actually allocated for the dll
	const DWORD_PTR deltaImageBase = dllBasePointer - (DWORD_PTR)pNtHeader->OptionalHeader.ImageBase;

	// Copy over DLL image headers to the newly allocated space
	optimized_memcpy(
		dllBasePointer, 
		concatDllBytesPtr, 
		pNtHeader->OptionalHeader.SizeOfHeaders);

	// Copy over DLL image sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);
	for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, section++) {
		void* pSectionDestination 
			= BYTE_OFFSET_AS(void*, dllBasePointer, section->VirtualAddress);
		void* pSectionBytes
			= BYTE_OFFSET_AS(void*, concatDllBytesPtr, section->PointerToRawData);

		optimized_memcpy(
			pSectionDestination, 
			pSectionBytes, 
			section->SizeOfRawData);
	}

	DebugWriteCharsAndFlush('b', 'a', 's', 'e', 'r', 'e', 'l', 'o', 'c', '\n');

	// Perform image base relocations, i.e. dark magic
	PIMAGE_DATA_DIRECTORY relocations 
		= &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const PBASE_RELOCATION_BLOCK relocationBlockArray 
		= BYTE_OFFSET_AS(PBASE_RELOCATION_BLOCK, dllBasePointer, relocations->VirtualAddress);

	DWORD processedRelocationsSize = 0;

	//HANDLE hProcess = GetCurrentProcessFuncPtr();

	while (processedRelocationsSize < relocations->Size) {
		PBASE_RELOCATION_BLOCK relocationBlock 
			= BYTE_OFFSET_AS(PBASE_RELOCATION_BLOCK, relocationBlockArray, processedRelocationsSize);
		processedRelocationsSize += sizeof(BASE_RELOCATION_BLOCK);

		DWORD relocationsCount 
			= (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries
			= BYTE_OFFSET_AS(PBASE_RELOCATION_ENTRY, relocationBlockArray, processedRelocationsSize);

		for (DWORD i = 0; i < relocationsCount; i++) {
			processedRelocationsSize += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0) {
				continue;
			}

			DWORD_PTR relocationRVA 
				= BYTE_OFFSET_AS(DWORD_PTR, relocationBlock->PageAddress, relocationEntries[i].Offset);

			// Isn't it just this?
			// I'm cooking here
			if (relocationEntries[i].Type == IMAGE_REL_BASED_DIR64 || relocationEntries[i].Type == IMAGE_REL_BASED_HIGHLOW) {
				*(DWORD_PTR*)(dllBasePointer + relocationRVA) += deltaImageBase;
			}
			else if (relocationEntries[i].Type == IMAGE_REL_BASED_HIGH) {
				*(DWORD_PTR*)(dllBasePointer + relocationRVA) += HIWORD(deltaImageBase);
			}
			else if (relocationEntries[i].Type == IMAGE_REL_BASED_LOW) {
				*(DWORD_PTR*)(dllBasePointer + relocationRVA) += LOWORD(deltaImageBase);
			}
		}
	}

	DebugWriteCharsAndFlush('r', 'e', 's', 'o', 'l', 'v', 'e', 'I', 'A', 'T', '\n');

	// Resolve import address table, i.e. more dark magic
	PIMAGE_DATA_DIRECTORY importDirectory 
		= &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor 
		= BYTE_OFFSET_AS(PIMAGE_IMPORT_DESCRIPTOR, importDirectory->VirtualAddress, dllBasePointer);

	LPCSTR libraryName = NULL;
	HMODULE hLibrary = NULL;

	while (importDescriptor->Name != NULL) {
		libraryName = BYTE_OFFSET_AS(LPCSTR, dllBasePointer, importDescriptor->Name);
		hLibrary = LoadLibraryAFuncPtr(libraryName);

		if (hLibrary) {
			PIMAGE_THUNK_DATA thunk
				= BYTE_OFFSET_AS(PIMAGE_THUNK_DATA, dllBasePointer, importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL) {
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
					LPCSTR functionOrdinal = (LPCSTR)(IMAGE_ORDINAL(thunk->u1.Ordinal));
					thunk->u1.Function = (DWORD_PTR)(GetProcAddressFuncPtr(hLibrary, functionOrdinal));
				}
				else {
					const PIMAGE_IMPORT_BY_NAME functionName 
						= BYTE_OFFSET_AS(PIMAGE_IMPORT_BY_NAME, dllBasePointer, thunk->u1.AddressOfData);
					const DWORD_PTR functionAddress 
						= (DWORD_PTR)(GetProcAddressFuncPtr(hLibrary, functionName->Name));
					thunk->u1.Function = functionAddress;
				}

				thunk++;
			}
		}

		importDescriptor++;
	}

	// Ignore export table
	// Ignore TLS callbacks

	DebugWriteCharsAndFlush('s', 'e', 'c', 't', 'i', 'o', 'n', 's', '\n');
	
	// Finalize the sections
	// Change the protection on the sections to what they require (avoids RWX memory)
	pDosHeader = (PIMAGE_DOS_HEADER)(dllBasePointer);
	pNtHeader = BYTE_OFFSET_AS(PIMAGE_NT_HEADERS, dllBasePointer, pDosHeader->e_lfanew);
	section = IMAGE_FIRST_SECTION(pNtHeader);

	for (size_t i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, section++) {
		LPVOID pSectionDestination 
			= BYTE_OFFSET_AS(LPVOID, dllBasePointer, section->VirtualAddress);

		if (section->SizeOfRawData == 0) {
			continue;
		}

		if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0) {
			// Not sure about this
			VirtualFreeFuncPtr(pSectionDestination, section->SizeOfRawData, MEM_DECOMMIT);
			continue;
		}

		DWORD protection = GetMemoryPermissionFlag(
			(section->Characteristics & IMAGE_SCN_MEM_READ) != 0,
			(section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0,
			(section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);

		const BOOL isCached = (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0;
		if (isCached) {
			protection |= PAGE_NOCACHE;
		}

		DWORD oldProtection = NULL;
		VirtualProtectFuncPtr(pSectionDestination, section->SizeOfRawData, protection, &oldProtection);
	}

	DebugWriteCharsAndFlush('d', 'l', 'l', 'm', 'a', 'i', 'n', '\n');

	// Finally, call the dll's entry point, if there is one
	if (pNtHeader->OptionalHeader.AddressOfEntryPoint) {
		const DLLEntry dllEntry 
			= BYTE_OFFSET_AS(DLLEntry, dllBasePointer, pNtHeader->OptionalHeader.AddressOfEntryPoint);

		// DllMain will return TRUE (so numerical 1) on success, not 0
		if ((*dllEntry)((HINSTANCE)dllBasePointer, DLL_PROCESS_ATTACH, 0) != TRUE) {
			return 4;
		}
	}

	return 0;
}