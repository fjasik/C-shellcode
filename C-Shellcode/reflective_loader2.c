// Deeply inspired by:
// https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c

#pragma once

//#include "test.h"

#include "peb_lookup.h"
#include "debug.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

typedef BOOL(WINAPI* DLLEntry)(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved);

typedef HMODULE(WINAPI* _LoadLibraryA)(
	_In_ LPCSTR lpLibFileName);

typedef LPVOID(WINAPI* _VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect);

typedef INT(WINAPI* _GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName);

typedef DWORD(NTAPI* _NtFlushInstructionCache)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ ULONG NumberOfBytesToFlush);

typedef struct _UNICODE_STR {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

#define IMAGE_REL_BASED_ARM_MOV32A		5
#define IMAGE_REL_BASED_ARM_MOV32T		7

#define ARM_MOV_MASK					(DWORD)(0xFBF08000)
#define ARM_MOV_MASK2					(DWORD)(0xFBF08F00)
#define ARM_MOVW						0xF2400000
#define ARM_MOVT						0xF2C00000

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

#pragma intrinsic(_ReturnAddress)

// We have to wrap the _ReturnAddress call in another function,
// as _ReturnAddress gives the address where we will go upon returning from the current function
// This function can not be inlined by the compiler or we will not get the address we expect
__declspec(noinline) void* CurrentAddress() {
	return _ReturnAddress();
}

//// Some ChatGPT magic
//void* optimized_memcpy(void* dest, const void* src, size_t n) {
//	unsigned char* d = (unsigned char*)dest;
//	const unsigned char* s = (const unsigned char*)src;
//
//	// Copy bytes until the destination is aligned to 16 bytes
//	while (((uintptr_t)d & 15) && n) {
//		*d++ = *s++;
//		n--;
//	}
//
//	// Use SSE2 intrinsics to copy 16 bytes at a time
//	__m128i* d128 = (__m128i*)d;
//	const __m128i* s128 = (const __m128i*)s;
//	while (n >= 16) {
//		_mm_store_si128(d128++, _mm_loadu_si128(s128++));
//		n -= 16;
//	}
//
//	// Copy any remaining bytes
//	d = (unsigned char*)d128;
//	s = (const unsigned char*)s128;
//	while (n--) {
//		*d++ = *s++;
//	}
//
//	return dest;
//}

#pragma optimize("", off)
inline void CustomMemCopy(unsigned char* restrict destination, const unsigned char* restrict source, SIZE_T size) {
	for (SIZE_T i = 0; i < size; i++) {
		destination[i] = source[i];
	}
}
#pragma optimize("", on)

//// We have to mark this function as without optimizations, 
//// because the compiler will automatically replace this with a call to memcpy
//#pragma optimize("", off)
//inline void MemCopy(void* source, void* destination, DWORD size) {
//	// Implement later if needed
//}
//#pragma optimize("", on)

// This is our position independent reflective DLL loader/injector
int main() {
	// Get the concatenated dll pointer by adding an offset to the current instruction pointer value
	const void* currentAddressPointer = CurrentAddress();

	const unsigned int kShellcodeLength = 0x1600;
	const unsigned int currentInstructionPointerOffset = 0x24;

	const unsigned int kDllOffset = kShellcodeLength - currentInstructionPointerOffset;
	const DWORD_PTR* concatenatedDllBytesPtr = (DWORD_PTR)currentAddressPointer + kDllOffset;

	//const DWORD_PTR concatenatedDllBytesPtr
	//	= ReadFileIntoMemory("C:\\Users\\frane\\Documents\\code\\Reflective\\out\\bin\\x64\\Debug\\DummyDLL.dll");


	// kernel32.dll - lowercase hash
	void* kernel32Module = GetModuleByHash(0x7040ee75);
	if (!kernel32Module) {
		return 1;
	}

	DebugInitialise(kernel32Module);

	DefineImportedFuncPtrByHash(kernel32Module, LoadLibraryA, 0x5fbff0fb);
	DefineImportedFuncPtrByHash(kernel32Module, VirtualAlloc, 0x382c0f97);
	//DefineImportedFuncPtrByHash(kernel32Module, VirtualFree, 0x668fcf2e);
	//DefineImportedFuncPtrByHash(kernel32Module, VirtualProtect, 0x844ff18d);
	DefineImportedFuncPtrByHash(kernel32Module, GetProcAddress, 0xcf31bb1f);

	// ntdll.dll - lowercase hash
	void* ntdllModule = GetModuleByHash(0x22d3b5ed);
	if (!ntdllModule) {
		return 2;
	}

	DefineImportedFuncPtrByHash(ntdllModule, NtFlushInstructionCache, 0x80183adf);

	DebugWriteChars('r', 'e', 'a', 'd', 'y', '\n');

	USHORT usCounter;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress = concatenatedDllBytesPtr;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// This should print MZ
	DebugWriteChars(
		((char*)&((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic)[0],
		((char*)&((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic)[1],
		'\n');

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)VirtualAllocFuncPtr(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	DebugWriteCharsAndFlush('m', 'e', 'm', 'c', 'o', 'p', 'y', '\n');

	while (uiValueA--)
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...

	DebugWriteCharsAndFlush('s', 'e', 'c', 't', 'i', 'o', 'n', 's', '\n');

	// uiValueA = the VA of the first section
	uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--) {
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// uiValueC if the VA for this sections data
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	DebugWriteCharsAndFlush('r', 'e', 's', 'o', 'l', 'v', 'e', 'I', 'A', 'T', '\n');

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name) {
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)LoadLibraryAFuncPtr((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA)) {
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else {
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)GetProcAddressFuncPtr((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...

	DebugWriteCharsAndFlush('b', 'a', 's', 'e', 'r', 'e', 'l', 'o', 'c', '\n');

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size) {
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--) {
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T) {
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD));
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					// sanity chack we are processing a MOV instruction...
					if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT) {
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm = (WORD)(dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
					}
				}
#endif
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
				}
			}

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	NtFlushInstructionCacheFuncPtr((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	DebugWriteCharsAndFlush('d', 'l', 'l', 'm', 'a', 'i', 'n', '\n');

	// if we are injecting an DLL via a stub we call DllMain with no parameter
	DWORD result = ((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	// Return 0 if result is true
	return !(result == TRUE);
}