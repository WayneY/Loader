// Loader.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Loader.h"
#include <psapi.h>




int hookapi(HMODULE hModule, LPCSTR lpLibFileName, LPCSTR lpApiName, LPCVOID Callback){
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)PtrFromRva(pDosHdr, pDosHdr->e_lfanew);
	if (IMAGE_NT_SIGNATURE != pNtHdr->Signature)
	{
		return 1;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)PtrFromRva(pDosHdr, pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; pImportDesc->Name; pImportDesc++){
		LPCSTR dllName = (LPCSTR)PtrFromRva(pDosHdr, pImportDesc->Name);
		if (0 == lstrcmpiA(dllName, lpLibFileName)){
			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHdr, pImportDesc->FirstThunk);
			PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHdr, pImportDesc->OriginalFirstThunk);
			for (; origThunk->u1.Function; origThunk++, thunk++){
				if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
					continue;
				}

				PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)PtrFromRva(pDosHdr, origThunk->u1.AddressOfData);
				if (0 == lstrcmpA(lpApiName, (LPCSTR)pImport->Name)){

					MEMORY_BASIC_INFORMATION thunkMemInfo;
					DWORD junk;
					DWORD oldProtect;
					if (!VirtualQuery(thunk, &thunkMemInfo, sizeof(MEMORY_BASIC_INFORMATION))){
						return GetLastError();
					}

					//if (!VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &junk)){
					//MessageBoxA(NULL, std::to_string(thunkMemInfo.RegionSize).c_str(), "Hooked", MB_OK);
					PROC* baseaddr = (PROC*)&thunk->u1.Function;
					if (!VirtualProtect(baseaddr, sizeof(Callback), PAGE_EXECUTE_READWRITE, &oldProtect)){
						return GetLastError();
					}
#ifdef _WIN64
					thunk->u1.Function = (ULONGLONG)(DWORD_PTR)Callback;
#else

					thunk->u1.Function = (DWORD)Callback;
#endif
					MessageBoxA(NULL, "aaaa", "Hooked", MB_OK);
					
					if (!VirtualProtect(&thunk, thunkMemInfo.RegionSize, oldProtect, &junk)){
						return 3;
					}
					
					return S_OK;
				}
			}

			return 5;
		}
	}
	
	return 6;
		
}

//int hookapi(HMODULE hModule, LPCSTR lpLibFileName, LPCSTR lpApiName, LPCVOID Callback){
//	HMODULE hLoaded =  LoadLibraryA(lpLibFileName);
//	FARPROC pProtoFill = GetProcAddress(hLoaded, lpApiName);
//	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hModule;
//	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)PtrFromRva(pDosHdr, pDosHdr->e_lfanew);	
//	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)PtrFromRva(pDosHdr, pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
//	while (pImportDesc->Name){
//		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHdr, pImportDesc->FirstThunk);
//		while (thunk->u1.Function){
//			PROC* ppfn = (PROC*)&thunk->u1.Function;
//			if (*ppfn == pProtoFill){
//				DWORD oldProtect;
//				if (!VirtualProtect(ppfn, sizeof(Callback), PAGE_EXECUTE_READWRITE, &oldProtect)){
//					return GetLastError();
//				}
//				ppfn = &Callback;
//				return 0;
//			}
//			thunk++;
//		}
//		pImportDesc++;
//	}
//}


LPCTSTR changeFileDir(LPCTSTR lpFileNameOrig, tstring toReplace, tstring replacement){
	tstring filenameorig(lpFileNameOrig);
	return filenameorig.replace(filenameorig.find(toReplace), toReplace.length(), replacement).c_str();
}

LPCSTR changeFileDir(LPCSTR lpFileNameOrig, std::string toReplace, std::string replacement){
	std::string filenameorig(lpFileNameOrig);
	return filenameorig.replace(filenameorig.find(toReplace), toReplace.length(), replacement).c_str();
}

tstring GetFileNameByHandle(HANDLE hFile)
{
	TCHAR pszFilename[MAX_PATH + 1];
	HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);;
	tstring sFileName;
	if (hFileMap)
	{
		LPVOID pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem)
		{
			if (GetMappedFileName(GetCurrentProcess(),pMem,pszFilename,MAX_PATH))
			{
				tstring path(pszFilename);
				auto pos = path.rfind(L"\\");
				if (pos == tstring::npos){
					pos = -1;
				}
				sFileName =  tstring(path.begin() + pos + 1, path.end());
			}
			UnmapViewOfFile(pMem);
		}

		CloseHandle(hFileMap);
	}
	return sFileName;
}

HANDLE CreateFileAH(LPCSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	return CreateFileA(changeFileDir(lpFileName,"data\\local_cn.pack","clanlong\\clanlong.bin"), dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE CreateFileWH(LPCTSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	//return CreateFileW(changeFileDir(lpFileName, L"data\\local_cn.pack", L"clanlong\\clanlong.bin"), dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	MessageBox(NULL, L"Hook!", L"Hooked", MB_OK);
	return CreateFileW(lpFileName, dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DllExport void eadem_mutata_resurgo(){

}

//BOOL ReadFileH(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped){
//	if (ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)){
//		tstring sFileName = GetFileNameByHandle(hFile);
//		if (L"clanlong.bin" == sFileName){
//			Decrypt(lpBuffer, nNumberOfBytesToRead);
//		}
//		return TRUE;
//	}
//	else{
//		return FALSE;
//	}
//
//}

//BOOL Decrypt(LPVOID lpBuffer, DWORD nNumberOfBytesToRead){
//	__asm{
//		mov esi, $115D2312
//		mov TimeKey, esi
//		mov esi, Packet
//		mov eax, Len
//		push esi
//		push 0
//		push eax
//		lea edi, dword ptr[esi]
//		push edi
//		call @Start
//		jmp @Exit
//	@Start:
//		push ebp
//		mov ebp, esp
//		mov ecx, dword ptr[ebp + $010]
//		test ecx, ecx
//		mov eax, $04453EB5
//		je @_DNF_00799178
//		push ecx
//		call Sub008D5240
//		add esp, 4
//		@_DNF_00799178:
//
//		push ebx
//		movzx ebx, ah
//		and ebx, $080000007
//		push esi
//		mov byte ptr TmpKey_1, al
//		jns @_DNF_0079918F
//		dec ebx
//		or ebx, $FFFFFFF8
//		inc ebx
//	@_DNF_0079918F:
//		mov eax, dword ptr[ebp + $0C]
//		xor esi, esi
//		test eax, eax
//		mov dword ptr TmpKey_2, ebx
//		jle @_DNF_007991D6
//		push edi
//		mov edi, dword ptr[ebp + 8]
//		jmp @_DNF_007991B0
//
//	@_DNF_007991A4:
//		mov ebx, dword ptr TmpKey_2
//		lea ebx, dword ptr[ebx]
//	@_DNF_007991B0 :
//		mov dl, byte ptr[esi + edi]
//		mov cl, 8
//		sub cl, bl
//		mov al, dl
//		shr al, cl
//		mov ecx, ebx
//		shl dl, cl
//		or al, dl
//		mov byte ptr[esi + edi], al
//		xor al, byte ptr TmpKey_1
//		mov byte ptr[esi + edi], al
//		mov eax, dword ptr[ebp + $0C]
//		inc esi
//		cmp esi, eax
//		jl @_DNF_007991A4
//		pop edi
//	@_DNF_007991D6:
//		pop esi
//		pop ebx
//		pop ebp
//		ret $10
//	@Exit:
//
//	@Sub008D5240:
//	@_DNF_008D5240:
//		push ebp
//		mov ebp, esp
//		push esi
//		mov esi, dword ptr[ebp + 8]
//		test esi, esi
//		jnz @_DNF_008D525C
//		call timeGetTime
//		add dword ptr TimeKey, eax
//		lea esi, TimeKey
//	@_DNF_008D525C:
//		mov eax, dword ptr[esi]
//		imul eax, eax, $041C64E6D
//		add eax, $03039
//		mov edx, eax
//		imul eax, eax, $041C64E6D
//		add eax, $03039
//		mov ecx, eax
//		imul eax, eax, $041C64E6D
//		shr edx, $010
//		shr ecx, $010
//		add eax, $03039
//		and edx, $07FF
//		and ecx, $03FF
//		mov dword ptr[esi], eax
//		shl edx, $0A
//		xor ecx, edx
//		shr eax, $010
//		and eax, $03FF
//		shl ecx, $0A
//		xor eax, ecx
//		pop esi
//		pop ebp
//		ret
//	}
//}



int PatchIat(
	__in HMODULE Module,
	__in PSTR ImportedModuleName,
	__in PSTR ImportedProcName,
	__in PVOID AlternateProc
	)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	UINT Index;

	_ASSERTE(Module);
	_ASSERTE(ImportedModuleName);
	_ASSERTE(ImportedProcName);
	_ASSERTE(AlternateProc);

	NtHeader = (PIMAGE_NT_HEADERS)
		PtrFromRva(DosHeader, DosHeader->e_lfanew);

	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)
		PtrFromRva(DosHeader,
		NtHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//
	// Iterate over import descriptors/DLLs.
	//
	for (Index = 0;
		ImportDescriptor[Index].Characteristics != 0;
		Index++)
	{
		PSTR dllName = (PSTR)
			PtrFromRva(DosHeader, ImportDescriptor[Index].Name);

		if (0 == _strcmpi(dllName, ImportedModuleName))
		{
			//
			// This the DLL we are after.
			//
			PIMAGE_THUNK_DATA Thunk;
			PIMAGE_THUNK_DATA OrigThunk;

			if (!ImportDescriptor[Index].FirstThunk ||
				!ImportDescriptor[Index].OriginalFirstThunk)
			{
				return 1;
			}

			Thunk = (PIMAGE_THUNK_DATA)
				PtrFromRva(DosHeader,
				ImportDescriptor[Index].FirstThunk);
			OrigThunk = (PIMAGE_THUNK_DATA)
				PtrFromRva(DosHeader,
				ImportDescriptor[Index].OriginalFirstThunk);

			for (; OrigThunk->u1.Function != NULL;
				OrigThunk++, Thunk++)
			{
				if (OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					continue;
				}

				PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)
					PtrFromRva(DosHeader, OrigThunk->u1.AddressOfData);

				if (0 == strcmp(ImportedProcName,
					(char*)import->Name))
				{
					//
					// Proc found, patch it.
					//
					DWORD junk;
					MEMORY_BASIC_INFORMATION thunkMemInfo;

					//
					// Make page writable.
					//
					VirtualQuery(
						Thunk,
						&thunkMemInfo,
						sizeof(MEMORY_BASIC_INFORMATION));

					if (FALSE == VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, thunkMemInfo.AllocationProtect, &thunkMemInfo.Protect)){
						return (GetLastError());
					};
					MessageBox(NULL, L"1111111!", L"Hooked", MB_OK);
					if (FALSE == VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &thunkMemInfo.Protect)){
						return (GetLastError());
					};
					MessageBox(NULL, L"111133333111!", L"Hooked", MB_OK);

#ifdef _WIN64
					Thunk->u1.Function = (ULONGLONG)(DWORD_PTR)
						AlternateProc;
#else
					//DWORD * pTemp = (DWORD*)&Thunk->u1.Function;
					//*pTemp = (DWORD)AlternateProc;
					Thunk->u1.Function = (DWORD)(DWORD_PTR)AlternateProc;
#endif
					MessageBox(NULL, L"222222!", L"Hooked", MB_OK);
					//
					// Restore page protection.
					//
					if (!VirtualProtect(
						thunkMemInfo.BaseAddress,
						thunkMemInfo.RegionSize,
						thunkMemInfo.Protect,
						&junk))
					{
						return(GetLastError());
					}

					return 0;
				}
			}

			//
			// Import not found.
			//
			return 2;
		}
	}

	//
	// DLL not found.
	//
	return 3;
}