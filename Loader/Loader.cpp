// Loader.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Loader.h"
#include <psapi.h>



int hookapi(HMODULE hModule, LPCTSTR lpLibFileName, LPCTSTR lpApiName, LRESULT Callback){
	return 0;
}

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
	return CreateFileW(changeFileDir(lpFileName, L"data\\local_cn.pack", L"clanlong\\clanlong.bin"), dwDesireAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL ReadFileH(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped){
	if (ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)){
		tstring sFileName = GetFileNameByHandle(hFile);
		if (L"clanlong.bin" == sFileName){
			Decrypt(lpBuffer, nNumberOfBytesToRead);
		}
		return TRUE;
	}
	else{
		return FALSE;
	}

}

BOOL Decrypt(LPVOID lpBuffer, DWORD nNumberOfBytesToRead){
	__asm{
		mov esi, $115D2312
		mov TimeKey, esi
		mov esi, Packet
		mov eax, Len
		push esi
		push 0
		push eax
		lea edi, dword ptr[esi]
		push edi
		call @Start
		jmp @Exit
	@Start:
		push ebp
		mov ebp, esp
		mov ecx, dword ptr[ebp + $010]
		test ecx, ecx
		mov eax, $04453EB5
		je @_DNF_00799178
		push ecx
		call Sub008D5240
		add esp, 4
		@_DNF_00799178:

		push ebx
		movzx ebx, ah
		and ebx, $080000007
		push esi
		mov byte ptr TmpKey_1, al
		jns @_DNF_0079918F
		dec ebx
		or ebx, $FFFFFFF8
		inc ebx
	@_DNF_0079918F:
		mov eax, dword ptr[ebp + $0C]
		xor esi, esi
		test eax, eax
		mov dword ptr TmpKey_2, ebx
		jle @_DNF_007991D6
		push edi
		mov edi, dword ptr[ebp + 8]
		jmp @_DNF_007991B0

	@_DNF_007991A4:
		mov ebx, dword ptr TmpKey_2
		lea ebx, dword ptr[ebx]
	@_DNF_007991B0 :
		mov dl, byte ptr[esi + edi]
		mov cl, 8
		sub cl, bl
		mov al, dl
		shr al, cl
		mov ecx, ebx
		shl dl, cl
		or al, dl
		mov byte ptr[esi + edi], al
		xor al, byte ptr TmpKey_1
		mov byte ptr[esi + edi], al
		mov eax, dword ptr[ebp + $0C]
		inc esi
		cmp esi, eax
		jl @_DNF_007991A4
		pop edi
	@_DNF_007991D6:
		pop esi
		pop ebx
		pop ebp
		ret $10
	@Exit:

	@Sub008D5240:
	@_DNF_008D5240:
		push ebp
		mov ebp, esp
		push esi
		mov esi, dword ptr[ebp + 8]
		test esi, esi
		jnz @_DNF_008D525C
		call timeGetTime
		add dword ptr TimeKey, eax
		lea esi, TimeKey
	@_DNF_008D525C:
		mov eax, dword ptr[esi]
		imul eax, eax, $041C64E6D
		add eax, $03039
		mov edx, eax
		imul eax, eax, $041C64E6D
		add eax, $03039
		mov ecx, eax
		imul eax, eax, $041C64E6D
		shr edx, $010
		shr ecx, $010
		add eax, $03039
		and edx, $07FF
		and ecx, $03FF
		mov dword ptr[esi], eax
		shl edx, $0A
		xor ecx, edx
		shr eax, $010
		and eax, $03FF
		shl ecx, $0A
		xor eax, ecx
		pop esi
		pop ebp
		ret
	}
}