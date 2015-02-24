// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "Loader.h"

int a = 999999;
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//a = hookapi(GetModuleHandle(L"Attila.dll"), "KERNEL32.dll", "CreateFileW",  &CreateFileWH);
		a = PatchIat(GetModuleHandle(L"Rome2.dll"), "KERNEL32.dll", "CreateFileW", &CreateFileWH);
		MessageBox(NULL, std::to_wstring(a).c_str(), L"Hooked", MB_OK);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break; 
	}
	return TRUE;
}

