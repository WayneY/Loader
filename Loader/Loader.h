#include <Windows.h>
#include <string>

#ifdef UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

#define DllExport   __declspec( dllexport )

#define PtrFromRva(base, rva)(((PBYTE) base) + rva)

int hookapi(HMODULE hModule, LPCSTR lpLibFileName, LPCSTR lpApiName, LPCVOID Callback);
int PatchIat(__in HMODULE Module,__in PSTR ImportedModuleName,__in PSTR ImportedProcName,__in PVOID AlternateProc);
LPCTSTR changeFileDir(LPCTSTR lpFileNameOrig, tstring toReplace, tstring replacement);
LPCSTR changeFileDir(LPCSTR lpFileNameOrig, std::string toReplace, std::string replacement);
tstring GetFileNameByHandle(HANDLE file);
HANDLE CreateFileAH(LPCSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE CreateFileWH(LPCTSTR lpFileName, DWORD dwDesireAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL ReadFileH(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

DllExport void eadem_mutata_resurgo();

