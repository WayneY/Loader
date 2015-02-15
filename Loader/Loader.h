#include <Windows.h>
#include <string>

#ifdef UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif


int hookapi(HMODULE hModule, LPCTSTR lpLibFileName, LPSTR lpApiName, LRESULT Callback);
LPCTSTR changeFileDir(LPCTSTR lpFileNameOrig, tstring toReplace, tstring replacement);
LPCSTR changeFileDir(LPCSTR lpFileNameOrig, std::string toReplace, std::string replacement);
tstring GetFileNameByHandle(HANDLE file);
HANDLE CreateFileAH(LPCTSTR lpFileName, DWORD dwDesireAccess, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL ReadFileH(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

