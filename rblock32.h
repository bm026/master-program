#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <string.h>
#include <stdlib.h>
#include <SubAuth.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntioapi.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "NtosKrnl.lib")

#define HEADER_SIZE 128
#define HASH_TABLE_SIZE 2048

#define HEADER_DIFFERENCE_THRESHOLD 64
#define OCCURRENCE_THRESHOLD 3
#define TIME_THRESHOLD 20
#define INDICATOR_THRESHOLD 3

struct HookArray {
	CHAR *dll;
	CHAR *function;
	LPVOID proxy;
	LPVOID original;
	DWORD length;
};

typedef NTSTATUS(WINAPI *NtCreateThreadExProc) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

struct NtCreateThreadExBuffer {
	ULONG Length;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

// hash table entry
struct file_s {
	TCHAR name[MAX_PATH];
	char header[HEADER_SIZE];
	unsigned long time;
	struct file_s *prev;
	struct file_s *next;
};
typedef struct file_s file_t;

void Init_Data_Structures();
unsigned long Get_Timestamp();
unsigned int HT_Hash(TCHAR *filename);
void HT_Insert(TCHAR *name, char *header);
file_t *HT_Find(TCHAR *name);
void HT_Delete(TCHAR *name);
void Record_File_In_Table(HANDLE h);
void Check_File_In_Table(HANDLE h, BOOL is_close);
void Check_Header_Change_Occurrences();
void Check_File_Deletion_Occurrences(unsigned int n);
void Check_CandC_Occurrence(const TCHAR *name);
void Check_Registry_Change_Occurrence(unsigned int n);
void Check_File_Extension_Occurrence();
void Check_Directory_Traversal_Occurrence(PUNICODE_STRING dir);
void Check_Windows_Crypto_Library_Occurrence(HKEY key, const TCHAR *subkey);
void Check_All_Indicators();
void Terminate_Process();
void Hook_Functions();
BOOL Hook_Function(CHAR *dll, CHAR *function, LPVOID proxy, LPVOID original, PDWORD length);
void Unhook_Functions();
BOOL Unhook_Function(CHAR *dll, CHAR *function, LPVOID original, DWORD length);
BOOL Inject_Dll(DWORD dw_procID);
void Termination_Message();

// CreateProcessA
typedef BOOL (WINAPI *tOldCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI NewCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
tOldCreateProcessA OldCreateProcessA;

// CreateProcessW
typedef BOOL (WINAPI *tOldCreateProcessW)(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI NewCreateProcessW(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
tOldCreateProcessW OldCreateProcessW;

// MessageBoxW
typedef int (WINAPI *tOldMessageBoxW)(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);
int WINAPI NewMessageBoxW(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);
tOldMessageBoxW OldMessageBoxW;

// CreateFileA
typedef HANDLE (WINAPI *tOldCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI NewCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
tOldCreateFileA OldCreateFileA;

// CreateFileW
typedef HANDLE(WINAPI *tOldCreateFileW)(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI NewCreateFileW(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
tOldCreateFileW OldCreateFileW;

// WriteFile
typedef BOOL(WINAPI *tOldWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped);
BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
tOldWriteFile OldWriteFile;

// RegOpenKeyExA
typedef LONG(WINAPI *tOldRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LONG WINAPI NewRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
tOldRegOpenKeyExA OldRegOpenKeyExA;

// RegOpenKeyExW
typedef LONG(WINAPI *tOldRegOpenKeyExW)(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LONG WINAPI NewRegOpenKeyExW(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
tOldRegOpenKeyExW OldRegOpenKeyExW;

// RegSetValueExA
typedef LONG(WINAPI *tOldRegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG WINAPI NewRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
tOldRegSetValueExA OldRegSetValueExA;

// RegSetValueExW
typedef LONG(WINAPI *tOldRegSetValueExW)(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LONG WINAPI NewRegSetValueExW(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
tOldRegSetValueExW OldRegSetValueExW;

// NtQueryDirectoryFile
typedef NTSTATUS(*tOldNtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
NTSTATUS NewNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
tOldNtQueryDirectoryFile OldNtQueryDirectoryFile;

// ZwQueryDirectoryFile
typedef NTSTATUS(*tOldZwQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
NTSTATUS NewZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
tOldZwQueryDirectoryFile OldZwQueryDirectoryFile;

// NtQueryAttributesFile
typedef NTSTATUS(*tOldNtQueryAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
NTSTATUS NewNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
tOldNtQueryAttributesFile OldNtQueryAttributesFile;

// PathFindExtensionA
typedef LPSTR(*tOldPathFindExtensionA)(LPSTR pszPath);
LPSTR NewPathFindExtensionA(LPSTR pszPath);
tOldPathFindExtensionA OldPathFindExtensionA;

// PathFindExtensionW
typedef LPWSTR(*tOldPathFindExtensionW)(LPWSTR pszPath);
LPWSTR NewPathFindExtensionW(LPWSTR pszPath);
tOldPathFindExtensionW OldPathFindExtensionW;


// GLOBAL VARIABLES
LPVOID trampoline_area;
file_t **file_table;

unsigned long o_headerchange[OCCURRENCE_THRESHOLD];
unsigned int o_headerchange_p = 0;
unsigned long o_filedelete[2];
unsigned long o_filesdeleted[OCCURRENCE_THRESHOLD];
unsigned int o_filesdeleted_p = 0;
unsigned long o_registrychange[2];

unsigned long i_headerchange = 0;
unsigned long i_registrychange = 0;
unsigned long i_candc = 0;
unsigned long i_directorytraversal = 0;
unsigned long i_cryptolib = 0;
unsigned long i_filedelete = 0;
unsigned long i_fileextension = 0;