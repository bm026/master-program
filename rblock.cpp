#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#define BUFSIZE 512

TCHAR dll_name[] = _T("rblock32.dll");

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

BOOL Inject_Dll(DWORD dw_procID);
void print_error(wchar_t *error);
void fatal(char *error);


int main(int argc, char *argv[]) {

	HANDLE h_token = NULL;
	TOKEN_PRIVILEGES token_priv;
	LUID luid_debug;
	BOOL status;

	HANDLE h_snapshot = NULL;
	PROCESSENTRY32 pe32;
	memset(&pe32, 0, sizeof(PROCESSENTRY32));

	// enable SeDebugPrivilege
	status = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token);
	if (status == FALSE) fatal("opening process security token");
	status = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid_debug);
	if (status == FALSE) fatal("getting sedebug luid");
	token_priv.PrivilegeCount = 1;
	token_priv.Privileges[0].Luid = luid_debug;
	token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(h_token, FALSE, &token_priv, 0, NULL, NULL) != FALSE) printf("SeDebugPrivileges enabled\n\n");
	else printf("SeDebugPrivileges not enabled\n\n");
	CloseHandle(h_token);

	// take snapshot of processes
	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h_snapshot == INVALID_HANDLE_VALUE) fatal("taking process snapshot");

	// enumerate first process
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(h_snapshot, &pe32) == FALSE) {
		CloseHandle(h_snapshot);
		fatal("first snapshot process");
	}

	// inject dll to first process
	if (pe32.th32ProcessID != 0) {
		_tprintf(_T("Process: %d, %s\n"), pe32.th32ProcessID, pe32.szExeFile);
		Inject_Dll(pe32.th32ProcessID);
	}

	// enumerate other processes
	while (Process32Next(h_snapshot, &pe32)) {
		// inject dll to other processes
		if (pe32.th32ProcessID != 0) {
			_tprintf(_T("Process: %d, %s\n"), pe32.th32ProcessID, pe32.szExeFile);
			Inject_Dll(pe32.th32ProcessID);
		}
	}

	CloseHandle(h_snapshot);

	getchar();
	return 0;
}

BOOL Inject_Dll(DWORD dw_procID) {

	HANDLE h_proc;
	HANDLE h_remotethread;
	HMODULE hm_ntdll;
	HMODULE hm_kernel32;
	LPVOID lp_remotemem;
	TCHAR dll_path[MAX_PATH];
	SIZE_T dll_path_len;
	BOOL status;
	FARPROC LoadLibrary_addr;
	NtCreateThreadExProc NtCreateThreadEx = NULL;
	NtCreateThreadExBuffer nt_buf;

	HMODULE hm_modules[1024];
	DWORD nb;
	TCHAR mod_name[MAX_PATH];
	BOOL is_kernel32 = FALSE;
	unsigned int i;

	// get full dll path
	GetFullPathName(dll_name, MAX_PATH, dll_path, NULL);
	dll_path_len = _tcslen(dll_path) * sizeof(TCHAR);

	// get handle for process
	h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dw_procID);
	if (h_proc == NULL) {
		print_error(_T("getting process handle"));
		return FALSE;
	}

	// check process has relevant modules
	status = EnumProcessModules(h_proc, hm_modules, sizeof(hm_modules), &nb);
	if (status == FALSE) {
		print_error(_T("enumerating process modules"));
		CloseHandle(h_proc);
		return FALSE;
	}
	for (i = 0; i < (nb / sizeof(HMODULE)); i++) {
		if (GetModuleFileNameEx(h_proc, hm_modules[i], mod_name, sizeof(mod_name) / sizeof(TCHAR))) {
			if (StrCmpI(mod_name, _T("C:\\Windows\\System32\\kernel32.dll")) == 0) {
				is_kernel32 = TRUE;
			}
		}
	}
	if (!is_kernel32) {
		print_error(_T("process does not include kernel32.dll"));
		CloseHandle(h_proc);
		return FALSE;
	}

	// get module handles
	hm_ntdll = GetModuleHandle(_T("ntdll.dll"));
	hm_kernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hm_kernel32 == NULL) {
		print_error(_T("getting handle to kernel32.dll"));
		CloseHandle(h_proc);
		return FALSE;
	}

	// get LoadLibrary address
	LoadLibrary_addr = GetProcAddress(hm_kernel32, "LoadLibraryW");
	if (LoadLibrary_addr == NULL) {
		print_error(_T("getting LoadLibrary address"));
		CloseHandle(h_proc);
		return FALSE;
	}

	// allocate memory in process
	lp_remotemem = VirtualAllocEx(h_proc, NULL, dll_path_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lp_remotemem == NULL) {
		print_error(_T("allocating memory in process"));
		CloseHandle(h_proc);
		return FALSE;
	}

	// write to process
	status = WriteProcessMemory(h_proc, lp_remotemem, (LPCVOID)dll_path, dll_path_len, NULL);
	if (status == NULL) {
		print_error(_T("no bytes written to process"));
		CloseHandle(h_proc);
		return FALSE;
	}

	// if windows 7, vista, use NtCreateThreadEx
	if (hm_ntdll != NULL) {
		_tprintf(_T("\tUsing NtCreateThreadEx\n"));

		// get NtCreateThreadEx address
		NtCreateThreadEx = (NtCreateThreadExProc)GetProcAddress(hm_ntdll, "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL) {
			print_error(_T("getting NtCreateThreadEx address"));
			CloseHandle(h_proc);
			return FALSE;
		}

		// initialise buffer
		memset(&nt_buf, 0, sizeof(NtCreateThreadExBuffer));
		DWORD temp1 = 0;
		DWORD temp2 = 0;
		nt_buf.Length = sizeof(NtCreateThreadExBuffer);
		nt_buf.Unknown1 = 0x10003;
		nt_buf.Unknown2 = 0x8;
		nt_buf.Unknown3 = &temp2;
		nt_buf.Unknown4 = 0;
		nt_buf.Unknown5 = 0x10004;
		nt_buf.Unknown6 = 4;
		nt_buf.Unknown7 = &temp1;
		nt_buf.Unknown8 = 0;

		// create remote thread
		status = NtCreateThreadEx(&h_remotethread, GENERIC_ALL, NULL, h_proc, (LPTHREAD_START_ROUTINE)LoadLibrary_addr, lp_remotemem, FALSE, NULL, NULL, NULL, &nt_buf);
		if (status < 0) {
			print_error(_T("calling NtCreateThreadEx"));
			CloseHandle(h_proc);
			return FALSE;
		}
		WaitForSingleObject(h_remotethread, 1000);
	}

	// if windows xp, use CreateRemoteThread
	else {
		_tprintf(_T("\tUsing CreateRemoteThread\n"));

		// create remote thread
		h_remotethread = CreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary_addr, lp_remotemem, 0, NULL);
		if (h_remotethread == NULL) {
			print_error(_T("calling CreateRemoteThread"));
			CloseHandle(h_proc);
			return FALSE;
		}
	}

	_tprintf(_T("\tDLL injected successfully\n\n"));
	CloseHandle(h_proc);
	return TRUE;
}

void print_error(wchar_t *error) {
	_tprintf(_T("\tDLL not injected, error %s with code %d\n\n"), error, GetLastError());
}

// prints error message and closes program when something terrible happens
void fatal(char *error) {
	printf("Error: %s, with code %u. Exiting.\n", error, GetLastError());
	getchar();
	exit(1);
}