#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#define BUFSIZE 512

TCHAR dll_path[MAX_PATH] = _T("C:\\Program Files\\rblock\\rblock32.dll");

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

void print_error(wchar_t *error);

int main(int argc, char *argv[]) {
	HANDLE h_proc;
	HANDLE h_remotethread;
	HMODULE hm_ntdll;
	HMODULE hm_kernel32;
	LPVOID lp_remotemem;
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
	TCHAR filename[MAX_PATH];

	unsigned int procID = strtoul(argv[0], NULL, 10);
	dll_path_len = _tcslen(dll_path) * sizeof(TCHAR);

	// get handle for process
	h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procID);
	if (h_proc == NULL) {
		print_error(_T("getting process handle"));
		return FALSE;
	}

	// get output information
	GetModuleFileNameEx(h_proc, NULL, filename, sizeof(filename));
	_tprintf(_T("New process: %s\n"), filename);

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
	getchar();
	return TRUE;
}

void print_error(wchar_t *error) {
	_tprintf(_T("\tDLL not injected, error %s with code %d\n\n"), error, GetLastError());
	getchar();
}