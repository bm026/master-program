#include "hde32.h"
#include "rblock32.h"

// injection exe
TCHAR exe_name[] = _T("rblock_inj.exe");
TCHAR inj_path[MAX_PATH] = _T("C:\\Program Files\\rblock\\rblock_inj.exe");
TCHAR term_path[MAX_PATH] = _T("C:\\Program Files\\rblock\\rblock_term.exe");

// functions to be hooked
HookArray hook_array[] = {
	{ "kernel32.dll", "CreateProcessA", (LPVOID)&NewCreateProcessA, &OldCreateProcessA, 0 },
	{ "kernel32.dll", "CreateProcessW", (LPVOID)&NewCreateProcessW, &OldCreateProcessW, 0 },
	{ "user32.dll", "MessageBoxW", (LPVOID)&NewMessageBoxW, &OldMessageBoxW, 0 },
	{ "kernel32.dll", "CreateFileA", (LPVOID)&NewCreateFileA, &OldCreateFileA, 0 },
	{ "kernel32.dll", "CreateFileW", (LPVOID)&NewCreateFileW, &OldCreateFileW, 0 },
	{ "kernel32.dll", "WriteFile", (LPVOID)&NewWriteFile, &OldWriteFile, 0 },
	{ "advapi32.dll", "RegOpenKeyExA", (LPVOID)&NewRegOpenKeyExA, &OldRegOpenKeyExA, 0 },
	{ "advapi32.dll", "RegOpenKeyExW", (LPVOID)&NewRegOpenKeyExW, &OldRegOpenKeyExW, 0 },
	{ "advapi32.dll", "RegSetValueExA", (LPVOID)&NewRegSetValueExA, &OldRegSetValueExA, 0 },
	{ "advapi32.dll", "RegSetValueExW", (LPVOID)&NewRegSetValueExW, &OldRegSetValueExW, 0 },
	{ "ntdll.dll", "NtQueryDirectoryFile", (LPVOID)&NewNtQueryDirectoryFile, &OldNtQueryDirectoryFile, 0 },
	{ "ntoskrnl.exe", "ZwQueryDirectoryFile", (LPVOID)&NewZwQueryDirectoryFile, &OldZwQueryDirectoryFile, 0 },
	{ "shlwapi.dll", "PathFindExtensionA", (LPVOID)&NewPathFindExtensionA, &OldPathFindExtensionA, 0 },
	{ "shlwapi.dll", "PathFindExtensionW", (LPVOID)&NewPathFindExtensionW, &OldPathFindExtensionW, 0 },
	{ "ntdll.dll", "NtQueryAttributesFile", (LPVOID)&NewNtQueryAttributesFile, &OldNtQueryAttributesFile, 0 },
};


// DLL entry function
BOOL APIENTRY DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		Init_Data_Structures();
		Hook_Functions();
		break;
	case DLL_PROCESS_DETACH:
		Unhook_Functions();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

// =================================================================================================
//   MONITORING FUNCTIONS
// =================================================================================================

void Init_Data_Structures() {

	// allocate memory for file hash table
	file_table = (file_t **)malloc(HASH_TABLE_SIZE * sizeof(file_t *));
	memset(file_table, 0, HASH_TABLE_SIZE * sizeof(file_t *));

	return;
}

// get current timestamp as long integer (since 1 Jan 2017)
unsigned long Get_Timestamp() {
	SYSTEMTIME t;
	unsigned long time = 0;
	GetSystemTime(&t);
	time = t.wSecond + 60 * t.wMinute + 3600 * t.wHour + 86400 * t.wDay + 2678400 * t.wMonth + 32140800 * (t.wYear - 2017);
	return time;
}

// get hash key value from file name string
unsigned int HT_Hash(TCHAR *filename) {
	char *file;
	unsigned int hash = 5381;
	int l, c;
	file = (char *)malloc(MAX_PATH * sizeof(char));
	memset(file, 0, MAX_PATH * sizeof(char));
	//l = _tcslen(filename);
	wcstombs(file, filename, MAX_PATH-1);

	// djb2 algorithm
	while ((c = *file++) != 0) {
		hash = ((hash << 5) + hash) + c; // hash * 33 + c
	}
	return hash % HASH_TABLE_SIZE;
}

// create new hash table entry
void HT_Insert(TCHAR *name, char *header) {
	file_t *entry;
	file_t *chain;
	unsigned long time = Get_Timestamp();
	unsigned int key = HT_Hash(name);
	// allocate memory for new entry
	entry = (file_t *)malloc(sizeof(file_t));
	memset(entry, 0, sizeof(file_t));
	// fill entry
	_tcscpy(entry->name, name);
	memcpy(entry->header, header, HEADER_SIZE);
	entry->time = time;
	entry->prev = NULL;
	entry->next = NULL;
	// set entry in table
	if (file_table[key] == NULL) file_table[key] = entry;
	else {
		chain = file_table[key];
		while (chain->next != NULL) {
			if (_tcscmp(chain->name, name) == 0) {
				// update entry
				memcpy(chain->header, header, HEADER_SIZE);
				chain->time = time;
				break;
			}
			else chain = chain->next;
		}
		// add new entry
		if (chain->next == NULL) {
			chain->next = entry;
			entry->prev = chain;
		}
	}
	return;
}

// find entry in hash table
file_t *HT_Find(TCHAR *name) {
	file_t *chain;
	unsigned int key = HT_Hash(name);
	chain = file_table[key];
	while (chain != NULL) {
		if (_tcscmp(chain->name, name) == 0) break;
		else chain = chain->next;
	}
	return chain;
}

// delete entry from table and free memory
void HT_Delete(TCHAR *name) {
	file_t *entry = HT_Find(name);
	unsigned int key = HT_Hash(name);
	if (entry != NULL) {
		// only entry in chain
		if (entry->prev == NULL && entry->next == NULL) file_table[key] = NULL;
		// last entry in chain
		else if (entry->next == NULL) entry->prev->next = NULL;
		// first entry in chain
		else if (entry->prev == NULL) {
			file_table[key] = entry->next;
			entry->next->prev = NULL;
		}
		// middle entry in chain
		else {
			entry->prev->next = entry->next;
			entry->next->prev = entry->prev;
		}
		free(entry);
	}
	return;
}

// get file information from handle and place in file table
void Record_File_In_Table(HANDLE h) {
	FILE_NAME_INFO fni;
	TCHAR *name;
	DWORD dw_bytes;
	char *header;
	name = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
	memset(name, 0, MAX_PATH * sizeof(TCHAR));
	header = (char *)malloc(HEADER_SIZE * sizeof(char));
	memset(header, 0, HEADER_SIZE * sizeof(char));
	// get file name
	GetFileInformationByHandleEx(h, FileNameInfo, &fni, sizeof(fni));
	_tcscpy(name, fni.FileName);
	// read header bytes
	ReadFile(h, header, HEADER_SIZE, &dw_bytes, NULL);
	// add to or update hash table
	HT_Insert(name, header);
	return;
}

// get file information from handle and check against file table
void Check_File_In_Table(HANDLE h, BOOL is_close) {
	file_t *entry = NULL;
	int diff = 0;
	int i;
	unsigned long time;
	FILE_NAME_INFO fni;
	TCHAR *name;
	DWORD dw_bytes;
	char *header;
	name = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
	memset(name, 0, MAX_PATH * sizeof(TCHAR));
	header = (char *)malloc(HEADER_SIZE * sizeof(char));
	memset(header, 0, HEADER_SIZE * sizeof(char));
	// get file name
	GetFileInformationByHandleEx(h, FileNameInfo, &fni, sizeof(fni));
	_tcscpy(name, fni.FileName);
	// read header bytes
	ReadFile(h, header, HEADER_SIZE, &dw_bytes, NULL);
	// find hash table entry
	entry = HT_Find(name);
	// check header entries for differences
	if (entry != NULL) {
		for (i = 0; i < HEADER_SIZE; i++) {
			if (entry->header[i] != header[i]) diff++;
		}
		if (diff >= HEADER_DIFFERENCE_THRESHOLD) {
			// too many differences, possible encryption
			Check_Header_Change_Occurrences();
		}
		if (is_close) HT_Delete(name);
	}
	return;
}

// checks for multiple occurrences of header changes
void Check_Header_Change_Occurrences() {
	unsigned long time = Get_Timestamp();
	unsigned int next_p = (o_headerchange_p + 1) % OCCURRENCE_THRESHOLD;
	o_headerchange[o_headerchange_p] = time;
	if ((o_headerchange[o_headerchange_p] - o_headerchange[next_p]) <= TIME_THRESHOLD) {
		// occurrence threshold reached in under time threshold
		i_headerchange = time;
		Check_All_Indicators();
	}
	o_headerchange_p = next_p;
	return;
}

// checks for multiple occurrences of file deletion
void Check_File_Deletion_Occurrences(unsigned int n) {
	unsigned long time = Get_Timestamp();
	unsigned int next_p;
	o_filedelete[n] = time;
	if ((o_filedelete[0] <= o_filedelete[1]) && ((o_filedelete[1] - o_filedelete[0]) <= TIME_THRESHOLD)) {
		next_p = (o_filesdeleted_p + 1) % OCCURRENCE_THRESHOLD;
		o_filedelete[o_filesdeleted_p] = time;
		if ((o_filedelete[o_filesdeleted_p] - o_filedelete[next_p]) <= TIME_THRESHOLD) {
			// occurrence threshold reached in under time threshold
			i_filedelete = time;
			Check_All_Indicators();
		}
		o_filesdeleted_p = next_p;
	}
	return;
}

// checks for establishment of socket with command and control server
void Check_CandC_Occurrence(const TCHAR *name) {
	unsigned long time;
	// if socket endpoint created
	if (_tcscmp(name, _T("\\Device\\Afd\\Endpoint")) == 0) {
		time = Get_Timestamp();
		i_candc = time;
		Check_All_Indicators();
	}
	return;
}

// checks for registry changes
void Check_Registry_Change_Occurrence(unsigned int n) {
	unsigned long time = Get_Timestamp();
	o_registrychange[n] = time;
	if ((o_registrychange[0] <= o_registrychange[1]) && ((o_registrychange[1] - o_registrychange[0]) <= TIME_THRESHOLD)) {
		i_registrychange = time;
		Check_All_Indicators();
	}
	return;
}

// checks for file extension checking
void Check_File_Extension_Occurrence() {
	unsigned long time = Get_Timestamp();
	i_fileextension = time;
	Check_All_Indicators();
	return;
}

// checks for directory traversal
void Check_Directory_Traversal_Occurrence(PUNICODE_STRING dir) {
	unsigned long time;
	TCHAR wildcard[2] = _T("*");
	unsigned int last_char_pos = dir->Length / 2;
	TCHAR last_char[2] = _T("_");
	last_char[0] = dir->Buffer[last_char_pos];

	// check for whole directory mapping
	if ((_tcscmp(last_char, wildcard) == 0) || dir == NULL) {
		time = Get_Timestamp();
		i_directorytraversal = time;
		Check_All_Indicators();
	}
	return;
}

// check for use of the Windows crypto library
void Check_Windows_Crypto_Library_Occurrence(HKEY key, const TCHAR *subkey) {
	unsigned long time;
	if (key == HKEY_LOCAL_MACHINE) {
		if ((_tcscmp(subkey, _T("SOFTWARE\\Windows\\Cryptography\\Defaults\\Provider\\Microsoft Base Cryptography Provider")) == 0) ||
			(_tcscmp(subkey, _T("SOFTWARE\\Windows\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced Cryptography Provider")) == 0) ||
			(_tcscmp(subkey, _T("SOFTWARE\\Windows\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptography Provider")) == 0) ||
			(_tcscmp(subkey, _T("SOFTWARE\\Windows\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptography Provider")) == 0)) {
			time = Get_Timestamp();
			i_cryptolib = time;
			Check_All_Indicators();
		}
	}
	return;
}

// check occurrences to determine whether process should be stopped
void Check_All_Indicators() {
	unsigned int count = 0;
	unsigned long time = Get_Timestamp();
	if (time - i_headerchange <= TIME_THRESHOLD) count++;
	if (time - i_candc <= TIME_THRESHOLD) count++;
	if (time - i_cryptolib <= TIME_THRESHOLD) count++;
	if (time - i_directorytraversal <= TIME_THRESHOLD) count++;
	if (time - i_filedelete <= TIME_THRESHOLD) count++;
	if (time - i_registrychange <= TIME_THRESHOLD) count++;

	if (count >= INDICATOR_THRESHOLD) {
		// STOP PROCESS
		Terminate_Process();
	}
	return;
}

// terminates current process
void Terminate_Process() {
	HANDLE proc;
	proc = GetCurrentProcess();
	Termination_Message();
	TerminateProcess(proc, 1);
	return;
}

// =================================================================================================
//   PROXY FUNCTIONS
// =================================================================================================

// CreateProcessA
BOOL WINAPI NewCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
	
	BOOL ret = OldCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	Inject_Dll(lpProcessInformation->dwProcessId);
	return ret;
}

// CreateProcessW
BOOL WINAPI NewCreateProcessW(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	BOOL ret = OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	Inject_Dll(lpProcessInformation->dwProcessId);
	return ret;
}

// MessageBoxW
int WINAPI NewMessageBoxW(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType) {
	printf("MessageBoxW called!\n");
	return OldMessageBoxW(hWnd, (LPCSTR)lpText, lpCaption, uType);
}

// CreateFileA
HANDLE WINAPI NewCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	TCHAR t_name[MAX_PATH];
	HANDLE h = OldCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);
	Record_File_In_Table(h);
	mbstowcs(t_name, lpFileName, MAX_PATH);
	Check_CandC_Occurrence(t_name);
	return h;
}

// CreateFileW
HANDLE WINAPI NewCreateFileW(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

	HANDLE h = OldCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);
	Record_File_In_Table(h);
	Check_CandC_Occurrence(lpFileName);
	return h;
}

// WriteFile
BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	BOOL ret = OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	Check_File_In_Table(hFile, FALSE);
	return ret;
}

// RegOpenKeyExA
LONG WINAPI NewRegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
	TCHAR t_subkey[MAX_PATH];
	LONG ret = OldRegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	Check_Registry_Change_Occurrence(0);
	mbstowcs(t_subkey, lpSubKey, MAX_PATH);
	Check_Windows_Crypto_Library_Occurrence(hKey, t_subkey);
	return ret;
}

// RegOpenKeyExW
LONG WINAPI NewRegOpenKeyExW(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
	LONG ret = OldRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	Check_Registry_Change_Occurrence(0);
	Check_Windows_Crypto_Library_Occurrence(hKey, lpSubKey);
	return ret;
}

// RegSetValueExA
LONG WINAPI NewRegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData) {
	LONG ret = OldRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	Check_Registry_Change_Occurrence(1);
	return ret;
}

// RegSetValueExW
LONG WINAPI NewRegSetValueExW(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData) {
	LONG ret = OldRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
	Check_Registry_Change_Occurrence(1);
	return ret;
}

// NtQueryDirectoryFile
NTSTATUS NewNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
	BOOLEAN RestartScan) {
	NTSTATUS ret = OldNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
		BOOLEAN RestartScan);
	Check_Directory_Traversal_Occurrence(FileName);
	Check_File_Deletion_Occurrences(1);
	return ret;
}

// ZwQueryDirectoryFile
NTSTATUS NewZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
	BOOLEAN RestartScan) {
	NTSTATUS ret = OldZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
		BOOLEAN RestartScan);
	Check_Directory_Traversal_Occurrence(FileName);
	Check_File_Deletion_Occurrences(1);
	return ret;
}

// NtQueryAttributesFile
NTSTATUS NewNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {
	NTSTATUS ret = OldNtQueryAttributesFile(ObjectAttributes, FileInformation);
	Check_File_Deletion_Occurrences(0);
	return ret;
}

// PathFindExtensionA
LPSTR NewPathFindExtensionA(LPSTR pszPath) {
	LPSTR ret = OldPathFindExtensionA(pszPath);
	Check_File_Extension_Occurrence();
	return ret;
}

// PathFindExtensionW
LPWSTR NewPathFindExtensionW(LPWSTR pszPath) {
	LPWSTR ret = OldPathFindExtensionW(pszPath);
	Check_File_Extension_Occurrence();
	return ret;
}


// =================================================================================================
//   HOOKING FUNCTIONS
// =================================================================================================

// hooks each function specified in hook array
void Hook_Functions() {
	int entries;
	int i;

	// allocate space for trampoline
	entries = sizeof(hook_array) / sizeof(HookArray);
	trampoline_area = VirtualAlloc(NULL, 25 * entries, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!trampoline_area) return;

	for (i = 0; i < entries; i++) {
		// 25 bytes for each trampoline
		*(LPVOID *)hook_array[i].original = (LPVOID)((DWORD)trampoline_area + (i * 25));
		Hook_Function(hook_array[i].dll, hook_array[i].function, hook_array[i].proxy, *(LPVOID *)hook_array[i].original, &hook_array[i].length);
	}
}


// creates hook and trampoline for function
BOOL Hook_Function(CHAR *dll, CHAR *function, LPVOID proxy, LPVOID original, PDWORD length) {
	LPVOID function_addr;
	DWORD trampoline_len = 0;
	DWORD original_protect;
	hde32s disasm;
	LPVOID ip;
	BYTE source_buf[8];
	BYTE JMP[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	// get function address
	function_addr = GetProcAddress(GetModuleHandleA(dll), function);
	if (function_addr == NULL) return FALSE;

	// disassemble function until we find 5 or more bytes of full instructions
	while (trampoline_len < 5) {
		ip = (LPVOID)((DWORD)function_addr + trampoline_len);
		trampoline_len += hde32_disasm(ip, &disasm);
	}

	// build trampoline buffer using first n bytes of original instructions
	memcpy(original, function_addr, trampoline_len);
	*(DWORD *)(JMP + 1) = ((DWORD)function_addr + trampoline_len) - ((DWORD)original + trampoline_len + 5);
	memcpy((LPVOID)((DWORD)original + trampoline_len), JMP, 5);

	// write hook to original function
	if (VirtualProtect(function_addr, trampoline_len, PAGE_EXECUTE_READWRITE, &original_protect) == NULL) return FALSE;
	*(DWORD *)(JMP + 1) = (DWORD)proxy - (DWORD)function_addr - 5;
	memcpy(source_buf, function_addr, 8); // buffer must be base 2, so pad with arbitrary bytes to make 8
	memcpy(source_buf, JMP, 5);
	__asm
	{
		lea esi, source_buf;
		mov edi, function_addr;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}

	// restore original protection
	VirtualProtect(function_addr, trampoline_len, original_protect, &original_protect);

	// clear old instruction cache
	FlushInstructionCache(GetCurrentProcess(), function_addr, trampoline_len);

	*length = trampoline_len;
	return TRUE;
}


void Unhook_Functions() {
	int entries;
	int i;

	entries = sizeof(hook_array) / sizeof(HookArray);
	for (i = 0; i < entries; i++) {
		// 25 bytes for each trampoline
		Unhook_Function(hook_array[i].dll, hook_array[i].function, *(LPVOID *)hook_array[i].original, hook_array[i].length);
	}
	VirtualFree(trampoline_area, 0, MEM_RELEASE);
}


BOOL Unhook_Function(CHAR *dll, CHAR *function, LPVOID original, DWORD length) {
	LPVOID function_addr;
	DWORD original_protect;
	BYTE source_buf[8];

	// get function address
	function_addr = GetProcAddress(GetModuleHandleA(dll), function);
	if (function_addr == NULL) return FALSE;

	// get write privileges
	if (VirtualProtect(function_addr, length, PAGE_EXECUTE_READWRITE, &original_protect) == NULL) return FALSE;

	// rewrite original function
	memcpy(source_buf, function_addr, 8);
	memcpy(source_buf, original, length);
	__asm
	{
		lea esi, source_buf;
		mov edi, function_addr;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}

	// restore original protection
	VirtualProtect(function_addr, length, original_protect, &original_protect);

	// clear old instruction cache
	FlushInstructionCache(GetCurrentProcess(), function_addr, length);

	return TRUE;
}


// =================================================================================================
//   DLL INJECTION
// =================================================================================================

BOOL Inject_Dll(DWORD dw_procID) {

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	TCHAR procID[10];

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	swprintf_s(procID, sizeof(procID), _T("%d"), dw_procID);

	return OldCreateProcessW(inj_path, procID, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}


// =================================================================================================
//   PROCESS TERMINATION MESSAGE
// =================================================================================================

void Termination_Message() {

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	OldCreateProcessW(term_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	return;
}