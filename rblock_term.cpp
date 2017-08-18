#include <Windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
	MessageBox(NULL, L"Behaviour similar to that of ransomware was detected; the process was terminated.", L"POTENTIAL RANSOMWARE BLOCKED", MB_OK);
	return 0;
}