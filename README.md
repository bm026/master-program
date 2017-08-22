## Master project source code

This repository contains the source code developed during my Master thesis, titled 'Developing a Method for the Detection and
Termination of Ransomware at Runtime'. A breakdown of the files in the repository is shown below:

* **rblock.cpp**: Compiles into rblock.exe, which is the process injection program. This program uses DLL injection to inject rblock32.dll into each running process.
* **rblock32.h** / **rblock32.cpp**: Compile into rblock32.dll, which is the system call monitoring DLL. This DLL uses inline hooking to monitor the system calls made by the process it is injected into, and ultimately makes the decision as to whether the process is suspected ransomware.
* **rblock_inj.cpp**: Compiles into rblock_inj.exe, which is a dedicated process injection program used to carry out DLL injection into new processes.
* **rblock_term.cpp**: Compiles into rblock_term.exe, which is used to display a message to the user when a process has been identified as ransomware and has been terminated.
* **t_aes.cpp**: Compiles into t_aes.exe, which is the ransomware emulation application. This application was used to compile a dictionary of system call patterns of common ransomware tasks.