#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlHelp32.h>
#include <string.h>

DWORD GetProcess(char pName[32]) {
	char pByName[32];
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD tProc = NULL;
	PROCESSENTRY32 pe32= {0,};
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	
	sprintf(pByName, "%s.exe", pName);
	Process32First(hSnap, &pe32);
	
	while(Process32Next(hSnap, &pe32)){
		if( !strcmp(pByName, pe32.szExeFile) ) {
			printf("[*] Process Found : %s\n", pe32.szExeFile);
			tProc = pe32.th32ProcessID;
			break;
		}
	}	
	
	if( tProc == NULL){
		printf("not found");
	}
	return tProc;
	
} 

bool Inject(DWORD pid, char dName[128]) {
	HANDLE hProc, hMod, hTred;
	LPVOID buff, addr;
	
	if( !(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) ) 
		return false;
	
	if( !(buff = VirtualAllocEx(hProc, NULL, lstrlen(dName) +1, MEM_COMMIT, PAGE_READWRITE )) )
		return false;
	
	if(	!(WriteProcessMemory(hProc, buff, (LPVOID)dName, lstrlen((LPCTSTR)dName) +1, NULL))	)
		return false;
	
	hMod = GetModuleHandle("kernel32.dll");
	addr = (void (*))GetProcAddress((HMODULE)hMod, "LoadLibraryA");
	hTred = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, buff, 0, NULL);
	
	WaitForSingleObject(hTred, INFINITE);
	
	CloseHandle(hProc); 
	CloseHandle(hMod);
	CloseHandle(hTred);
	return true;
}

//void IATPrint() {
//	HMODULE hMod = GetModuleHandleA(0);
//	
//	PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)hMod;
//	PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS) ((PBYTE) hMod + DOS->e_lfanew);
//	PIMAGE_IMPORT_DESCRIPTOR IMPORT = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hMod + NT->OptionalHeader.DataDirectory[1].VirtualAddress);
//	
//	while(IMPORT->FirstThunk) {
//		printf("[*] Get Module Name : %s\n", (char *) (PBYTE)hMod + IMPORT->Name );
//		
//		PIMAGE_THUNK_DATA THUNK = (PIMAGE_THUNK_DATA)((PBYTE)hMod + IMPORT->OriginalFirstThunk);
//		
//		while(THUNK->u1.Function){ 
//			printf("  - Function Name : %s\n", (char *) ((PBYTE)hMod + THUNK->u1.AddressOfData +2));
//			THUNK++;
//		}
//		IMPORT++;
//	}
//}


int main() {
	char target[32], dll[128];
	DWORD pid;
	
	printf("[INPUT] Process Name : ");
	scanf("%s", target );
	printf("[*] Found the Process\n");               
	printf("  - pid : %d\n", (pid = GetProcess(target)));
	
	printf("[INPUT] DLL Name : ");
	scanf("%s", dll);
	
	printf("  - DLL Name : %s\n", dll);
	
	if( Inject(pid, dll) ) {
		printf("Suscess Inject!");
	} else {
	 	printf("Faild Inject...");
	 }
	
	printf("\n===============================================\n\n");
	
	//IATPrint();
	//path

	return 0;
}
