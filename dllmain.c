/* Replace "dll.h" with the name of your header */
#include "dll.h"
#include <stdio.h>
#include <windows.h>
#include <string.h>


BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			HMODULE hMod = GetModuleHandleA(0);
	
			PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)hMod;
			PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS) ((PBYTE) hMod + DOS->e_lfanew);
			PIMAGE_IMPORT_DESCRIPTOR IMPORT = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hMod + NT->OptionalHeader.DataDirectory[1].VirtualAddress);
			FILE *file = fopen("C:\\Users\\dltmd\\Desktop\\coding\\iat\\data.txt", "w");
			
			while(IMPORT->FirstThunk) {
				char *mod = (char *) (PBYTE)hMod + IMPORT->Name;
				fputs(mod, file);
				 fputc('\n', file);
				
				PIMAGE_THUNK_DATA THUNK = (PIMAGE_THUNK_DATA)((PBYTE)hMod + IMPORT->OriginalFirstThunk);
				
				while(THUNK->u1.Function){ 
					char *function = (char *) ((PBYTE)hMod + THUNK->u1.AddressOfData +2);
					fputs("  - ", file);
					fputs(function, file);
					fputc('\n', file);
					THUNK++;
				}
				IMPORT++;
			}
			fclose(file);
			
			break;
		}

	}
	
	/* Return TRUE on success, FALSE on failure */
	return TRUE;
}
