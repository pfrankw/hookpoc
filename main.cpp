
#include <stdio.h>
#include <windows.h>




int enableDebugPrivileges() {
    HANDLE hcurrent=GetCurrentProcess();
    HANDLE hToken;
    BOOL bret=OpenProcessToken(hcurrent,40,&hToken);
    LUID luid;
    bret=LookupPrivilegeValue(NULL,"SeDebugPrivilege",&luid);
    TOKEN_PRIVILEGES NewState,PreviousState;
    DWORD ReturnLength;
    NewState.PrivilegeCount =1;
    NewState.Privileges[0].Luid =luid;
    NewState.Privileges[0].Attributes=2;
    return AdjustTokenPrivileges(hToken,FALSE,&NewState,28,&PreviousState,&ReturnLength);
}





int main(int argc, char **argv)
{

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    LPVOID pDll;
    HANDLE hRemoteThread;


    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));

    printf("Hook PoC\n");
    enableDebugPrivileges();
    if(argc != 3)
    {
        printf("Minimum 2 arguments\n");
        return 0;
    }



    if(CreateProcess(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        pDll = VirtualAllocEx(pi.hProcess, NULL, strlen(argv[2])+1, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(pDll)
        {
            if(WriteProcessMemory(pi.hProcess, pDll, argv[2], strlen(argv[2])+1, NULL))
            {
                hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA"), pDll, 0, NULL);
                if(hRemoteThread)
                    printf("CreateRemoteThread() success!\n");
                else
                    printf("CreateRemoteThread() failed\n");
            }


        }
        else
            printf("VirtualAllocEx() failed\n");

        Sleep(1000);
        if(ResumeThread(pi.hThread))
            printf("Process resumed\n");
    }
    else
        printf("CreateProcess() failed\n");

    return 0;
}
