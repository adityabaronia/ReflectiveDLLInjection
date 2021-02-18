# Reflective Injection

**Reflective injection is a technique that allows an attacker to  inject a DLL into a target process from memory rather than disk. ** 

An extra function will be exported in the DLL and that will be **position independent** function. 


## code
    // https://www.youtube.com/watch?v=EZUoCCFVZXQ
    #include <stdio.h>
    #include <Windows.h>
    #include <string.h>
    
    typedef struct _PE_INFO {
      LPVOID base;
      BOOL Reloc; //If base relocation is needed
      LPVOID Get_Proc; //Address of GetProcAddress function 
      LPVOID Load_Dll; //Address of LoadLibraryA
    }PE_INFO, * LPE_INFO;
    
    //2:09 read_in_memory
    
    // This function will find the pid of the target process. Name of the target process will be given by command line argument
    HANDLE Find_Process(const char* processName) {
      HANDLE hSnapshot, hProcess; 
      PROCESSENTRY32 pe;
      pe.dwSize = sizeof(pe);
      BOOL found = 0;
      
      if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
        return 1;
      }
    
      if(!Process32First(hSnapshot, &pe)) {
        return 1;
      }
      
      do {
        if (!strcmp(pe.szExeFile , processName)) {
          found = 1;
          break;
        }
      } while (Process32Next(hSnapshot, &pe));
      
      if (!found) {
        printf("Processnot found\n");
        retrun 1;
      }
      
      if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pe.th32ProcessID)) == NULL) {
        printf("Failed to open process\n");
        return 1;
      }
      
      else 
      retrun hProcess;
    }
    
    
    int main(int argc, char* argv[]) {
      if (argc != 2){
        printf("usage: <process name>");
      }
      
      
    return 0;
    }
