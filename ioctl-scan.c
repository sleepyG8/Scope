#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

////////////////////////////////////////////////////////////
//                      IOCTL-Scan                        //
//                        Sleepy                          //
//                         2025                           //                   
////////////////////////////////////////////////////////////

// Compile: cl ioctl-scan.c 

// Use for finding possible attack paths in drivers

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)


typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;         // Handle to the module section
    PVOID MappedBase;       // Base address in memory
    PVOID ImageBase;        // Load address of the driver
    ULONG ImageSize;        // Size of the loaded module
    ULONG Flags;            // Flags (e.g., kernel mode module)
    USHORT LoadOrderIndex;  // Load order
    USHORT InitOrderIndex;  // Initialization order
    USHORT LoadCount;       // Reference count
    USHORT PathLength;      // Length of the driver path string
    CHAR FullPathName[256]; // Full module path
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;  // Total count of loaded drivers
    RTL_PROCESS_MODULE_INFORMATION Modules[1]; // Array of modules
} RTL_PROCESS_MODULES;

BOOL getText(const char* fullPath) {
     FILE* dataFile = fopen(fullPath, "rb");

    if (!dataFile) {
        printf("Error reading file\n");
        return 1;
    }
  
    fseek(dataFile, 0, SEEK_END);
    size_t size = ftell(dataFile);
    fseek(dataFile, 0, SEEK_SET);

    BYTE* buff = malloc(size);

    if (!fread(buff, 1, size, dataFile )) {
    printf("error\n");
    return 1;
    }

   // for (int i=0; i < size; i++) {
    //printf("\\0x%02x", buff[i]);
    //}

   // printf("Done.\n");

   // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buff;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
       printf("Invalid NT headers\n");
        return FALSE;
    }


    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {

    SIZE_T rawSize = section->SizeOfRawData;

   // printf("section: %s\n", section->Name);
    if (strcmp(section->Name, "PAGE") == 0 || strcmp(section->Name, ".text") == 0) {
    
      //  printf("Mapped section: %.*s\n", 8, section->Name);

        if (memcmp(section->Name, ".text", 5) == 0) {
        BYTE* textStart = (BYTE*)buff + section->VirtualAddress;
        SIZE_T textSize = section->Misc.VirtualSize;  // More accurate than SizeOfRawData
        DWORD oldProtect = 0;
       // printf(".text start: %x\n", textStart);
       // printf("size: %lu\n", section->SizeOfRawData);


       for (int i=0; i < textSize; i++) {


            if (textStart[i] == 0xB8) {
                DWORD ioctlCode = *(DWORD*)&textStart[i + 1];

                if ((ioctlCode & 0xFF000000) == 0x22000000 || (ioctlCode >= 0x220000 && ioctlCode <= 0x22FFFF)) {
                    printf("\x1b[32m0x %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X - %02X %02X %02X %02X %02X [%d] \x1b[0m\n", textStart[i - 12], textStart[i - 11], textStart[i - 10], textStart[i - 9], textStart[i - 8], textStart[i - 7], textStart[i - 6], textStart[i - 5], textStart[i - 4], textStart[i - 3], textStart[i - 2], textStart[i - 1], textStart[i], textStart[i + 1], textStart[i + 2], textStart[i + 3], textStart[i + 4], textStart[i + 5], i);
                    continue;
                    }
                 }


            //printf("0x%02X, ", textStart[i]);
           
        }
    }
    
}
}
return TRUE;
}

int main(int argc, char* argv[]) {

    //usual getting handle for undocumented function
        HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return 1;
    }

    //set the struct data from p* to actual Nt name that is = to the Nt name in the dll
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQueryInformationProcess\n");
        return 1;
    }

    //getting the size thats why NULL and 0 it saves as returnLen
    ULONG returnLen = 0;
    NTSTATUS status = NtQuerySystemInformation(11, NULL, 0, &returnLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        printf("Error 0x%X", status);
        return 1;
    }

    //alloc modules
    RTL_PROCESS_MODULES *modules = (RTL_PROCESS_MODULES*)malloc(returnLen);

    //actual call to 
    status = NtQuerySystemInformation(11, modules, returnLen, &returnLen);
    if (status != STATUS_SUCCESS) {
        printf("Error 0x%X", status);
        return 1;
    }

    printf("Number of modules %lu\n", modules->NumberOfModules);

    char buffer[256];
    printf("Getting drivers");

    for (int i = 0; i < 5; i++) {
        printf(".");
        Sleep(200);
    }
    printf("\n");

    BOOL dirty = FALSE;
    //getting the names from the buffer
    
        for (int i=0; i < modules->NumberOfModules; i++) {
       
        printf("%s\n", (char*)modules->Modules[i].FullPathName);

        char path[100];
    const char* systemRoot = "C:\\Windows\\";
    const char* symbolicPath = (char*)modules->Modules[i].FullPathName;

    snprintf(path, sizeof(path), "%s%s", systemRoot, symbolicPath + 11);
        if (!getText((path))) {
            printf("Failed getting: %s\n", (char*)modules->Modules[i].FullPathName);
        }

        
    }

        return 0;
    }

