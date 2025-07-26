# IOCTL Scanner

The IOCTL Scanner is a memory-native tool built for identifying control codes within the `.text` and `PAGE` sections of loaded kernel drivers. It operates directly on raw memory to reveal symbolic IOCTL patterns without relying on import tables or user-mode APIs.

## Features

• Direct scanning of kernel driver sections mapped in memory  
• Identification of IOCTL setup logic using byte-pattern recognition  
• Extraction of literal control codes (`CTL_CODE(...)`) across driver space  
• Symbolic logging of device names and IOCTL addresses  
• Runtime-safe operation without injecting or altering live driver structures

## Use Cases

• Reverse engineering third-party or legacy drivers  
• Tracing user-mode interfaces to kernel behavior  
• Uncovering undocumented device control logic  
• Enhancing reflective debugging and symbolic trace systems

## Sample Output

```bash
\SystemRoot\system32\ntoskrnl.exe
0x 8D 0D 48 B2 8C 00 45 33 C0 48 89 45 - B8 48 8D 15 22 [186] 
0x 05 41 03 F4 EB CE F0 48 0F C1 1D 97 - B8 72 00 40 22 [221]
0x CD E9 85 FD FF FF F0 48 0F C1 1D 0C - B8 72 00 40 22 [221]
```
## Build
```bash
• cl ioctl-scan.c 
```
