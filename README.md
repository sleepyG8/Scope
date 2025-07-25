# Scope 🔍🧬

**Scope** is a memory-native ritual scanner for uncovering and interpreting the `.text` and `PAGE` sections of loaded kernel drivers on Windows systems. It blends manual PE parsing with undocumented APIs to paint symbolic maps of system modules—highlighting CALL invocations (`0xE8`) like glyphs etched into memory.

---

## 🌀 Purpose

This tool isn't just a utility—it's a ceremonial compass for:

- Tracing execution patterns within `ntoskrnl.exe` and other kernel drivers
- Mapping `CALL` instructions inside `.text` for symbolic debugging and syscall choreography
- Feeding data into reflective loaders, custom debuggers, and stealthy execution frameworks

---

## ⚙️ How It Works

1. Uses `NtQuerySystemInformation` (SystemModuleInformation) to enumerate loaded drivers
2. Locates `ntoskrnl.exe` or target module by symbolic path
3. Parses the PE manually, extracting `.text` and `PAGE` sections
4. Highlights `0xE8` CALL opcodes for syscall tracing or ritual tagging

---

## 🛠️ Build & Run

### 🔧 Requirements
- Windows (x64)
- C compiler

### 📦 Compile
```bash
cl scope.c
```
### Usage:
- scope.exe <\SystemRoot\system32\ntoskrnl.exe> (Any target module)
