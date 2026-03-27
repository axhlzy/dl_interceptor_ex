# dl_interceptor

[English](README.md) | [中文](README_zh.md)

Android native library + injector that monitors ELF `.init` / `.init_array` and `.fini` / `.fini_array` execution by hooking the linker's `soinfo::call_constructors()` and `soinfo::call_destructors()`.

Provides **pre** and **post** callbacks around constructor/destructor execution, per-entry init_array tracing, breakpoints, and memory dumping — all from a single self-contained binary.

## Features

- Callbacks fire before and after `.init` + `.init_array` (and `.fini` + `.fini_array`)
- Per-entry init_array execution tracing with absolute/relative addresses
- Symbol resolution via xDL (shows function names when available)
- **Breakpoints** — SIGSTOP the process before any init_array entry
- **Memory dump** — dump the .so after relocation at any init_array entry
- **GumTrace Support** — deep execution tracing for specific init functions using `libGumTrace.so`
- **Init array hooks** — replace, skip, or wrap individual init functions with execution time measurement
- Supports **armeabi-v7a**, **arm64-v8a**, **x86**, and **x86_64**
- Supports Android 5.0–16 (API 21–36)
- Runtime `soinfo` struct scanning — no hardcoded offsets, works across AOSP and vendor linkers
- Self-contained inline hook engine (`mini_hook.hpp`)
- Single-binary injector with embedded .so (ptrace-based, no extra files needed)

## Quick Start

# Auto-detects device architecture, builds, pushes, clears logcat, and injects into app
./run.ps1 -p com.example.app -t libfk.so:1
```

## Injector Usage

```
di_injector [options]

Required:
  -p <package>    Target app package name

Optional:
  -b <lib:N>      Breakpoint on init_array entry (1-based index, repeatable)
  -d <lib:N>      Dump .so memory at init_array entry (1-based, repeatable)
  -hk <lib>       Hook all init_array functions of a specific lib and trace execution (use 'all' for all libs)
  -t <lib:N>      Trace a specific init_array execution using GumTrace (1-based, repeatable)
                  Format: libname.so:N | libname.so:* | libname.so
  -a <activity>   Activity to launch (default: auto-detect)
  -w <timeout>    Timeout in ms for process spawn (default: 10000)
  -n              Inject into already running process (don't restart)
  -h              Show help
```

### Examples

```bash
# Basic injection — monitor all library loads
di_injector -p com.example.app

# Breakpoint at libfoo.so's 1st init_array function
di_injector -p com.example.app -b libfoo.so:1
# Resume: kill -CONT <pid>

# Dump libfoo.so memory at 1st init_array entry
di_injector -p com.example.app -d libfoo.so:1
# Output: /data/local/tmp/libfoo.so_dump_1.so

# Breakpoint + dump combined
di_injector -p com.example.app -b libfoo.so:1 -d libfoo.so:1

# Hook all init_array entries of a library to trace execution
di_injector -p com.example.app -hk libfoo.so

# Hook all init_array entries for ALL libraries
di_injector -p com.example.app -hk all

# Trace libfoo.so's 1st init_array function using GumTrace
di_injector -p com.example.app -t libfoo.so:1
# Output: /data/local/tmp/trace/<pkg>/libfoo.so_1_0x<addr>.log

# Break on ALL init_array entries of a library
di_injector -p com.example.app -b libfoo.so:*

# Multiple targets
di_injector -p com.example.app -b libfoo.so:1 -d libbar.so:3
```

### Index Convention

All init_array indices are **1-based**:
- `libfoo.so:1` = first init_array entry
- `libfoo.so:18` = 18th entry
- `libfoo.so:*` or `libfoo.so` = all entries

## How It Works

```
dlopen("libfoo.so")
│
├── Linker maps ELF into memory
├── Linker resolves relocations (fills GOT/PLT)
│
├── >>> PRE callback fires <<<
├── >>> Per-entry init_array hooks (breakpoint/dump/replace) <<<
│
├── Linker runs .init
├── Linker runs .init_array[1], [2], ... [N]
│   (each entry logged with abs/rel address + symbol if available)
│
├── >>> POST callback fires <<<
│
└── dlopen() returns
```

### Injection Flow

1. `am force-stop` → `am start` the target app
2. Poll `/proc` every 5ms to catch the PID at earliest moment
3. `ptrace(ATTACH)` to freeze the process
4. Remote `mmap` + `dlopen` to load `libdl_interceptor.so`
5. Remote `dlsym` + call `dl_interceptor_init()`
6. Remote call `dl_interceptor_set_package_name()` and configuration functions (`set_breakpoint`, `set_tracepoint`, etc.)
7. `ptrace(DETACH)` — process resumes with hooks active
8. If tracing is active, `libGumTrace.so` is loaded in the target and logs to `/data/local/tmp/trace/`

### Offset Discovery

The library uses runtime memory scanning to discover `soinfo` struct field offsets:
1. Uses **xDL** to find `soinfo::call_constructors()` symbol in the linker binary
2. Installs an inline hook at the function entry via `mini_hook.hpp`
3. Loads a tiny dummy `.so` to trigger `call_constructors()`, then scans the `soinfo` memory to discover field offsets by matching known values
4. Works across AOSP and vendor-modified linkers (Samsung, Xiaomi, Huawei, etc.)

## C API

```c
#include "dl_interceptor.h"

// Initialize (call once)
int dl_interceptor_init(void);

// Set package name (required for trace log directory naming)
void dl_interceptor_set_package_name(const char *pkg_name);

// Library load callbacks (pre = before .init, post = after .init_array)
int dl_interceptor_register_dl_init_callback(pre, post, data);
int dl_interceptor_unregister_dl_init_callback(pre, post, data);
int dl_interceptor_register_dl_fini_callback(pre, post, data);
int dl_interceptor_unregister_dl_fini_callback(pre, post, data);

// Per-entry init_array hook (inspect/replace/skip each init function)
int dl_interceptor_register_init_array_hook(hook, data);
int dl_interceptor_unregister_init_array_hook(hook, data);

// Breakpoint (SIGSTOP before init_array entry, 1-based index)
int dl_interceptor_set_breakpoint(lib_name, index);
void dl_interceptor_clear_breakpoints(void);

// Dump .so memory at init_array entry (1-based index)
int dl_interceptor_set_dumppoint(lib_name, index);
void dl_interceptor_clear_dumppoints(void);

// Hook all init_array entries of a library and trace execution
int dl_interceptor_set_hookpoint(const char *lib_name);
void dl_interceptor_clear_hookpoints(void);

// Trace a specific init_array entry using GumTrace
int dl_interceptor_set_tracepoint(const char *lib_name, int index);
void dl_interceptor_clear_tracepoints(void);
```

## Building

### Requirements

- Android NDK (r21+)
- CMake 3.22.1+
- Ninja
- Python 3 (for bin2hex during injector build)

### Build & Run Script

The recommended way to build and run is using the `run.ps1` script. It automatically detects your connected device's architecture via `adb`, builds the matching ABI (if needed), pushes the executable, and runs it with the arguments provided:

```powershell
# Inject into app
./run.ps1 -p com.example.app

# Pass any injector arguments directly
./run.ps1 -p com.example.app -b libfoo.so:1 -d libfoo.so:1
```

If you only need to build manually without running, you can use `build_ndk.ps1`:

```powershell
# Build all ABIs (auto-detects SDK/NDK)
./build_ndk.ps1

# Build specific ABI or clean
./build_ndk.ps1 -Abi arm64-v8a
./build_ndk.ps1 -Clean
```

The script auto-detects paths from:
- `ANDROID_SDK_ROOT` / `ANDROID_HOME` environment variables
- Common install locations (`%LOCALAPPDATA%\Android\Sdk`, `C:\Android\Sdk`, `D:\Android\Sdk`)
- Latest NDK version under `<sdk>/ndk/`
- Latest CMake version under `<sdk>/cmake/`

### As a CMake Subdirectory

```cmake
add_subdirectory(dl_interceptor)
target_link_libraries(your_lib PRIVATE dl_interceptor)
```

## Project Structure

```
dl_interceptor/
├── CMakeLists.txt                 # Library build configuration
├── build_ndk.ps1                  # Build script (auto-detects SDK/NDK)
├── include/
│   └── dl_interceptor.h           # Public C API
├── src/
│   ├── dl_interceptor.cpp         # Core implementation
│   └── mini_hook.hpp              # Header-only inline hook engine
├── injector/
│   ├── CMakeLists.txt             # Injector build (embeds .so via bin2hex)
│   ├── injector.cpp               # ptrace-based injector
│   └── bin2hex.py                 # Binary-to-C-header converter
├── nothing/
│   ├── jni/
│   │   ├── dl_interceptor_nothing.c  # Dummy .so source
│   │   ├── Android.mk
│   │   └── Application.mk
│   └── libs/                      # Prebuilt dummy .so (all ABIs)
└── third_party/
    └── xdl/                       # Symbol resolution library
```

## Output Files

After building, the injector binary is at:
```
build/injector-<abi>/di_injector    # Single binary with embedded .so
```

The injector extracts its embedded `.so` files to `/data/local/tmp/` at runtime. No need to push separate files.

## Notes

- Requires **root** (for ptrace and dlopen into other processes)
- When using `-d` (dump), SELinux is temporarily set to permissive. Restore with `setenforce 1`
- Dump files are written to `/data/local/tmp/<libname>_dump_<N>.so`
- The dummy library `libdl_interceptor_nothing.so` must be accessible at `/data/local/tmp/` (extracted automatically by the injector)
- **Check Logs**: The injector and library log all output, hook traces, and execution details to logcat. You should filter the logs using the `DLInterceptor` tag to see them (e.g., `adb logcat -s DLInterceptor`).

## Acknowledgements

- **[xDL](https://github.com/hexhacking/xDL)**: The excellent symbol resolution library used for `soinfo` dynamic struct scanning and ELF parsing.
- **[GumTrace](https://github.com/lidongyooo/GumTrace)**: The powerful execution tracing library (based on Frida Gum) integrated for deep function tracing.
- **[aimardcr/dl_interceptor](https://github.com/aimardcr/dl_interceptor)**: The original project that inspired and provided foundational ideas for this tool.

## License

MIT
