// Copyright (c) 2026
// SPDX-License-Identifier: MIT
//
// dl_interceptor - Monitor ELF .init/.init_array and .fini/.fini_array
// execution
//
// Hooks soinfo::call_constructors() and soinfo::call_destructors() in the
// Android linker to provide callbacks before and after ELF
// initialization/finalization.
//
// Supports: Android 5.0+ (API 21+), armeabi-v7a, arm64-v8a, x86, x86_64
// Dependencies: mini_hook (inline hooking), xDL (symbol resolution)

#pragma once

#include <link.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define DI_EXPORT __attribute__((visibility("default")))
#else
#define DI_EXPORT
#endif

// Callback type: receives dl_phdr_info for the ELF being initialized/finalized.
//   info  - ELF program header info (dlpi_addr, dlpi_name, dlpi_phdr,
//   dlpi_phnum) size  - size of the dl_phdr_info struct data  - user-provided
//   opaque pointer from registration
typedef void (*dl_interceptor_callback_t)(struct dl_phdr_info *info,
                                          size_t size, void *data);

// Initialize dl_interceptor. Must be called before registering callbacks.
// Returns 0 on success, -1 on failure.
// Can be called multiple times safely (only initializes once).
DI_EXPORT int dl_interceptor_init(void);

// Register callbacks for ELF .init + .init_array execution.
//   pre  - called AFTER ELF is mapped+relocated, BEFORE .init/.init_array runs
//   (may be NULL) post - called AFTER .init/.init_array finishes (may be NULL)
//   data - opaque pointer passed back to callbacks
// Returns 0 on success, -1 on failure.
DI_EXPORT int dl_interceptor_register_dl_init_callback(
    dl_interceptor_callback_t pre, dl_interceptor_callback_t post, void *data);

// Unregister a previously registered dl_init callback.
// Pass the same pre, post, data used during registration.
// Returns 0 on success, -1 if not found.
DI_EXPORT int dl_interceptor_unregister_dl_init_callback(
    dl_interceptor_callback_t pre, dl_interceptor_callback_t post, void *data);

// Register callbacks for ELF .fini + .fini_array execution.
//   pre  - called BEFORE .fini/.fini_array runs (may be NULL)
//   post - called AFTER .fini/.fini_array finishes (may be NULL)
//   data - opaque pointer passed back to callbacks
// Returns 0 on success, -1 on failure.
DI_EXPORT int dl_interceptor_register_dl_fini_callback(
    dl_interceptor_callback_t pre, dl_interceptor_callback_t post, void *data);

// Unregister a previously registered dl_fini callback.
// Returns 0 on success, -1 if not found.
DI_EXPORT int dl_interceptor_unregister_dl_fini_callback(
    dl_interceptor_callback_t pre, dl_interceptor_callback_t post, void *data);

// ---------------------------------------------------------------------------
// Init/Fini array entry info — passed to init_array hook callbacks
// ---------------------------------------------------------------------------

typedef void (*dl_interceptor_init_func_t)(void);

// Info about a single .init_array / .fini_array entry
struct dl_interceptor_array_entry {
  const char *lib_name; // Library name (e.g. "libfoo.so")
  ElfW(Addr) lib_base;  // Library load bias (base address)
  size_t index;         // Index in the array (0-based)
  size_t total;         // Total entries in the array
  ElfW(Addr) func_abs;  // Absolute address of the function
  ElfW(Addr) func_rel;  // Relative offset from lib_base
};

// Init array hook callback type.
// Called for EACH entry in .init_array BEFORE it executes.
//   entry - info about the current init_array function
//   data  - user-provided opaque pointer
// Return:
//   NULL  - skip this init function (don't execute it)
//   other - execute the returned function pointer instead (can be original or
//   replacement)
typedef dl_interceptor_init_func_t (*dl_interceptor_array_hook_t)(
    const struct dl_interceptor_array_entry *entry, void *data);

// Register a hook for .init_array entries.
// The hook is called for every .init_array function of every library loaded
// after registration. The hook can inspect, replace, or skip each init
// function. Returns 0 on success, -1 on failure.
DI_EXPORT int
dl_interceptor_register_init_array_hook(dl_interceptor_array_hook_t hook,
                                        void *data);

// Unregister a previously registered init_array hook.
// Returns 0 on success, -1 if not found.
DI_EXPORT int
dl_interceptor_unregister_init_array_hook(dl_interceptor_array_hook_t hook,
                                          void *data);

// ---------------------------------------------------------------------------
// Breakpoint on init_array entry
// ---------------------------------------------------------------------------

// Set a breakpoint on a specific init_array entry.
// When the matching library is loaded and the specified init_array index is
// about to execute, the process will SIGSTOP itself, allowing a debugger to
// attach.
//
//   lib_name - library name to match (substring match, e.g. "libfk.so")
//   index    - 1-based index into .init_array (-1 = break on ALL entries)
//
// The process logs the breakpoint hit and stops. To resume:
//   - From shell: kill -CONT <pid>
//   - From debugger: attach and continue
//   - The original init function runs after resume
//
// Returns 0 on success, -1 on failure.
DI_EXPORT int dl_interceptor_set_breakpoint(const char *lib_name, int index);

// Clear all breakpoints.
DI_EXPORT void dl_interceptor_clear_breakpoints(void);

// ---------------------------------------------------------------------------
// Dump .so at init_array entry
// ---------------------------------------------------------------------------

// Set a dump point on a specific init_array entry.
// When the matching init_array function is about to execute, the library's
// memory is dumped to /data/local/tmp/<libname>_dump_<index>.so
//
// This captures the .so AFTER relocation but BEFORE (or at) the specified
// init function runs — useful for dumping unpacked/decrypted code.
//
//   lib_name - library name to match (substring match, e.g. "libfk.so")
//   index    - 1-based index into .init_array (-1 = dump at ALL entries)
//
// Returns 0 on success, -1 on failure.
DI_EXPORT int dl_interceptor_set_dumppoint(const char *lib_name, int index);

// Clear all dump points.
DI_EXPORT void dl_interceptor_clear_dumppoints(void);

// ---------------------------------------------------------------------------
// Hook all init_array entries for a library
// ---------------------------------------------------------------------------

// Apply the generic wrapper hook to all init_array entries of a library.
// This wraps each entry and logs exactly when it starts and finishes executing.
//
//   lib_name - library name to match (e.g. "libutils.so" or "all" for all libs)
//
// Returns 0 on success, -1 on failure.
DI_EXPORT int dl_interceptor_set_hookpoint(const char *lib_name);

// Clear all hook points.
DI_EXPORT void dl_interceptor_clear_hookpoints(void);

#ifdef __cplusplus
}
#endif
