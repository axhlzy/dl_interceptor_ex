// Copyright (c) 2026
// SPDX-License-Identifier: MIT
//
// dl_interceptor - Monitor ELF .init/.init_array and .fini/.fini_array execution
//
// Implementation: hooks soinfo::call_constructors() and soinfo::call_destructors()
// in the Android linker via DobbyHook. Uses xDL for symbol resolution and runtime
// memory scanning to discover soinfo struct field offsets (vendor-independent).

#include "dl_interceptor.h"

#include <android/api-level.h>
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <atomic>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "mini_hook.hpp"
#include "xdl.h"

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#define DI_TAG "DLInterceptor"
#define DI_LOGI(...) __android_log_print(ANDROID_LOG_INFO, DI_TAG, __VA_ARGS__)
#define DI_LOGW(...) __android_log_print(ANDROID_LOG_WARN, DI_TAG, __VA_ARGS__)
#define DI_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, DI_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#ifndef __LP64__
#define DI_LINKER_BASENAME "linker"
#else
#define DI_LINKER_BASENAME "linker64"
#endif

// The dummy .so used for soinfo memory scanning.
// This must be a real .so that can be dlopen'd. It can be an empty library
// from your project — just needs to exist in the APK's lib/<abi>/ folder.
// If you don't have one, create a .so with a single unused symbol.
#ifndef DI_DUMMY_LIB_NAME
#define DI_DUMMY_LIB_NAME "libdl_interceptor_nothing.so"
#endif

// Symbol names for soinfo::call_constructors / call_destructors
// Android L (5.0-5.1): CamelCase
#define DI_SYM_CALL_CTORS_L "__dl__ZN6soinfo16CallConstructorsEv"
#define DI_SYM_CALL_DTORS_L "__dl__ZN6soinfo15CallDestructorsEv"
// Android M+ (6.0+): snake_case
#define DI_SYM_CALL_CTORS_M "__dl__ZN6soinfo17call_constructorsEv"
#define DI_SYM_CALL_DTORS_M "__dl__ZN6soinfo16call_destructorsEv"

// Max scan depth for soinfo struct (in pointer-sized words)
#define DI_SOINFO_SCAN_WORDS 128

// ---------------------------------------------------------------------------
// Callback list (intrusive singly-linked list with rwlock)
// ---------------------------------------------------------------------------

struct di_callback {
    dl_interceptor_callback_t pre;
    dl_interceptor_callback_t post;
    void *data;
    di_callback *next;
};

struct di_callback_list {
    di_callback *head;
    pthread_rwlock_t lock;
};

static void di_cb_list_init(di_callback_list *list) {
    list->head = nullptr;
    pthread_rwlock_init(&list->lock, nullptr);
}

static int di_cb_list_add(di_callback_list *list, dl_interceptor_callback_t pre,
                          dl_interceptor_callback_t post, void *data) {
    auto *cb = static_cast<di_callback *>(malloc(sizeof(di_callback)));
    if (!cb) return -1;
    cb->pre = pre;
    cb->post = post;
    cb->data = data;

    pthread_rwlock_wrlock(&list->lock);

    // Check for duplicates
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->pre == pre && cur->post == post && cur->data == data) {
            pthread_rwlock_unlock(&list->lock);
            free(cb);
            return -1;  // duplicate
        }
    }

    cb->next = list->head;
    list->head = cb;
    pthread_rwlock_unlock(&list->lock);
    return 0;
}

static int di_cb_list_remove(di_callback_list *list, dl_interceptor_callback_t pre,
                             dl_interceptor_callback_t post, void *data) {
    pthread_rwlock_wrlock(&list->lock);

    di_callback **pp = &list->head;
    while (*pp) {
        di_callback *cur = *pp;
        if (cur->pre == pre && cur->post == post && cur->data == data) {
            *pp = cur->next;
            pthread_rwlock_unlock(&list->lock);
            free(cur);
            return 0;
        }
        pp = &cur->next;
    }

    pthread_rwlock_unlock(&list->lock);
    return -1;  // not found
}

static void di_cb_list_invoke_pre(di_callback_list *list, struct dl_phdr_info *info, size_t size) {
    pthread_rwlock_rdlock(&list->lock);
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->pre) cur->pre(info, size, cur->data);
    }
    pthread_rwlock_unlock(&list->lock);
}

static void di_cb_list_invoke_post(di_callback_list *list, struct dl_phdr_info *info, size_t size) {
    pthread_rwlock_rdlock(&list->lock);
    for (di_callback *cur = list->head; cur; cur = cur->next) {
        if (cur->post) cur->post(info, size, cur->data);
    }
    pthread_rwlock_unlock(&list->lock);
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static di_callback_list g_init_cbs;
static di_callback_list g_fini_cbs;

// Init array hook list
struct di_array_hook {
    dl_interceptor_array_hook_t hook;
    void *data;
    di_array_hook *next;
};

struct di_array_hook_list {
    di_array_hook *head;
    pthread_rwlock_t lock;
};

static di_array_hook_list g_init_array_hooks;

static void di_array_hook_list_init(di_array_hook_list *list) {
    list->head = nullptr;
    pthread_rwlock_init(&list->lock, nullptr);
}

static int di_array_hook_list_add(di_array_hook_list *list, dl_interceptor_array_hook_t hook, void *data) {
    auto *h = static_cast<di_array_hook *>(malloc(sizeof(di_array_hook)));
    if (!h) return -1;
    h->hook = hook;
    h->data = data;
    pthread_rwlock_wrlock(&list->lock);
    for (di_array_hook *cur = list->head; cur; cur = cur->next) {
        if (cur->hook == hook && cur->data == data) {
            pthread_rwlock_unlock(&list->lock);
            free(h);
            return -1;
        }
    }
    h->next = list->head;
    list->head = h;
    pthread_rwlock_unlock(&list->lock);
    return 0;
}

static int di_array_hook_list_remove(di_array_hook_list *list, dl_interceptor_array_hook_t hook, void *data) {
    pthread_rwlock_wrlock(&list->lock);
    di_array_hook **pp = &list->head;
    while (*pp) {
        di_array_hook *cur = *pp;
        if (cur->hook == hook && cur->data == data) {
            *pp = cur->next;
            pthread_rwlock_unlock(&list->lock);
            free(cur);
            return 0;
        }
        pp = &cur->next;
    }
    pthread_rwlock_unlock(&list->lock);
    return -1;
}

// soinfo field offsets discovered at runtime
static size_t g_off_load_bias = SIZE_MAX;
static size_t g_off_name = SIZE_MAX;
static size_t g_off_phdr = SIZE_MAX;
static size_t g_off_phnum = SIZE_MAX;
static size_t g_off_constructors_called = SIZE_MAX;

static std::atomic<bool> g_offsets_ready{false};
static std::atomic<pid_t> g_scan_tid{0};

// Original function pointers (set by DobbyHook)
static void (*g_orig_call_constructors)(void *soinfo) = nullptr;
static void (*g_orig_call_destructors)(void *soinfo) = nullptr;

// ---------------------------------------------------------------------------
// API level helper
// ---------------------------------------------------------------------------

static int di_get_api_level() {
    static int level = -1;
    if (level >= 0) return level;
    level = android_get_device_api_level();
    if (level < 0) {
        // Fallback: read from build.prop
        char buf[16] = {};
        __system_property_get("ro.build.version.sdk", buf);
        level = atoi(buf);
    }
    if (level < __ANDROID_API_L__) level = __ANDROID_API_L__;
    return level;
}

// ---------------------------------------------------------------------------
// soinfo → dl_phdr_info conversion
// ---------------------------------------------------------------------------

static bool di_soinfo_is_loading(void *soinfo) {
    auto val = *reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
    return val == 0;
}

static void di_soinfo_to_dlinfo(void *soinfo, struct dl_phdr_info *info) {
    auto base = reinterpret_cast<uintptr_t>(soinfo);
    info->dlpi_addr = *reinterpret_cast<ElfW(Addr) *>(base + g_off_load_bias);
    info->dlpi_name = *reinterpret_cast<const char **>(base + g_off_name);
    info->dlpi_phdr = *reinterpret_cast<const ElfW(Phdr) **>(base + g_off_phdr);
    info->dlpi_phnum = static_cast<ElfW(Half)>(*reinterpret_cast<size_t *>(base + g_off_phnum));
}

// ---------------------------------------------------------------------------
// soinfo memory scanning — discover field offsets at runtime
// ---------------------------------------------------------------------------

static int di_soinfo_scan_pre(void *soinfo) {
    // Open the dummy lib via xDL to get its known values
    void *handle = xdl_open(DI_DUMMY_LIB_NAME, XDL_DEFAULT);
    if (!handle) {
        DI_LOGE("scan: xdl_open(%s) failed", DI_DUMMY_LIB_NAME);
        return -1;
    }

    xdl_info_t dlinfo;
    xdl_info(handle, XDL_DI_DLINFO, &dlinfo);

    // Find PT_DYNAMIC vaddr
    uintptr_t l_ld = UINTPTR_MAX;
    for (size_t i = 0; i < dlinfo.dlpi_phnum; i++) {
        if (dlinfo.dlpi_phdr[i].p_type == PT_DYNAMIC) {
            l_ld = reinterpret_cast<uintptr_t>(dlinfo.dli_fbase) + dlinfo.dlpi_phdr[i].p_vaddr;
            break;
        }
    }
    if (l_ld == UINTPTR_MAX) {
        DI_LOGE("scan: PT_DYNAMIC not found in %s", DI_DUMMY_LIB_NAME);
        xdl_close(handle);
        return -1;
    }

    auto si = reinterpret_cast<uintptr_t>(soinfo);
    auto known_phdr = reinterpret_cast<uintptr_t>(dlinfo.dlpi_phdr);
    auto known_phnum = static_cast<uintptr_t>(dlinfo.dlpi_phnum);
    auto known_load_bias = reinterpret_cast<uintptr_t>(dlinfo.dli_fbase);

    // Scan soinfo memory for known patterns
    for (size_t i = 0; i < sizeof(uintptr_t) * DI_SOINFO_SCAN_WORDS; i += sizeof(uintptr_t)) {
        if (g_off_phdr != SIZE_MAX && g_off_load_bias != SIZE_MAX)
            break;  // found everything

        uintptr_t v0 = *reinterpret_cast<uintptr_t *>(si + i);
        uintptr_t v1 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t));
        uintptr_t v2 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 2);
        uintptr_t v5 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 5);
        uintptr_t v6 = *reinterpret_cast<uintptr_t *>(si + i + sizeof(uintptr_t) * 6);

        // Pattern 1: phdr, phnum adjacent
        if (g_off_phdr == SIZE_MAX && v0 == known_phdr && v1 == known_phnum) {
            g_off_phdr = i;
            g_off_phnum = i + sizeof(uintptr_t);
            i += sizeof(uintptr_t);
            continue;
        }

        // Pattern 2: link_map layout: load_bias, l_name, l_ld, l_next, l_prev(0), load_bias_again
        // Matches: load_bias == dli_fbase, l_ld == PT_DYNAMIC addr, l_prev == 0, load_bias field == load_bias
        if (g_off_load_bias == SIZE_MAX && v0 == known_load_bias && v2 == l_ld && v5 == 0 &&
            v6 == known_load_bias) {
            // Verify l_name points to a string ending with our dummy lib name
            auto l_name = reinterpret_cast<const char *>(v1);
            size_t dummy_len = strlen(DI_DUMMY_LIB_NAME);
            size_t name_len = strlen(l_name);
            if (name_len >= dummy_len &&
                strcmp(l_name + name_len - dummy_len, DI_DUMMY_LIB_NAME) == 0) {
                g_off_load_bias = i;
                g_off_name = i + sizeof(uintptr_t);
                // constructors_called is at a known offset from the link_map fields
                // In AOSP: link_map { l_addr, l_name, l_ld, l_next, l_prev } then constructors_called
                g_off_constructors_called = i + sizeof(uintptr_t) * 5;
                i += sizeof(uintptr_t) * 6;
                continue;
            }
        }
    }

    xdl_close(handle);

    if (g_off_load_bias == SIZE_MAX || g_off_name == SIZE_MAX || g_off_phdr == SIZE_MAX ||
        g_off_phnum == SIZE_MAX || g_off_constructors_called == SIZE_MAX) {
        DI_LOGE("scan: failed to discover offsets (load_bias=%zu, name=%zu, phdr=%zu, phnum=%zu, called=%zu)",
                g_off_load_bias, g_off_name, g_off_phdr, g_off_phnum, g_off_constructors_called);
        return -1;
    }

    DI_LOGI("scan: offsets discovered (load_bias=%zu, name=%zu, phdr=%zu, phnum=%zu, called=%zu)",
            g_off_load_bias, g_off_name, g_off_phdr, g_off_phnum, g_off_constructors_called);
    return 0;
}

static void di_soinfo_scan_post(void *soinfo) {
    auto val = *reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
    if (val != 0) {
        g_offsets_ready.store(true, std::memory_order_release);
        DI_LOGI("scan: post-verification OK, offsets confirmed");
    } else {
        DI_LOGE("scan: post-verification FAILED, constructors_called still 0");
    }
}

// ---------------------------------------------------------------------------
// Proxy functions for soinfo::call_constructors / call_destructors
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Symbol resolution helper
// ---------------------------------------------------------------------------

static const char *di_resolve_symbol(void *addr) {
    xdl_info_t info;
    void *cache = nullptr;
    if (xdl_addr(addr, &info, &cache) == 0 && info.dli_sname != nullptr) {
        xdl_addr_clean(&cache);
        return info.dli_sname;
    }
    xdl_addr_clean(&cache);
    return nullptr;
}

// Parse ELF dynamic section to log .init / .init_array details
static void di_log_init_details(const struct dl_phdr_info *info) {
    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Phdr) *phdr = info->dlpi_phdr;
    ElfW(Half) phnum = info->dlpi_phnum;

    // Find PT_DYNAMIC
    const ElfW(Dyn) *dyn = nullptr;
    for (ElfW(Half) i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn) *>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return;

    ElfW(Addr) init_func = 0;
    ElfW(Addr) init_array = 0;
    size_t init_arraysz = 0;
    ElfW(Addr) fini_func = 0;
    ElfW(Addr) fini_array = 0;
    size_t fini_arraysz = 0;

    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_INIT:          init_func    = d->d_un.d_ptr; break;
            case DT_INIT_ARRAY:    init_array   = d->d_un.d_ptr; break;
            case DT_INIT_ARRAYSZ:  init_arraysz = d->d_un.d_val; break;
            case DT_FINI:          fini_func    = d->d_un.d_ptr; break;
            case DT_FINI_ARRAY:    fini_array   = d->d_un.d_ptr; break;
            case DT_FINI_ARRAYSZ:  fini_arraysz = d->d_un.d_val; break;
        }
    }

    if (init_func) {
        ElfW(Addr) abs_addr = base + init_func;
        const char *sym = di_resolve_symbol((void *)abs_addr);
        DI_LOGI("  .init          : abs=0x%" PRIxPTR " rel=0x%" PRIxPTR " %s",
                (uintptr_t)abs_addr, (uintptr_t)init_func, sym ? sym : "");
    }

    if (init_array && init_arraysz) {
        size_t count = init_arraysz / sizeof(ElfW(Addr));
        auto *arr = reinterpret_cast<const ElfW(Addr) *>(base + init_array);
        DI_LOGI("  .init_array    : %zu entries at rel=0x%" PRIxPTR, count, (uintptr_t)init_array);
        for (size_t i = 0; i < count; i++) {
            ElfW(Addr) func = arr[i];
            if (func == 0) continue;
            ElfW(Addr) rel = func - base;
            const char *sym = di_resolve_symbol((void *)func);
            if (sym)
                DI_LOGI("    [%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR " %s", i, (uintptr_t)func, (uintptr_t)rel, sym);
            else
                DI_LOGI("    [%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR, i, (uintptr_t)func, (uintptr_t)rel);
        }
    }

    if (fini_func) {
        ElfW(Addr) abs_addr = base + fini_func;
        const char *sym = di_resolve_symbol((void *)abs_addr);
        DI_LOGI("  .fini          : abs=0x%" PRIxPTR " rel=0x%" PRIxPTR " %s",
                (uintptr_t)abs_addr, (uintptr_t)fini_func, sym ? sym : "");
    }

    if (fini_array && fini_arraysz) {
        size_t count = fini_arraysz / sizeof(ElfW(Addr));
        auto *arr = reinterpret_cast<const ElfW(Addr) *>(base + fini_array);
        DI_LOGI("  .fini_array    : %zu entries at rel=0x%" PRIxPTR, count, (uintptr_t)fini_array);
        for (size_t i = 0; i < count; i++) {
            ElfW(Addr) func = arr[i];
            if (func == 0) continue;
            ElfW(Addr) rel = func - base;
            const char *sym = di_resolve_symbol((void *)func);
            if (sym)
                DI_LOGI("    [%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR " %s", i, (uintptr_t)func, (uintptr_t)rel, sym);
            else
                DI_LOGI("    [%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR, i, (uintptr_t)func, (uintptr_t)rel);
        }
    }
}

// Apply init_array hooks: let user hooks inspect/replace/skip each entry.
// Patches the init_array in-place (temporarily), returns backup for restore.
// Caller must free the returned backup array.
// Thread-locals set here for hooks to read
static thread_local const ElfW(Phdr) *g_current_phdr = nullptr;
static thread_local ElfW(Half) g_current_phnum = 0;

static ElfW(Addr) *di_apply_init_array_hooks(const struct dl_phdr_info *info) {
    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Phdr) *phdr = info->dlpi_phdr;
    ElfW(Half) phnum = info->dlpi_phnum;

    // Make phdr available to hooks via thread-local
    g_current_phdr = phdr;
    g_current_phnum = phnum;

    // Check if any hooks are registered
    pthread_rwlock_rdlock(&g_init_array_hooks.lock);
    bool has_hooks = (g_init_array_hooks.head != nullptr);
    pthread_rwlock_unlock(&g_init_array_hooks.lock);
    if (!has_hooks) return nullptr;

    // Find PT_DYNAMIC → DT_INIT_ARRAY + DT_INIT_ARRAYSZ
    const ElfW(Dyn) *dyn = nullptr;
    for (ElfW(Half) i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn) *>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return nullptr;

    ElfW(Addr) init_array_off = 0;
    size_t init_arraysz = 0;
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_INIT_ARRAY)   init_array_off = d->d_un.d_ptr;
        if (d->d_tag == DT_INIT_ARRAYSZ) init_arraysz   = d->d_un.d_val;
    }
    if (!init_array_off || !init_arraysz) return nullptr;

    size_t count = init_arraysz / sizeof(ElfW(Addr));
    auto *arr = reinterpret_cast<ElfW(Addr) *>(base + init_array_off);

    // Backup original array
    auto *backup = static_cast<ElfW(Addr) *>(malloc(count * sizeof(ElfW(Addr))));
    if (!backup) return nullptr;
    memcpy(backup, arr, count * sizeof(ElfW(Addr)));

    // Make the init_array page writable (it's in a RELRO segment on newer Android)
    uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)arr & ~(page_size - 1);
    size_t region_size = ((uintptr_t)arr + count * sizeof(ElfW(Addr)) - page_start + page_size - 1) & ~(page_size - 1);
    mprotect((void *)page_start, region_size, PROT_READ | PROT_WRITE);

    // Call hooks for each entry
    pthread_rwlock_rdlock(&g_init_array_hooks.lock);
    for (size_t i = 0; i < count; i++) {
        ElfW(Addr) orig_func = arr[i];
        if (orig_func == 0) continue;

        struct dl_interceptor_array_entry entry;
        entry.lib_name = info->dlpi_name;
        entry.lib_base = base;
        entry.index    = i;
        entry.total    = count;
        entry.func_abs = orig_func;
        entry.func_rel = orig_func - base;

        // Let each hook process the entry; last hook wins
        dl_interceptor_init_func_t replacement = reinterpret_cast<dl_interceptor_init_func_t>(orig_func);
        for (di_array_hook *h = g_init_array_hooks.head; h; h = h->next) {
            dl_interceptor_init_func_t result = h->hook(&entry, h->data);
            if (result == nullptr) {
                // Skip: replace with a no-op (set to 0, linker skips null entries)
                replacement = nullptr;
                break;
            }
            replacement = result;
        }
        arr[i] = reinterpret_cast<ElfW(Addr)>(replacement);
    }
    pthread_rwlock_unlock(&g_init_array_hooks.lock);

    return backup;
}

// Restore init_array from backup after call_constructors has run
static void di_restore_init_array(const struct dl_phdr_info *info, ElfW(Addr) *backup) {
    if (!backup) return;

    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Phdr) *phdr = info->dlpi_phdr;
    ElfW(Half) phnum = info->dlpi_phnum;

    const ElfW(Dyn) *dyn = nullptr;
    for (ElfW(Half) i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn) *>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) { free(backup); return; }

    ElfW(Addr) init_array_off = 0;
    size_t init_arraysz = 0;
    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_INIT_ARRAY)   init_array_off = d->d_un.d_ptr;
        if (d->d_tag == DT_INIT_ARRAYSZ) init_arraysz   = d->d_un.d_val;
    }

    if (init_array_off && init_arraysz) {
        size_t count = init_arraysz / sizeof(ElfW(Addr));
        auto *arr = reinterpret_cast<ElfW(Addr) *>(base + init_array_off);
        memcpy(arr, backup, count * sizeof(ElfW(Addr)));
        // Restore RELRO protection
        uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
        uintptr_t page_start = (uintptr_t)arr & ~(page_size - 1);
        size_t region_size = ((uintptr_t)arr + count * sizeof(ElfW(Addr)) - page_start + page_size - 1) & ~(page_size - 1);
        mprotect((void *)page_start, region_size, PROT_READ);
    }
    free(backup);
}

static void proxy_call_constructors(void *soinfo) {
    pid_t scan_tid = g_scan_tid.load(std::memory_order_acquire);

    if (scan_tid == 0) {
        // Normal path: offsets are ready, invoke user callbacks
        if (g_offsets_ready.load(std::memory_order_relaxed)) {
            if (di_soinfo_is_loading(soinfo)) {
                struct dl_phdr_info info = {};
                di_soinfo_to_dlinfo(soinfo, &info);
                DI_LOGI("ctors: pre  [%s] load_bias=0x%" PRIxPTR, info.dlpi_name, (uintptr_t)info.dlpi_addr);
                di_log_init_details(&info);
                di_cb_list_invoke_pre(&g_init_cbs, &info, sizeof(info));

                // Apply init_array hooks (patch in-place before linker runs them)
                ElfW(Addr) *backup = di_apply_init_array_hooks(&info);

                g_orig_call_constructors(soinfo);

                // Restore original init_array
                di_restore_init_array(&info, backup);

                DI_LOGI("ctors: post [%s]", info.dlpi_name);
                di_cb_list_invoke_post(&g_init_cbs, &info, sizeof(info));
                return;
            }
        }
    } else if (gettid() == scan_tid) {
        // Scanning path: this is our dummy .so being loaded
        bool scan_ok = (di_soinfo_scan_pre(soinfo) == 0);

        g_orig_call_constructors(soinfo);

        if (scan_ok) {
            di_soinfo_scan_post(soinfo);
        }
        return;
    }

    // Fallback: just call original
    g_orig_call_constructors(soinfo);
}

static void proxy_call_destructors(void *soinfo) {
    if (g_offsets_ready.load(std::memory_order_relaxed) &&
        g_scan_tid.load(std::memory_order_acquire) == 0) {
        auto val =
            *reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(soinfo) + g_off_constructors_called);
        if (val != 0) {
            struct dl_phdr_info info = {};
            di_soinfo_to_dlinfo(soinfo, &info);

            // Ignore: call_destructors() during failed load (constructors_called == 0, name/addr == 0)
            if (info.dlpi_addr != 0 && info.dlpi_name != nullptr) {
                DI_LOGI("dtors: pre  [%s]", info.dlpi_name);
                di_cb_list_invoke_pre(&g_fini_cbs, &info, sizeof(info));

                g_orig_call_destructors(soinfo);

                DI_LOGI("dtors: post [%s]", info.dlpi_name);
                di_cb_list_invoke_post(&g_fini_cbs, &info, sizeof(info));
                return;
            }
        }
    }

    g_orig_call_destructors(soinfo);
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

static int di_hook_linker() {
    int api = di_get_api_level();

    // Open linker via xDL (bypasses namespace restrictions)
    void *linker = xdl_open(DI_LINKER_BASENAME, XDL_DEFAULT);
    if (!linker) {
        DI_LOGE("hook: xdl_open(%s) failed", DI_LINKER_BASENAME);
        return -1;
    }

    // Resolve soinfo::call_constructors
    const char *ctors_sym = (api >= __ANDROID_API_M__) ? DI_SYM_CALL_CTORS_M : DI_SYM_CALL_CTORS_L;
    void *ctors_addr = xdl_dsym(linker, ctors_sym, nullptr);

    // Resolve soinfo::call_destructors
    const char *dtors_sym = (api >= __ANDROID_API_M__) ? DI_SYM_CALL_DTORS_M : DI_SYM_CALL_DTORS_L;
    void *dtors_addr = xdl_dsym(linker, dtors_sym, nullptr);

    xdl_close(linker);

    if (!ctors_addr || !dtors_addr) {
        DI_LOGE("hook: symbol resolution failed (ctors=%p [%s], dtors=%p [%s])",
                ctors_addr, ctors_sym, dtors_addr, dtors_sym);
        return -1;
    }
    DI_LOGI("hook: resolved %s @ %p", ctors_sym, ctors_addr);
    DI_LOGI("hook: resolved %s @ %p", dtors_sym, dtors_addr);

    // Hook with mini_hook
    if (mini_hook_install(ctors_addr, reinterpret_cast<void *>(proxy_call_constructors),
                          reinterpret_cast<void **>(&g_orig_call_constructors)) != 0) {
        DI_LOGE("hook: mini_hook_install(call_constructors) failed");
        return -1;
    }

    if (mini_hook_install(dtors_addr, reinterpret_cast<void *>(proxy_call_destructors),
                          reinterpret_cast<void **>(&g_orig_call_destructors)) != 0) {
        DI_LOGE("hook: mini_hook_install(call_destructors) failed");
        return -1;
    }

    DI_LOGI("hook: linker hooks installed successfully");
    return 0;
}

static int di_discover_offsets() {
    // Tell the proxy we're scanning (use our tid as the marker)
    g_scan_tid.store(gettid(), std::memory_order_release);

    // Load the dummy library — this triggers call_constructors, which runs our scan
    DI_LOGI("scan: loading dummy lib %s", DI_DUMMY_LIB_NAME);
    void *handle = dlopen(DI_DUMMY_LIB_NAME, RTLD_NOW);
    if (handle) dlclose(handle);

    // Done scanning
    g_scan_tid.store(0, std::memory_order_release);

    if (!handle) {
        DI_LOGE("scan: dlopen(%s) failed", DI_DUMMY_LIB_NAME);
        return -1;
    }
    if (!g_offsets_ready.load(std::memory_order_acquire)) {
        DI_LOGE("scan: offset discovery failed after dlopen");
        return -1;
    }

    return 0;
}

int dl_interceptor_init(void) {
    static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    static int init_result = -1;
    static bool inited = false;

    if (inited) return init_result;

    pthread_mutex_lock(&init_lock);
    if (!inited) {
        inited = true;
        di_cb_list_init(&g_init_cbs);
        di_cb_list_init(&g_fini_cbs);
        di_array_hook_list_init(&g_init_array_hooks);

        DI_LOGI("init: starting (API level %d)", di_get_api_level());
        if (di_hook_linker() == 0 && di_discover_offsets() == 0) {
            init_result = 0;
            DI_LOGI("init: success");
        } else {
            DI_LOGE("init: failed");
        }
    }
    pthread_mutex_unlock(&init_lock);

    return init_result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int dl_interceptor_register_dl_init_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data) {
    if (!pre && !post) return -1;
    return di_cb_list_add(&g_init_cbs, pre, post, data);
}

int dl_interceptor_unregister_dl_init_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data) {
    return di_cb_list_remove(&g_init_cbs, pre, post, data);
}

int dl_interceptor_register_dl_fini_callback(dl_interceptor_callback_t pre,
                                             dl_interceptor_callback_t post, void *data) {
    if (!pre && !post) return -1;
    return di_cb_list_add(&g_fini_cbs, pre, post, data);
}

int dl_interceptor_unregister_dl_fini_callback(dl_interceptor_callback_t pre,
                                               dl_interceptor_callback_t post, void *data) {
    return di_cb_list_remove(&g_fini_cbs, pre, post, data);
}

int dl_interceptor_register_init_array_hook(dl_interceptor_array_hook_t hook, void *data) {
    if (!hook) return -1;
    return di_array_hook_list_add(&g_init_array_hooks, hook, data);
}

int dl_interceptor_unregister_init_array_hook(dl_interceptor_array_hook_t hook, void *data) {
    return di_array_hook_list_remove(&g_init_array_hooks, hook, data);
}

// ---------------------------------------------------------------------------
// Breakpoint implementation
// ---------------------------------------------------------------------------

#define DI_MAX_BREAKPOINTS 32
#define DI_MAX_INIT_ENTRIES 1024

struct di_breakpoint {
    char lib_name[128];
    int  index;           // -1 = all entries (stored as 0-based internally)
    bool active;
};

static di_breakpoint g_breakpoints[DI_MAX_BREAKPOINTS];
static di_breakpoint g_dumppoints[DI_MAX_BREAKPOINTS];
static pthread_mutex_t g_bp_lock = PTHREAD_MUTEX_INITIALIZER;

// Wrapper context table — stores per-entry info for the wrapper functions.
// init_array functions run sequentially on one thread per library, so we
// use a static table indexed by init_array index. Before call_constructors
// runs, we populate the table; the wrappers read from it.
struct di_wrapper_ctx {
    dl_interceptor_init_func_t orig_func;
    const char *lib_name;
    ElfW(Addr) lib_base;
    size_t index;
    size_t total;
    ElfW(Addr) func_abs;
    ElfW(Addr) func_rel;
    bool is_breakpoint;
    bool is_dumppoint;
    // phdr info for dump
    const ElfW(Phdr) *phdr;
    ElfW(Half) phnum;
};

static thread_local di_wrapper_ctx g_wrapper_table[DI_MAX_INIT_ENTRIES];
static thread_local size_t g_wrapper_current = 0;

// Dump a library's memory to file using PT_LOAD segments
static void di_dump_library(const di_wrapper_ctx *ctx) {
    const char *short_name = strrchr(ctx->lib_name, '/');
    short_name = short_name ? short_name + 1 : ctx->lib_name;

    char dump_path[512];
    snprintf(dump_path, sizeof(dump_path), "/data/local/tmp/%s_dump_%zu.so",
             short_name, ctx->index + 1);

    int fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        DI_LOGE("  dump: open(%s) failed: %s", dump_path, strerror(errno));
        return;
    }

    // Find the extent of all PT_LOAD segments
    ElfW(Addr) min_vaddr = (ElfW(Addr))-1;
    ElfW(Addr) max_vaddr = 0;
    for (ElfW(Half) i = 0; i < ctx->phnum; i++) {
        if (ctx->phdr[i].p_type == PT_LOAD) {
            ElfW(Addr) seg_start = ctx->phdr[i].p_vaddr;
            ElfW(Addr) seg_end = seg_start + ctx->phdr[i].p_memsz;
            if (seg_start < min_vaddr) min_vaddr = seg_start;
            if (seg_end > max_vaddr) max_vaddr = seg_end;
        }
    }

    if (min_vaddr >= max_vaddr) {
        DI_LOGE("  dump: no PT_LOAD segments found for %s", short_name);
        close(fd);
        return;
    }

    size_t dump_size = (size_t)(max_vaddr - min_vaddr);
    auto *base_ptr = reinterpret_cast<const uint8_t *>(ctx->lib_base + min_vaddr);

    ssize_t written = 0;
    while (written < (ssize_t)dump_size) {
        ssize_t n = write(fd, base_ptr + written, dump_size - written);
        if (n < 0) {
            DI_LOGE("  dump: write failed: %s", strerror(errno));
            close(fd);
            return;
        }
        written += n;
    }
    close(fd);

    DI_LOGI("  dump: wrote %s (%zu bytes, base=0x%" PRIxPTR ")",
            dump_path, dump_size, (uintptr_t)ctx->lib_base);
}

// Generic wrapper: logs execution, optionally dumps/stops, then calls original
static void di_init_entry_wrapper(void) {
    size_t idx = g_wrapper_current++;
    if (idx >= DI_MAX_INIT_ENTRIES) return;

    di_wrapper_ctx *ctx = &g_wrapper_table[idx];

    // 1-based display
    size_t disp_idx = ctx->index + 1;
    size_t disp_total = ctx->total;

    if (ctx->is_dumppoint) {
        DI_LOGI("  >>> DUMP [%zu/%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR,
                disp_idx, disp_total, (uintptr_t)ctx->func_abs, (uintptr_t)ctx->func_rel);
        di_dump_library(ctx);
    }

    if (ctx->is_breakpoint) {
        DI_LOGI("  >>> BREAKPOINT [%zu/%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR,
                disp_idx, disp_total, (uintptr_t)ctx->func_abs, (uintptr_t)ctx->func_rel);
        DI_LOGI("  >>> Process stopped (pid=%d). Resume: kill -CONT %d", getpid(), getpid());
        raise(SIGSTOP);
        DI_LOGI("  >>> Resumed");
    }

    DI_LOGI("  exec init_array[%zu/%zu] abs=0x%" PRIxPTR " rel=0x%" PRIxPTR,
            disp_idx, disp_total, (uintptr_t)ctx->func_abs, (uintptr_t)ctx->func_rel);

    // Try to resolve symbol name
    const char *sym = di_resolve_symbol(reinterpret_cast<void *>(ctx->func_abs));
    if (sym) DI_LOGI("       symbol: %s", sym);

    if (ctx->orig_func) {
        ctx->orig_func();
    }

    DI_LOGI("  done init_array[%zu/%zu]", disp_idx, disp_total);
}

static bool di_has_breakpoint_for_lib(const char *lib_name) {
    pthread_mutex_lock(&g_bp_lock);
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++) {
        if (g_breakpoints[i].active && strstr(lib_name, g_breakpoints[i].lib_name) != nullptr) {
            pthread_mutex_unlock(&g_bp_lock);
            return true;
        }
        if (g_dumppoints[i].active && strstr(lib_name, g_dumppoints[i].lib_name) != nullptr) {
            pthread_mutex_unlock(&g_bp_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&g_bp_lock);
    return false;
}

static bool di_breakpoint_matches(const char *lib_name, size_t index) {
    pthread_mutex_lock(&g_bp_lock);
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++) {
        if (!g_breakpoints[i].active) continue;
        if (strstr(lib_name, g_breakpoints[i].lib_name) != nullptr) {
            if (g_breakpoints[i].index == -1 || g_breakpoints[i].index == (int)index) {
                pthread_mutex_unlock(&g_bp_lock);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&g_bp_lock);
    return false;
}

static bool di_dumppoint_matches(const char *lib_name, size_t index) {
    pthread_mutex_lock(&g_bp_lock);
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++) {
        if (!g_dumppoints[i].active) continue;
        if (strstr(lib_name, g_dumppoints[i].lib_name) != nullptr) {
            if (g_dumppoints[i].index == -1 || g_dumppoints[i].index == (int)index) {
                pthread_mutex_unlock(&g_bp_lock);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&g_bp_lock);
    return false;
}

static dl_interceptor_init_func_t di_breakpoint_hook(
    const struct dl_interceptor_array_entry *entry, void *data) {
    (void)data;

    // Only wrap entries for libraries that have breakpoints
    if (!di_has_breakpoint_for_lib(entry->lib_name))
        return reinterpret_cast<dl_interceptor_init_func_t>(entry->func_abs);

    // Populate wrapper context
    if (entry->index < DI_MAX_INIT_ENTRIES) {
        di_wrapper_ctx *ctx = &g_wrapper_table[entry->index];
        ctx->orig_func = reinterpret_cast<dl_interceptor_init_func_t>(entry->func_abs);
        ctx->lib_name = entry->lib_name;
        ctx->lib_base = entry->lib_base;
        ctx->index = entry->index;
        ctx->total = entry->total;
        ctx->func_abs = entry->func_abs;
        ctx->func_rel = entry->func_rel;
        ctx->is_breakpoint = di_breakpoint_matches(entry->lib_name, entry->index);
        ctx->is_dumppoint = di_dumppoint_matches(entry->lib_name, entry->index);
        ctx->phdr = g_current_phdr;
        ctx->phnum = g_current_phnum;

        // Reset counter on first entry
        if (entry->index == 0) g_wrapper_current = 0;

        return di_init_entry_wrapper;
    }

    // Fallback: too many entries, just return original
    return reinterpret_cast<dl_interceptor_init_func_t>(entry->func_abs);
}

int dl_interceptor_set_breakpoint(const char *lib_name, int index) {
    if (!lib_name) return -1;

    // Convert 1-based user index to 0-based internal (-1 stays as -1)
    int internal_index = (index > 0) ? index - 1 : index;

    pthread_mutex_lock(&g_bp_lock);

    int slot = -1;
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++) {
        if (!g_breakpoints[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_bp_lock);
        DI_LOGE("breakpoint: no free slots (max=%d)", DI_MAX_BREAKPOINTS);
        return -1;
    }

    strncpy(g_breakpoints[slot].lib_name, lib_name, sizeof(g_breakpoints[slot].lib_name) - 1);
    g_breakpoints[slot].lib_name[sizeof(g_breakpoints[slot].lib_name) - 1] = '\0';
    g_breakpoints[slot].index = internal_index;
    g_breakpoints[slot].active = true;

    static bool hook_registered = false;
    if (!hook_registered) {
        dl_interceptor_register_init_array_hook(di_breakpoint_hook, nullptr);
        hook_registered = true;
    }

    pthread_mutex_unlock(&g_bp_lock);

    if (index > 0)
        DI_LOGI("breakpoint: set on %s init_array[%d]", lib_name, index);
    else
        DI_LOGI("breakpoint: set on %s init_array[*]", lib_name);
    return 0;
}

void dl_interceptor_clear_breakpoints(void) {
    pthread_mutex_lock(&g_bp_lock);
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++)
        g_breakpoints[i].active = false;
    pthread_mutex_unlock(&g_bp_lock);
    DI_LOGI("breakpoint: all breakpoints cleared");
}

int dl_interceptor_set_dumppoint(const char *lib_name, int index) {
    if (!lib_name) return -1;

    // Convert 1-based user index to 0-based internal (-1 stays as -1)
    int internal_index = (index > 0) ? index - 1 : index;

    pthread_mutex_lock(&g_bp_lock);

    int slot = -1;
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++) {
        if (!g_dumppoints[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_bp_lock);
        DI_LOGE("dumppoint: no free slots (max=%d)", DI_MAX_BREAKPOINTS);
        return -1;
    }

    strncpy(g_dumppoints[slot].lib_name, lib_name, sizeof(g_dumppoints[slot].lib_name) - 1);
    g_dumppoints[slot].lib_name[sizeof(g_dumppoints[slot].lib_name) - 1] = '\0';
    g_dumppoints[slot].index = internal_index;
    g_dumppoints[slot].active = true;

    // Reuse the same hook registration
    static bool hook_registered = false;
    if (!hook_registered) {
        dl_interceptor_register_init_array_hook(di_breakpoint_hook, nullptr);
        hook_registered = true;
    }

    pthread_mutex_unlock(&g_bp_lock);

    if (index > 0)
        DI_LOGI("dumppoint: set on %s init_array[%d]", lib_name, index);
    else
        DI_LOGI("dumppoint: set on %s init_array[*]", lib_name);
    return 0;
}

void dl_interceptor_clear_dumppoints(void) {
    pthread_mutex_lock(&g_bp_lock);
    for (int i = 0; i < DI_MAX_BREAKPOINTS; i++)
        g_dumppoints[i].active = false;
    pthread_mutex_unlock(&g_bp_lock);
    DI_LOGI("dumppoint: all dumppoints cleared");
}
