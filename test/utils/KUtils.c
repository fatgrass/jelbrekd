//
//  KUtils.c
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "KUtils.h"
#include <mach/port.h>
#include "KMem.h"
#include <mach/mach.h>
#include "OffsetHolder.h"
#include "find_port.h"
#include "ktask_holder.h"
#include <unistd.h>
#include "zone_map_ref_holder.h"
#include "vfs_context_current_holder.h"
#include "offsets.h"
#include "kern_exec.h"
#include "vnode_put_holder.h"
#include "vnode_lookup_holder.h"
#include "os_boolean_true_holder.h"
#include <sys/fcntl.h>
#include "sandbox.h"
#include "common.h"
#include "ext_add_holder.h"
#include "ext_rel_holder.h"
#include "ext_create_holder.h"
#include "libproc.h"
#include "kernproc_holder.h"
#include "strlen_holder.h"
#include "smalloc_holder.h"
#include "kernel_call.h"
#include "os_xml_holder.h"


#define SIZEOF_STRUCT_EXTENSION 0x60
uint64_t cached_task_self_addr = 0;
bool found_offs = false;




uint64_t get_proc_struct_for_pid(pid_t pid)
{
    
    uint64_t proc = ReadKernel64(ReadKernel64(get_kernel_task()) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    while (proc) {
        if (ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID)) == pid)
            return proc;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST));
    }
    return 0;
}

uint64_t proc_find(pid_t pid) {
    // TODO use kcall(proc_find) + ZM_FIX_ADDR
    uint64_t proc = ReadKernel64(ReadKernel64(get_kernel_task()) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    while (proc) {
        if (ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID)) == pid)
            return proc;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST));
    }
    return 0;
}




uint64_t get_address_of_port(pid_t pid, mach_port_t port)
{
    uint64_t proc_struct_addr = get_proc_struct_for_pid(pid);
    uint64_t task_addr = ReadKernel64(proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint64_t itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint64_t port_addr = ReadKernel64(is_table + (port_index * sizeof_ipc_entry_t));
    return port_addr;
}


uint64_t task_self_addr()
{
    if (cached_task_self_addr == 0) {
        cached_task_self_addr = have_kmem_read() && found_offs ? get_address_of_port(getpid(), mach_task_self()) : find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
        fprintf(stderr, "task self: 0x%llx\n", cached_task_self_addr);
    }
    return cached_task_self_addr;
}


uint64_t ipc_space_kernel()
{
    return ReadKernel64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

mach_port_t fake_host_priv_port = MACH_PORT_NULL;
mach_port_t fake_host_priv() {
    if (fake_host_priv_port != MACH_PORT_NULL) {
        return fake_host_priv_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
    uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
    
    // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
    WriteKernel32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
    
    // change the space of the port
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
    
    // set the kobject
    WriteKernel64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
    
    fake_host_priv_port = port;
    
    return port;
}





// thx Siguza
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;

uint64_t zm_fix_addr(uint64_t addr) {
    static kmap_hdr_t zm_hdr = {0, 0, 0, 0};
    if (zm_hdr.start == 0) {
        // xxx ReadKernel64(0) ?!
        // uint64_t zone_map_ref = find_zone_map_ref();
        fprintf(stderr, "zone_map_ref: %llx \n", get_zone_map_ref());
        uint64_t zone_map = ReadKernel64(get_zone_map_ref());
        fprintf(stderr, "zone_map: %llx \n", zone_map);
        // hdr is at offset 0x10, mutexes at start
        size_t r = kreadOwO(zone_map + 0x10, &zm_hdr, sizeof(zm_hdr));
        fprintf(stderr, "zm_range: 0x%llx - 0x%llx (read 0x%zx, exp 0x%zx)\n", zm_hdr.start, zm_hdr.end, r, sizeof(zm_hdr));
        
        if (r != sizeof(zm_hdr) || zm_hdr.start == 0 || zm_hdr.end == 0) {
            fprintf(stderr, "kread of zone_map failed!\n");
            exit(EXIT_FAILURE);
        }
        
        if (zm_hdr.end - zm_hdr.start > 0x100000000) {
            fprintf(stderr, "zone_map is too big, sorry.\n");
            exit(EXIT_FAILURE);
        }
    }
    
    uint64_t zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff);
    
    return zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp;
}


int _vnode_put(uint64_t vnode){
    return (int)kexecute2(get_vnode_put(), vnode, 0, 0, 0, 0, 0, 0);
}


uint64_t _vfs_context() {
    static uint64_t vfs_context = 0;
    if (vfs_context == 0) {
        vfs_context = kexecute2(get_vfs_context_current(), 1, 0, 0, 0, 0, 0, 0);
        vfs_context = zm_fix_addr(vfs_context);
    }
    return vfs_context;
}

int _vnode_lookup(const char *path, int flags, uint64_t *vpp, uint64_t vfs_context){
    size_t len = strlen(path) + 1;
    uint64_t vnode = kmem_alloc(sizeof(uint64_t));
    uint64_t ks = kmem_alloc(len);
    kwriteOwO(ks, path, len);
    int ret = (int)kexecute2(get_vnode_lookup(), ks, 0, vnode, vfs_context, 0, 0, 0);
    if (ret != ERR_SUCCESS) {
        return -1;
    }
    *vpp = ReadKernel64(vnode);
    kmem_free(ks, len);
    kmem_free(vnode, sizeof(uint64_t));
    return 0;
}


uint64_t vnodeForPath(const char *path) {
    uint64_t vfs_context = 0;
    uint64_t *vpp = NULL;
    uint64_t vnode = 0;
    vfs_context = _vfs_context();
    if (!ISADDR(vfs_context)) {
        fprintf(stderr, "Failed to get vfs_context.\n");
        goto out;
    }
    vpp = malloc(sizeof(uint64_t));
    if (vpp == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        goto out;
    }
    if (_vnode_lookup(path, O_RDONLY, vpp, vfs_context) != ERR_SUCCESS) {
        fprintf(stderr, "Failed to get vnode at path \"%s\".\n", path);
        goto out;
    }
    vnode = *vpp;
out:
    if (vpp != NULL) {
        free(vpp);
        vpp = NULL;
    }
    return vnode;
}

#define ADDR                 "0x%016llx"
#define TF_PLATFORM 0x00000400 /* task is a platform binary */
#define CS_VALID 0x0000001 /* dynamically valid */
#define CS_GET_TASK_ALLOW 0x0000004 /* has get-task-allow entitlement */
#define CS_INSTALLER 0x0000008 /* has installer entitlement */
#define CS_HARD 0x0000100 /* don't load invalid pages */
#define CS_KILL 0x0000200 /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION 0x0000400 /* force expiration checking */
#define CS_RESTRICT 0x0000800 /* tell dyld to treat restricted */
#define CS_REQUIRE_LV 0x0002000 /* require library validation */
#define CS_KILLED 0x1000000 /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM 0x2000000 /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */
#define CS_DEBUGGED 0x10000000 /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define off_OSDictionary_SetObjectWithCharP (sizeof(void*) * 0x1F)
#define off_OSDictionary_GetObjectWithCharP (sizeof(void*) * 0x26)
#define off_OSString_GetLength (sizeof(void*) * 0x11)
#define off_OSObject_Release (sizeof(void*) * 0x05)
#define off_OSDictionary_Merge (sizeof(void*) * 0x23)
#define off_OSArray_Merge (sizeof(void*) * 0x1E)





size_t kstrlen(uint64_t ptr) {
    size_t kstrlen = (size_t)kexecute2(get_strlen(), ptr, 0, 0, 0, 0, 0, 0);
    return kstrlen;
}

uint64_t kstralloc(const char *str) {
    size_t str_kptr_size = strlen(str) + 1;
    uint64_t str_kptr = kmem_alloc(str_kptr_size);
    if (str_kptr != 0) {
        kwriteOwO(str_kptr, str, str_kptr_size);
    }
    return str_kptr;
}

void kstrfree(uint64_t ptr) {
    if (ptr != 0) {
        size_t size = kstrlen(ptr);
        kmem_free(ptr, size);
    }
}

uint64_t OSObjectFunc(uint64_t OSObject, uint32_t off) {
    uint64_t OSObjectFunc = 0;
    uint64_t vtable = ReadKernel64(OSObject);
    vtable = kernel_xpacd(vtable);
    if (vtable != 0) {
        OSObjectFunc = ReadKernel64(vtable + off);
        OSObjectFunc = kernel_xpaci(OSObjectFunc);
    }
    return OSObjectFunc;
}


bool OSDictionary_SetItem(uint64_t OSDictionary, const char *key, uint64_t val) {
    bool OSDictionary_SetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_SetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_SetItem = (bool)kexecute2(function, OSDictionary, kstr, val, 0, 0, 0, 0);
            kstrfree(kstr);
        }
    }
    return OSDictionary_SetItem;
}

uint64_t OSDictionary_GetItem(uint64_t OSDictionary, const char *key) {
    uint64_t OSDictionary_GetItem = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_GetObjectWithCharP);
    if (function != 0) {
        uint64_t kstr = kstralloc(key);
        if (kstr != 0) {
            OSDictionary_GetItem = kexecute2(function, OSDictionary, kstr, 0, 0, 0, 0, 0);
            if (OSDictionary_GetItem != 0 && (OSDictionary_GetItem >> 32) == 0) {
                OSDictionary_GetItem = zm_fix_addr(OSDictionary_GetItem);
            }
            kstrfree(kstr);
        }
    }
    return OSDictionary_GetItem;
}

uint32_t OSString_GetLength(uint64_t OSString) {
    uint32_t OSString_GetLength = 0;
    uint64_t function = OSObjectFunc(OSString, off_OSString_GetLength);
    if (function != 0) {
        OSString_GetLength = (uint32_t)kexecute2(function, OSString, 0, 0, 0, 0, 0, 0);
    }
    return OSString_GetLength;
}

uint64_t OSString_CStringPtr(uint64_t OSString) {
    uint64_t OSString_CStringPtr = 0;
    if (OSString != 0) {
        OSString_CStringPtr = ReadKernel64(OSString + 0x10);
    }
    return OSString_CStringPtr;
}


char *OSString_CopyString(uint64_t OSString) {
    char *OSString_CopyString = NULL;
    uint32_t length = OSString_GetLength(OSString);
    if (length != 0) {
        char *str = malloc(length + 1);
        if (str != NULL) {
            str[length] = 0;
            uint64_t CStringPtr = OSString_CStringPtr(OSString);
            if (CStringPtr != 0) {
                if (kreadOwO(CStringPtr, str, length) == length) {
                    OSString_CopyString = strdup(str);
                }
            }
            SafeFreeNULL(str);
        }
    }
    return OSString_CopyString;
}

uint64_t OSUnserializeXML(const char *buffer) {
    uint64_t OSUnserializeXML = 0;
    uint64_t kstr = kstralloc(buffer);
    if (kstr != 0) {
        uint64_t error_kptr = 0;
        OSUnserializeXML = kexecute2(get_os_xml(), kstr, error_kptr, 0, 0, 0, 0, 0);
        if (OSUnserializeXML != 0) {
            OSUnserializeXML = zm_fix_addr(OSUnserializeXML);
        }
        kstrfree(kstr);
    }
    return OSUnserializeXML;
}

uint32_t OSDictionary_ItemCount(uint64_t OSDictionary) {
    uint32_t OSDictionary_ItemCount = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemCount = ReadKernel32(OSDictionary + 20);
    }
    return OSDictionary_ItemCount;
}

uint64_t OSDictionary_ItemBuffer(uint64_t OSDictionary) {
    uint64_t OSDictionary_ItemBuffer = 0;
    if (OSDictionary != 0) {
        OSDictionary_ItemBuffer = ReadKernel64(OSDictionary + 32);
    }
    return OSDictionary_ItemBuffer;
}

uint32_t OSArray_ItemCount(uint64_t OSArray) {
    uint32_t OSArray_ItemCount = 0;
    if (OSArray != 0) {
        OSArray_ItemCount = ReadKernel32(OSArray + 0x14);
    }
    return OSArray_ItemCount;
}

uint64_t OSArray_ItemBuffer(uint64_t OSArray) {
    uint64_t OSArray_ItemBuffer = 0;
    if (OSArray != 0) {
        OSArray_ItemBuffer = ReadKernel64(OSArray + 32);
    }
    return OSArray_ItemBuffer;
}

void OSObject_Release(uint64_t OSObject) {
    uint64_t function = OSObjectFunc(OSObject, off_OSObject_Release);
    if (function != 0) {
        kexecute2(function, OSObject, 0, 0, 0, 0, 0, 0);
    }
}

bool OSDictionary_Merge(uint64_t OSDictionary, uint64_t OSDictionary2) {
    bool OSDictionary_Merge = false;
    uint64_t function = OSObjectFunc(OSDictionary, off_OSDictionary_Merge);
    if (function != 0) {
        OSDictionary_Merge = (bool)kexecute2(function, OSDictionary, OSDictionary2, 0, 0, 0, 0, 0);
    }
    return OSDictionary_Merge;
}

bool OSArray_Merge(uint64_t OSArray, uint64_t OSArray2) {
    bool OSArray_Merge = false;
    uint64_t function = OSObjectFunc(OSArray, off_OSArray_Merge);
    if (function != 0) {
        OSArray_Merge = (bool)kexecute2(function, OSArray, OSArray2, 0, 0, 0, 0, 0);
    }
    return OSArray_Merge;
}




//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void set_platform_binary(uint64_t proc, bool set)
{
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    fprintf(stderr, "task_struct_addr = " ADDR, task_struct_addr);

    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}



const char *abs_path_exceptions[] = {
    "/Library",
    "/private/var/mobile/Library",
    "/System/Library/Caches",
    "/private/var/mnt",
    NULL
};




void unsandbox(uint64_t proc) {
    fprintf(stderr, "[jelbrekd] Unsandboxed proc 0x%llx\n", proc);
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    uint64_t cr_label = ReadKernel64(ucred + off_ucred_cr_label);
    WriteKernel64(cr_label + off_sandbox_slot, 0);
}


void set_csflags(uint64_t proc, uint32_t flags, bool value) {
    uint32_t csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}


uint64_t get_amfi_entitlements(uint64_t cr_label) {
    uint64_t amfi_entitlements = 0;
    amfi_entitlements = ReadKernel64(cr_label + 0x8);
    return amfi_entitlements;
}

uint64_t get_sandbox(uint64_t cr_label) {
    uint64_t sandbox = 0;
    sandbox = ReadKernel64(cr_label + 0x8 + 0x8);
    return sandbox;
}

void set_cs(uint64_t proc)
{
    set_csflags(proc, CS_PLATFORM_BINARY, true);
    set_csflags(proc, CS_REQUIRE_LV, false);
    set_csflags(proc, CS_CHECK_EXPIRATION, false);
    set_csflags(proc, CS_DYLD_PLATFORM, true);
    set_csflags(proc, CS_GET_TASK_ALLOW, true);
    set_csflags(proc, CS_INSTALLER, true);
    set_csflags(proc, CS_RESTRICT, false);
    set_csflags(proc, CS_DEBUGGED, true);
    set_csflags(proc, CS_HARD, false);
    set_csflags(proc, CS_KILL, false);
}

bool entitleProcess(uint64_t amfi_entitlements, const char *key, uint64_t val) {
    bool entitleProcess = false;
    if (amfi_entitlements != 0) {
        if (OSDictionary_GetItem(amfi_entitlements, key) != val) {
            entitleProcess = OSDictionary_SetItem(amfi_entitlements, key, val);
        }
    } else {
        fprintf(stderr, "[jelbrekd] ERROR GETTING AMFI!\n");
    }
    return entitleProcess;
}


int extension_create_file(uint64_t saveto, uint64_t sb, const char *path, size_t path_len, uint32_t subtype) {
    int extension_create_file = -1;
    uint64_t kstr = kstralloc(path);
    if (kstr != 0) {
        extension_create_file = (int)kexecute2(get_ext_create(), saveto, sb, kstr, (uint64_t)path_len, (uint64_t)subtype, 0, 0);
        kstrfree(kstr);
    }
    return extension_create_file;
}

int extension_add(uint64_t ext, uint64_t sb, const char *desc) {
    int extension_add = -1;
    uint64_t kstr = kstralloc(desc);
    if (kstr != 0) {
        extension_add = (int)kexecute2(get_ext_add(), ext, sb, kstr, 0, 0, 0, 0);
        kstrfree(kstr);
    }
    return extension_add;
}

void extension_release(uint64_t ext) {
    kexecute2(get_ext_rel(), ext, 0, 0, 0, 0, 0, 0);
}

uint64_t smalloc(size_t size) {
    uint64_t smalloc = kexecute2(get_smalloc(), (uint64_t)size, 0, 0, 0, 0, 0, 0);
    smalloc = zm_fix_addr(smalloc);
    return smalloc;
}

bool set_file_extension(uint64_t sandbox, const char *exc_key, const char *path) {
    bool set_file_extension = false;
    if (sandbox != 0) {
        uint64_t ext = smalloc(SIZEOF_STRUCT_EXTENSION);
        if (ext != 0) {
            int ret_extension_create_file = extension_create_file(ext, sandbox, path, strlen(path) + 1, 0);
            if (ret_extension_create_file == 0) {
                int ret_extension_add = extension_add(ext, sandbox, exc_key);
                if (ret_extension_add == 0) {
                    set_file_extension = true;
                }
            }
            extension_release(ext);
        }
    } else {
        set_file_extension = true;
    }
    return set_file_extension;
}

uint64_t get_exception_osarray(const char **exceptions) {
    uint64_t exception_osarray = 0;
    size_t xmlsize = 0x1000;
    size_t len=0;
    ssize_t written=0;
    char *ents = malloc(xmlsize);
    if (!ents) {
        return 0;
    }
    size_t xmlused = sprintf(ents, "<array>");
    for (const char **exception = exceptions; *exception; exception++) {
        len = strlen(*exception);
        len += strlen("<string></string>");
        while (xmlused + len >= xmlsize) {
            xmlsize += 0x1000;
            ents = reallocf(ents, xmlsize);
            if (!ents) {
                return 0;
            }
        }
        written = sprintf(ents + xmlused, "<string>%s/</string>", *exception);
        if (written < 0) {
            SafeFreeNULL(ents);
            return 0;
        }
        xmlused += written;
    }
    len = strlen("</array>");
    if (xmlused + len >= xmlsize) {
        xmlsize += len;
        ents = reallocf(ents, xmlsize);
        if (!ents) {
            return 0;
        }
    }
    written = sprintf(ents + xmlused, "</array>");
    
    exception_osarray = OSUnserializeXML(ents);
    SafeFreeNULL(ents);
    return exception_osarray;
}





char **copy_amfi_entitlements(uint64_t present) {
    unsigned int itemCount = OSArray_ItemCount(present);
    uint64_t itemBuffer = OSArray_ItemBuffer(present);
    size_t bufferSize = 0x1000;
    size_t bufferUsed = 0;
    size_t arraySize = (itemCount + 1) * sizeof(char *);
    char **entitlements = malloc(arraySize + bufferSize);
    if (!entitlements) {
        return NULL;
    }
    entitlements[itemCount] = NULL;
    
    for (int i = 0; i < itemCount; i++) {
        uint64_t item = ReadKernel64(itemBuffer + (i * sizeof(void *)));
        char *entitlementString = OSString_CopyString(item);
        if (!entitlementString) {
            SafeFreeNULL(entitlements);
            return NULL;
        }
        size_t len = strlen(entitlementString) + 1;
        while (bufferUsed + len > bufferSize) {
            bufferSize += 0x1000;
            entitlements = realloc(entitlements, arraySize + bufferSize);
            if (!entitlements) {
                SafeFreeNULL(entitlementString);
                return NULL;
            }
        }
        entitlements[i] = (char*)entitlements + arraySize + bufferUsed;
        strcpy(entitlements[i], entitlementString);
        bufferUsed += len;
        SafeFreeNULL(entitlementString);
    }
    return entitlements;
}


void set_amfi_ents(uint64_t proc)
{
    uint64_t proc_ucred = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    uint64_t cr_label = ReadKernel64(proc_ucred + koffset(KSTRUCT_OFFSET_UCRED_CR_LABEL));
    
    if (cr_label != 0)
    {
        uint64_t amfi_entitlements = get_amfi_entitlements(cr_label);
        
        fprintf(stderr, "AMFI 0x%llx", amfi_entitlements);
        
        if (entitleProcess(amfi_entitlements, "com.apple.private.skip-library-validation", get_os_boolean_true()))
        {
            fprintf(stderr, "[jelbrekd] com.apple.private.skip-library-validation [OK]\n");
        }
        if (entitleProcess(amfi_entitlements, "get-task-allow", get_os_boolean_true()))
        {
            fprintf(stderr, "[jelbrekd] get-task-allow [OK]\n");
        }
        unsandbox(proc);
    }
}

int setcsflagsandplatformize(int pid) {
    //fixupdylib("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    uint64_t proc = proc_find(pid);
    
    if (proc == 0)
    {
        fprintf(stderr, "Error Getting Proc!\n");
        return -1;
    } else {
        set_amfi_ents(proc);
        set_platform_binary(proc, true);
        set_cs(proc);
    }
    return -1;
}


void setUID (uid_t uid, uint64_t proc) {
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    WriteKernel32(proc + off_p_uid, uid);
    WriteKernel32(proc + off_p_ruid, uid);
    WriteKernel32(ucred + off_ucred_cr_uid, uid);
    WriteKernel32(ucred + off_ucred_cr_ruid, uid);
    WriteKernel32(ucred + off_ucred_cr_svuid, uid);
    fprintf(stderr, "Overwritten UID to %i for proc 0x%llx\n", uid, proc);
}

void setGID(gid_t gid, uint64_t proc) {
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    WriteKernel32(proc + off_p_gid, gid);
    WriteKernel32(proc + off_p_rgid, gid);
    WriteKernel32(ucred + off_ucred_cr_rgid, gid);
    WriteKernel32(ucred + off_ucred_cr_svgid, gid);
    fprintf(stderr, "Overwritten GID to %i for proc 0x%llx\n", gid, proc);
}

void fixupsetuid(int pid){

    uint64_t procForPid = proc_find(pid);
    if (procForPid == 0)
    {
        fprintf(stderr, "Error Getting Proc!\n");
        return;
    } else {
        fprintf(stderr, "Got Proc: %llx for pid %d\n", procForPid, pid);
        setUID(0, procForPid);
        setGID(0, procForPid);
    }
}
