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
#include "osobject.h"
#include "sandbox.h"
#include "libproc.h"
#include "kernproc_holder.h"

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
#define CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */
#define CS_HARD            0x0000100    /* don't load invalid pages */
#define CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000
#define CS_ALLOWED_MACHO    0x00ffffe
#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */
#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */
#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED         0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE         0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */


int fixupdylib(char *dylib) {
     fprintf(stderr, "Fixing up dylib %s\n", dylib);
    
#define VSHARED_DYLD 0x000200
    
    fprintf(stderr, "Getting vnode\n");
    uint64_t vnode = vnodeForPath(dylib);
    
    if (!vnode) {
         fprintf(stderr, "Failed to get vnode!\n");
        return -1;
    }
    
     fprintf(stderr, "vnode of %s: 0x%llx\n", dylib, vnode);
    
    uint32_t v_flags = rk32(vnode + off_v_flags);
    if (v_flags & VSHARED_DYLD) {
        _vnode_put(vnode);
        return 0;
    }
    
    fprintf(stderr, "old v_flags: 0x%x\n", v_flags);
    
    wk32(vnode + off_v_flags, v_flags | VSHARED_DYLD);
    
    v_flags = rk32(vnode + off_v_flags);
     fprintf(stderr, "new v_flags: 0x%x\n", v_flags);
    
    _vnode_put(vnode);
    
    return !(v_flags & VSHARED_DYLD);
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void set_csflags(uint64_t proc) {
    uint32_t csflags = rk32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    fprintf(stderr, "[jelbrekd] Previous CSFlags: 0x%x\n", csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    fprintf(stderr, "[jelbrekd] New CSFlags: 0x%x\n", csflags);
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}


void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    //0x10 = off_task
    //0x390 = KSTRUCT_OFFSET_TASK_TFLAGS
    uint64_t task = rk64(proc + off_task);
    
    uint32_t t_flags = ReadKernel32(task + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    
    fprintf(stderr, "[jelbrekd] Old t_flags: 0x%x\n", t_flags);
    
    WriteKernel32(task + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), t_flags | 0x400);
    
    fprintf(stderr, "[jelbrekd] New t_flags: 0x%x\n", t_flags);
    
}



const char* abs_path_exceptions[] = {
    "/Library/",
    "/private/var/mobile/Library",
    "/private/var/mnt/",
    "/System/Library/Caches/",
    NULL
};



static const char *exc_key = "com.apple.security.exception.files.absolute-path.read-only";
void set_sandbox_extensions(uint64_t proc) {
    fprintf(stderr, "[jelbrekd] Set sandbox called for proc: %llx\n", proc);
    
    uint64_t proc_ucred = ReadKernel64(proc + off_p_ucred);
    uint64_t sandbox = ReadKernel64(ReadKernel64(proc_ucred + 0x78) + 0x10);
    
    if (sandbox == 0)
    {
        fprintf(stderr, "[jelbrekd] No sandbox for proc: %llx\n", proc);
        return;
    }
    
    if (has_file_extension(sandbox, abs_path_exceptions[0]))
    {
        fprintf(stderr, "[jelbrekd] Path Exceptions Already Exist For Proc: %llx\n", proc);
        return;
    }
    
    uint64_t ext = 0;
    const char** path = abs_path_exceptions;
    while (*path != NULL)
    {
        ext = extension_create_file(*path, ext);
        if (ext == 0) {
            fprintf(stderr, "extension_create_file(%s) failed, panic!", *path);
        }
        path = path + 1;
    }
    
    if (ext != 0)
    {
        extension_add(ext, sandbox, exc_key);
    }
}

void set_csblob(uint64_t proc) {
    uint64_t textvp = rk64(proc + off_p_textvp); //vnode of executable
    off_t textoff = rk64(proc + off_p_textoff);
    
    
    fprintf(stderr, "[jelbrekd] __TEXT at 0x%llx. Offset: 0x%llx\n", textvp, textoff);
    
    if (textvp != 0){
        uint32_t vnode_type_tag = rk32(textvp + off_v_type);
        uint16_t vnode_type = vnode_type_tag & 0xffff;
        uint16_t vnode_tag = (vnode_type_tag >> 16);
        
        fprintf(stderr,"[jelbrekd] VNode Type: 0x%x. Tag: 0x%x.\n", vnode_type, vnode_tag);
        
        
        if (vnode_type == 1){
            uint64_t ubcinfo = rk64(textvp + off_v_ubcinfo);
            
           fprintf(stderr,"[jelbrekd] UBCInfo at 0x%llx.\n", ubcinfo);
            
            
            uint64_t csblobs = rk64(ubcinfo + off_ubcinfo_csblobs);
            while (csblobs != 0){
                
                fprintf(stderr,"[jelbrekd] CSBlobs at 0x%llx.\n", csblobs);
                
                
                cpu_type_t csblob_cputype = rk32(csblobs + off_csb_cputype);
                unsigned int csblob_flags = rk32(csblobs + off_csb_flags);
                off_t csb_base_offset = rk64(csblobs + off_csb_base_offset);
                uint64_t csb_entitlements = rk64(csblobs + off_csb_entitlements_offset);
                unsigned int csb_signer_type = rk32(csblobs + off_csb_signer_type);
                unsigned int csb_platform_binary = rk32(csblobs + off_csb_platform_binary);
                unsigned int csb_platform_path = rk32(csblobs + off_csb_platform_path);
                
                
                fprintf(stderr,"[jelbrekd] CSBlob CPU Type: 0x%x. Flags: 0x%x. Offset: 0x%llx\n", csblob_cputype, csblob_flags, csb_base_offset);
                fprintf(stderr,"[jelbrekd] CSBlob Signer Type: 0x%x. Platform Binary: %d Path: %d\n", csb_signer_type, csb_platform_binary, csb_platform_path);
                
                wk32(csblobs + off_csb_platform_binary, 1);
                
                csb_platform_binary = rk32(csblobs + off_csb_platform_binary);
                
                fprintf(stderr,"[jelbrekd] CSBlob Signer Type: 0x%x. Platform Binary: %d Path: %d\n", csb_signer_type, csb_platform_binary, csb_platform_path);
                
                fprintf(stderr,"[jelbrekd] Entitlements at 0x%llx.\n", csb_entitlements);
                
                csblobs = rk64(csblobs);
            }
        }
    }
}


//TheGoodShit

uint64_t get_exception_osarray(void) {
    static uint64_t cached = 0;
    
    if (cached == 0) {
        // XXX use abs_path_exceptions
        cached = OSUnserializeXML("<array>"
                                  "<string>/Library/</string>"
                                  "<string>/private/var/mobile/Library/</string>"
                                  "<string>/private/var/mnt/</string>"
                                  "<string>/System/Library/Caches/</string>"
                                  "</array>");
    }
    
    return cached;
}



void set_amfi_entitlements(uint64_t proc) {
    // AMFI entitlements
    
    
    uint64_t proc_ucred = rk64(proc+0xf8);
    uint64_t amfi_entitlements = rk64(rk64(proc_ucred+0x78)+0x8);
    
    fprintf(stderr, "[jelbrekd] Setting Entitlements...\n");
    
    
    OSDictionary_SetItem(amfi_entitlements, "get-task-allow", get_os_boolean_true());
    OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", get_os_boolean_true());
                         
                         uint64_t present = OSDictionary_GetItem(amfi_entitlements, exc_key);
                         
                         int rv = 0;
                         
                         if (present == 0) {
                             rv = OSDictionary_SetItem(amfi_entitlements, exc_key, get_exception_osarray());
                         } else if (present != get_exception_osarray()) {
                             unsigned int itemCount = OSArray_ItemCount(present);
                             
                             fprintf(stderr, "[jelbrekd] present != 0 (0x%llx)! item count: %d\n", present, itemCount);
                             
                             bool foundEntitlements = false;
                             
                             uint64_t itemBuffer = OSArray_ItemBuffer(present);
                             
                             for (int i = 0; i < itemCount; i++){
                                 uint64_t item = rk64(itemBuffer + (i * sizeof(void *)));
                                 fprintf(stderr, "[jelbrekd] Item %d: 0x%llx", i, item);
                                 char *entitlementString = OSString_CopyString(item);
                                 if (strstr(entitlementString, "/Library/") != 0) {
                                     foundEntitlements = true;
                                     free(entitlementString);
                                     break;
                                 }
                                 free(entitlementString);
                             }
                             
                             if (!foundEntitlements){
                                 rv = OSArray_Merge(present, get_exception_osarray());
                             } else {
                                 rv = 1;
                             }
                         } else {
                             fprintf(stderr, "[jelbrekd] Not going to merge array with itself :P\n");
                             rv = 1;
                         }
                         
                         if (rv != 1) {
                            fprintf(stderr, "[jelbrekd] Setting exc FAILED! amfi_entitlements: 0x%llx present: 0x%llx\n", amfi_entitlements, present);
                         }
}
//

void unsandbox(uint64_t proc) {
    fprintf(stderr, "[jelbrekd] Unsandboxed proc 0x%llx\n", proc);
    uint64_t ucred = ReadKernel64(proc + off_p_ucred);
    uint64_t cr_label = ReadKernel64(ucred + off_ucred_cr_label);
    WriteKernel64(cr_label + off_sandbox_slot, 0);
}


void set_csflags3(uint64_t proc) {
    uint32_t csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}

void set_csflags2(uint64_t proc, uint32_t flags) {
    uint32_t csflags = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS));
    csflags |= flags;
    WriteKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS), csflags);
}

void set_cs_platform_binary(uint64_t proc) {
    set_csflags2(proc, CS_PLATFORM_BINARY);
}

int setcsflagsandplatformize(int pid) {
    //fixupdylib("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    uint64_t proc = proc_find(pid);
    
    if (proc == 0)
    {
        fprintf(stderr, "Error Getting Proc!\n");
        return -1;
    } else {
        set_tfplatform(proc);
        set_csflags3(proc);
        set_cs_platform_binary(proc);
        set_amfi_entitlements(proc);
        unsandbox(proc);
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
