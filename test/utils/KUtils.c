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
#include "allproc_holder.h"

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

uint64_t proc_find(int pd, int tries) {
    // TODO use kcall(proc_find) + ZM_FIX_ADDR
    while (tries-- > 0) {
        uint64_t proc = rk64(get_allproc());
        while (proc) {
            uint32_t pid = rk32(proc + off_p_pid);
            if (pid == pd) {
                return proc;
            }
            proc = rk64(proc);
        }
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
    uint32_t csflags = rk32(proc + off_p_csflags);
    fprintf(stderr, "Previous CSFlags: 0x%x\n", csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    fprintf(stderr, "New CSFlags: 0x%x\n", csflags);
    WriteKernel32(proc + off_p_csflags, csflags);
}

void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    uint64_t task = rk64(proc + off_task);
    uint32_t t_flags = rk32(task + off_p_csflags);
    
    fprintf(stderr, "Old t_flags: 0x%x\n", t_flags);
    
    t_flags |= TF_PLATFORM;
    WriteKernel32(task+off_p_csflags, t_flags);
    
    fprintf(stderr, "New t_flags: 0x%x\n", t_flags);
    
}

void set_amfi_entitlements(uint64_t proc) {
    // AMFI entitlements
    
    
    uint64_t proc_ucred = rk64(proc+0xf8);
    uint64_t amfi_entitlements = rk64(rk64(proc_ucred+0x78)+0x8);
    
    
    OSDictionary_SetItem(amfi_entitlements, "get-task-allow", get_os_boolean_true());
    OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", get_os_boolean_true());
}



const char* abs_path_exceptions[] = {
    "/private/var/containers/Bundle/iosbinpack64",
    "/private/var/containers/Bundle/tweaksupport",
    // XXX there's some weird stuff about linking and special
    // handling for /private/var/mobile/* in sandbox
    "/private/var/mobile/Library",
    "/private/var/mnt",
    NULL
};



void set_sandbox_extensions(uint64_t proc) {
    uint64_t proc_ucred = rk64(proc + off_p_ucred);
    uint64_t sandbox = rk64(rk64(proc_ucred + 0x78) + 0x10);
    
    char name[40] = {0};
    kreadOwO(proc + 0x250, name, 20);
    
    fprintf(stderr, "proc = 0x%llx & proc_ucred = 0x%llx & sandbox = 0x%llx\n", proc, proc_ucred, sandbox);
    
    if (sandbox == 0) {
        fprintf(stderr, "no sandbox, skipping\n");
        return;
    }
    
    if (has_file_extension(sandbox, abs_path_exceptions[0])) {
        fprintf(stderr, "already has '%s', skipping\n", abs_path_exceptions[0]);
        return;
    }
    
    uint64_t ext = 0;
    const char** path = abs_path_exceptions;
    while (*path != NULL) {
        ext = extension_create_file(*path, ext);
        if (ext == 0) {
            fprintf(stderr, "extension_create_file(%s) failed, panic!\n", *path);
        }
        ++path;
    }
    
    fprintf(stderr, "last extension_create_file ext: 0x%llx\n", ext);
    
    if (ext != 0) {
        extension_add(ext, sandbox, "com.apple.security.exception.files.absolute-path.read-only");
    }
}



int setcsflagsandplatformize(int pid) {
    //fixupdylib("/var/containers/Bundle/tweaksupport/usr/lib/TweakInject.dylib");
    uint64_t proc = proc_find(pid, 3);
    if (proc != 0) {
        set_csflags(proc);
        set_tfplatform(proc);
        set_amfi_entitlements(proc);
        set_sandbox_extensions(proc);
        //set_csblob(proc);
        fprintf(stderr, "setcsflagsandplatformize on PID %d\n", pid);
        return 0;
    }
   fprintf(stderr, "Unable to find PID %d to entitle!\n", pid);
    return 1;
}

void fixupsetuid(int pid) {
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));
    
    int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    if (ret < 0){
        fprintf(stderr, "Unable to get path for PID %d\n", pid);
        return;
    }
    struct stat file_st;
    if (lstat(pathbuf, &file_st) == -1){
       fprintf(stderr, "Unable to get stat for file %s\n", pathbuf);
        return;
    }
    if (file_st.st_mode & S_ISUID){
        uid_t fileUID = file_st.st_uid;
        fprintf(stderr, "Fixing up setuid for file owned by %u\n", fileUID);
        
        uint64_t proc = proc_find(pid, 3);
        if (proc != 0) {
            uint64_t ucred = rk64(proc + off_p_ucred);
            
            uid_t cr_svuid = rk32(ucred + off_ucred_cr_svuid);
            fprintf(stderr, "Original sv_uid: %u\n", cr_svuid);
            wk32(ucred + off_ucred_cr_svuid, fileUID);
            fprintf(stderr, "New sv_uid: %u\n", fileUID);
        }
    } else {
        fprintf(stderr, "File %s is not setuid!\n", pathbuf);
        return;
    }
}

int unsandbox(int pid) {
    uint64_t proc = proc_find(pid, 3);
    uint64_t proc_ucred = rk64(proc + off_p_ucred);
    uint64_t sandbox = rk64(rk64(proc_ucred+0x78) + 8 + 8);
    if (sandbox == 0) {
        fprintf(stderr, "[jelbrekd] ALREADY UNSANDBOX!\n");
        return 0;
    } else {
        fprintf(stderr, "[jelbrekd] Unsandboxing PID:%d\n", pid);
        wk64(rk64(proc_ucred+0x78) + 8 + 8, 0);
        sandbox = rk64(rk64(proc_ucred+0x78) + 8 + 8);
        if (sandbox == 0) return 0;
    }
    return -1;
}
