//
//  test.m
//  test
//
//  Created by Tanay Findley on 4/20/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include "jelbrek_server.h"
#import <os/log.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/message.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "tfp0_holder.h"
#include "kernel_slide.h"
#include "offsets.h"
#include "KUtils.h"
#include "libproc.h"
#include "kern_exec.h"

mach_port_t tfp0;
uint64_t kernel_base;

#define CS_OPS_STATUS       0   /* return status */

#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */
#define CS_HARD            0x0000100    /* don't load invalid pages */
#define CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY 3
#define JAILBREAKD_COMMAND_FIXUP_SETUID 4


typedef boolean_t (*dispatch_mig_callback_t)(mach_msg_header_t *message, mach_msg_header_t *reply);
mach_msg_return_t dispatch_mig_server(dispatch_source_t ds, size_t maxmsgsz, dispatch_mig_callback_t callback);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service, mach_port_t *server_port);


int is_valid_command(uint8_t command) {
    return (command == JAILBREAKD_COMMAND_ENTITLE ||
            command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT ||
            command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY ||
            command == JAILBREAKD_COMMAND_FIXUP_SETUID);
}



int handle_command(uint8_t command, uint32_t pid) {
    if (!is_valid_command(command)) {
        fprintf(stderr,"Invalid command recieved.\n");
        return 1;
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE) {
        fprintf(stderr,"JAILBREAKD_COMMAND_ENTITLE PID: %d\n", pid);
        setcsflagsandplatformize(pid);
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT) {
        fprintf(stderr,"JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT PID: %d\n", pid);
         setcsflagsandplatformize(pid);
        kill(pid, SIGCONT);
    }
    
    if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY) {
        fprintf(stderr,"JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY PID: %d\n", pid);
        __block int PID = pid;
        dispatch_queue_t queue = dispatch_queue_create("org.coolstar.jailbreakd.delayqueue", NULL);
        dispatch_async(queue, ^{
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            bzero(pathbuf, sizeof(pathbuf));
            
            NSLog(@"%@", @"Waiting to ensure it's not xpcproxy anymore...");
            int ret = proc_pidpath(PID, pathbuf, sizeof(pathbuf));
            while (ret > 0 && strcmp(pathbuf, "/usr/libexec/xpcproxy") == 0){
                proc_pidpath(PID, pathbuf, sizeof(pathbuf));
                usleep(100);
            }
            
            NSLog(@"%@",@"Continuing!");
            setcsflagsandplatformize(PID);
            kill(PID, SIGCONT);
        });
        dispatch_release(queue);
        
        
    }
    
    if (command == JAILBREAKD_COMMAND_FIXUP_SETUID) {
        fprintf(stderr,"JAILBREAKD_FIXUP_SETUID PID: %d\n", pid);
        fixupsetuid(pid);
    }
    
    
    return 0;
}

kern_return_t jbd_call(mach_port_t server_port, uint8_t command, uint32_t pid) {
    fprintf(stderr,"[Mach] New call from %x: command %x, pid %d\n", server_port, command, pid);
    return (handle_command(command, pid) == 0) ? KERN_SUCCESS : KERN_FAILURE;
}






void logMe(const char *message)
{
    fprintf(stderr, "[jelbrekd] %s\n", message);
}


int main(int argc, const char *argv[])
{
    logMe("Starting...");
    
    logMe("Initializing Offsets...");
    offs_init();
    
    unlink("/var/run/jelbrekd.pid");
    logMe("Getting Offsets...");
    
    //Offsets
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    kernel_base = (uint64_t)strtoull([offsets[@"KernelBase"] UTF8String], NULL, 16);
    
    NSString *kernelBase = [NSString stringWithFormat:@"Got KernelBase At: 0x%llx", kernel_base];
    const char *kBase = [kernelBase cStringUsingEncoding:NSASCIIStringEncoding];
    
    NSString *kernelSlide = [NSString stringWithFormat:@"Got KernelSlide At: 0x%llx", kernel_slide];
    const char *kSlide = [kernelSlide cStringUsingEncoding:NSASCIIStringEncoding];
    
    logMe("Getting tfp0...");
    kern_return_t err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
    if (err != KERN_SUCCESS) {
        fprintf(stderr,"host_get_special_port 4: %s\n", mach_error_string(err));
        return 5;
    }
    
    set_tfp_port(tfp0);
    
    NSString *tfpZero = [NSString stringWithFormat:@"Got TFP0 At: %u", tfp0];
    const char *tfpZ = [tfpZero cStringUsingEncoding:NSASCIIStringEncoding];
    
    logMe("Initializing Kexecute...");
    init_kexecute();
    
    logMe(kBase);
    logMe(kSlide);
    logMe(tfpZ);
    
    
    @autoreleasepool {
        mach_port_t port;
        
        if ((err = bootstrap_check_in(bootstrap_port, "space.tw3lve.jelbrekd", &port))) {
            fprintf(stderr,"Failed to check in: %s\n", mach_error_string(err));
            return -1;
        }
        
        dispatch_source_t server = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(server, ^{
            dispatch_mig_server(server, jbd_jailbreak_daemon_subsystem.maxsize, jailbreak_daemon_server);
        });
        dispatch_resume(server);
        
        logMe("MIG Is Online!");
        
        int fd = open("/var/run/jelbrekd.pid", O_WRONLY | O_CREAT, 0600);
        char mmmm[8] = {0};
        int sz = snprintf(mmmm, 8, "%d", getpid());
        write(fd, mmmm, sz);
        close(fd);
        
        logMe("Dumped pid");
        
        dispatch_main();
        
    }
    
    return EXIT_FAILURE;
}
