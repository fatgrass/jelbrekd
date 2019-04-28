//
//  KUtils.h
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef KUtils_h
#define KUtils_h
#define ISADDR(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)
#include <stdio.h>


mach_port_t fake_host_priv(void);
uint64_t task_self_addr(void);
uint64_t get_address_of_port(pid_t pid, mach_port_t port);
uint64_t get_proc_struct_for_pid(pid_t pid);
int setcsflagsandplatformize(int pid);
uint64_t zm_fix_addr(uint64_t addr);
void fixupsetuid(int pid);
void unsandbox(uint64_t proc);

#endif /* KUtils_h */
