//
//  kern_exec.h
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef kern_exec_h
#define kern_exec_h

#define ISADDR(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

bool init_kexecute(void);
uint64_t kexecute2(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
void term_kexecute(void);

#endif /* kern_exec_h */
