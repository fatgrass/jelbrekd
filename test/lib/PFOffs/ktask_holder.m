//
//  ktask_holder.c
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "ktask_holder.h"


uint64_t get_kernel_task()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t kernel_task = (uint64_t)strtoull([offsets[@"KernelTask"] UTF8String], NULL, 16);
    
    return kernel_task;
}
