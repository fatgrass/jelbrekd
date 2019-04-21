//
//  smalloc_holder.c
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include "smalloc_holder.h"
#import <Foundation/Foundation.h>

uint64_t get_smalloc()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t ret = (uint64_t)strtoull([offsets[@"Smalloc"] UTF8String], NULL, 16);
    
    return ret;
}
