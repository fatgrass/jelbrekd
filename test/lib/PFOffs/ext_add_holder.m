//
//  ext_add_holder.c
//  test
//
//  Created by Tanay Findley on 4/28/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include "ext_add_holder.h"
#import <Foundation/Foundation.h>

uint64_t get_ext_add()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t ret = (uint64_t)strtoull([offsets[@"JBD_ExtAdd"] UTF8String], NULL, 16);
    
    return ret;
}
