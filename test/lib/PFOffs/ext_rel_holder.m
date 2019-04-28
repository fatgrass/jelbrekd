//
//  ext_rel_holder.c
//  test
//
//  Created by Tanay Findley on 4/28/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include "ext_rel_holder.h"
#import <Foundation/Foundation.h>

uint64_t get_ext_rel()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t ret = (uint64_t)strtoull([offsets[@"JBD_ExtRel"] UTF8String], NULL, 16);
    
    return ret;
}
