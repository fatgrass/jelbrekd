//
//  zone_map_ref_holder.c
//  test
//
//  Created by Tanay Findley on 4/21/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#include "zone_map_ref_holder.h"
#import <Foundation/Foundation.h>


uint64_t get_zone_map_ref()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t ret = (uint64_t)strtoull([offsets[@"ZoneMapOffset"] UTF8String], NULL, 16);
    
    return ret;
}
