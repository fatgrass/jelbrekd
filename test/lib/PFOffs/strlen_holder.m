//
//  strlen_holder.m
//  test
//
//  Created by Tanay Findley on 4/28/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "strlen_holder.h"

uint64_t get_strlen()
{
    NSMutableDictionary *offsets = [NSMutableDictionary dictionaryWithContentsOfFile:@"/jb/offsets.plist"];
    uint64_t ret = (uint64_t)strtoull([offsets[@"JBD_Strlen"] UTF8String], NULL, 16);
    
    return ret;
}
