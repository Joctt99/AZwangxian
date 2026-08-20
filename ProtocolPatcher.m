#import "ProtocolPatcher.h"
#import <CoreFoundation/CoreFoundation.h>

#ifndef DLOG
#define DLOG(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#endif

@implementation ProtocolPatcher

+ (NSData *)patchServerResponse:(NSData *)response {
    if (!response || response.length < 12) {
        return response;
    }

    NSMutableData *mutableResponse = [response mutableCopy];
    uint32_t cmd_be;
    uint32_t errorCode_be;

    [mutableResponse getBytes:&cmd_be range:NSMakeRange(4, 4)];
    [mutableResponse getBytes:&errorCode_be range:NSMakeRange(8, 4)];

    uint32_t cmd_host = CFSwapInt32BigToHost(cmd_be);
    uint32_t errorCode_host = CFSwapInt32BigToHost(errorCode_be);

    if (errorCode_host != 0) {
        uint32_t patchedErrorCode_be = CFSwapInt32HostToBig(0);
        [mutableResponse replaceBytesInRange:NSMakeRange(8, 4) withBytes:&patchedErrorCode_be];
        
        DLOG(@"[PROTO-PATCH] Patched cmd=0x%08X, errorCode from 0x%08X to 0x00000000", cmd_host, errorCode_host);
    }

    return mutableResponse;
}

@end
