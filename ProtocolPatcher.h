
#import <Foundation/Foundation.h>

@interface ProtocolPatcher : NSObject

+ (NSData *)patchServerResponse:(NSData *)response;

@end
