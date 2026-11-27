// hpke_dumper v2 — MINIMAL: just log to verify injection works on IG 454.1
#import <Foundation/Foundation.h>

__attribute__((constructor))
static void init_hpke_dumper(void) {
    NSLog(@"[HPKE] dylib loaded OK");
}
