// hpke_dumper v3 — safe hooks: delayed class scan, no early objc_copyClassList
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static NSFileHandle *gFH;
static NSString *gPath;

static void emit(NSString *s) {
    NSLog(@"[HPKE] %@", s);
    if (!gFH) return;
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    @synchronized (gPath) { @try { [gFH writeData:d]; } @catch (__unused id e) {} }
}
static NSString *hexOf(const void *b, NSUInteger n) {
    const unsigned char *p = b;
    NSMutableString *h = [NSMutableString stringWithCapacity:n * 2];
    for (NSUInteger i = 0; i < n; i++) [h appendFormat:@"%02x", p[i]];
    return h;
}

// ---- Hook: encryptData:withPublicKey:withInfo:withAad: ----
typedef void *(*EncFn)(void *, void *, void *, void *, void *, void *);
static EncFn o_enc;

static void *my_enc(void *self, void *_cmd, void *data, void *pk, void *info, void *aad) {
    @try {
        NSData *pkD = (__bridge NSData *)pk;
        NSData *inD = (__bridge NSData *)data;
        NSData *ifD = (__bridge NSData *)info;
        NSData *aaD = (__bridge NSData *)aad;
        NSMutableString *L = [NSMutableString stringWithFormat:@"\n==== HPKE ENCRYPT ====\nClass: %s\n",
            class_getName([(__bridge id)self class])];
        if (pkD && [pkD isKindOfClass:[NSData class]])
            [L appendFormat:@"SERVER_PK_HEX: %@\nSERVER_PK_B64: %@\nSERVER_PK_LEN: %lu\n",
                hexOf(pkD.bytes, pkD.length), [pkD base64EncodedStringWithOptions:0], (unsigned long)pkD.length];
        if (ifD && [ifD isKindOfClass:[NSData class]]) {
            NSString *s = [[NSString alloc] initWithData:ifD encoding:NSUTF8StringEncoding];
            [L appendFormat:@"INFO_HEX: %@\nINFO_STR: %@\nINFO_LEN: %lu\n",
                hexOf(ifD.bytes, ifD.length), s ?: @"(bin)", (unsigned long)ifD.length];
        }
        if (aaD && [aaD isKindOfClass:[NSData class]]) {
            NSUInteger al = aaD.length;
            [L appendFormat:@"AAD_LEN: %lu\nAAD_HEX: %@\n", (unsigned long)al,
                hexOf(aaD.bytes, al < 512 ? al : 512)];
            NSString *as = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
            if (as) [L appendFormat:@"AAD_STR: %@\n", as];
        }
        if (inD && [inD isKindOfClass:[NSData class]]) {
            [L appendFormat:@"PT_LEN: %lu\nPT_HEAD: %@\n", (unsigned long)inD.length,
                hexOf(inD.bytes, inD.length < 64 ? inD.length : 64)];
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.zip", (unsigned long)time(NULL)]];
            [inD writeToFile:zp atomically:YES];
            [L appendFormat:@"PT_SAVED: %@\n", zp];
        }
        emit(L);
    } @catch (id e) { emit([NSString stringWithFormat:@"hook err: %@", e]); }

    void *r = o_enc(self, _cmd, data, pk, info, aad);

    @try {
        NSData *bl = (__bridge NSData *)r;
        if (bl && [bl isKindOfClass:[NSData class]])
            emit([NSString stringWithFormat:@"BLOB_LEN: %lu\nBLOB_HEAD: %@\n",
                (unsigned long)bl.length, hexOf(bl.bytes, bl.length < 48 ? bl.length : 48)]);
    } @catch (__unused id e) {}
    return r;
}

// ---- swizzle helper ----
static int swz(Class c, const char *sel, IMP imp, void *orig) {
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (!m) return 0;
    *(IMP *)orig = method_getImplementation(m);
    method_setImplementation(m, imp);
    return 1;
}

static BOOL gDone = NO;

static void tryHook(void) {
    if (gDone) return;
    SEL s = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
    unsigned int n = 0;
    Class *cls = objc_copyClassList(&n);
    for (unsigned int i = 0; i < n; i++) {
        if (class_getInstanceMethod(cls[i], s)) {
            const char *name = class_getName(cls[i]);
            int ok = swz(cls[i], "encryptData:withPublicKey:withInfo:withAad:", (IMP)my_enc, &o_enc);
            emit([NSString stringWithFormat:@"HOOKED %s (%d)", name, ok]);
            gDone = YES;
            break;
        }
    }
    free(cls);
}

static void retry(int att) {
    if (gDone) { emit(@"ALL HOOKS READY — trigger selfie IDV"); return; }
    if (att >= 120) { emit(@"timeout — class not found"); return; }
    tryHook();
    if (gDone) { emit(@"ALL HOOKS READY — trigger selfie IDV"); return; }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
        dispatch_get_global_queue(0, 0), ^{ retry(att + 1); });
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v3 loaded");
        // Delay class scan by 5 seconds to let IG fully load
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(0, 0), ^{ retry(0); });
    }
}
