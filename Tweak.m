// hpke_dumper v4 — no objc_copyClassList, hook via CFNotification + NSTimer
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <time.h>

static NSFileHandle *gFH;
static NSString *gPath;
static BOOL gDone = NO;

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

// ---- Hook ----
typedef void *(*EncFn)(void *, void *, void *, void *, void *, void *);
static EncFn o_enc;

static void *my_enc(void *self, void *_cmd, void *data, void *pk, void *info, void *aad) {
    // ALWAYS call original first so app doesn't break
    void *result = o_enc(self, _cmd, data, pk, info, aad);

    // Log safely — crash here won't affect app flow
    @try {
        NSMutableString *L = [NSMutableString stringWithFormat:@"\n==== HPKE ENCRYPT ====\nClass: %s\n",
            class_getName([(__bridge id)self class])];

        NSData *pkD = (__bridge NSData *)pk;
        if (pkD && [pkD respondsToSelector:@selector(length)]) {
            [L appendFormat:@"SERVER_PK_HEX: %@\nSERVER_PK_B64: %@\nSERVER_PK_LEN: %lu\n",
                hexOf(pkD.bytes, pkD.length), [pkD base64EncodedStringWithOptions:0], (unsigned long)pkD.length];
        }

        NSData *ifD = (__bridge NSData *)info;
        if (ifD && [ifD respondsToSelector:@selector(length)]) {
            NSString *s = [[NSString alloc] initWithData:ifD encoding:NSUTF8StringEncoding];
            [L appendFormat:@"INFO_HEX: %@\nINFO_STR: %@\nINFO_LEN: %lu\n",
                hexOf(ifD.bytes, ifD.length), s ?: @"(bin)", (unsigned long)ifD.length];
        }

        NSData *aaD = (__bridge NSData *)aad;
        if (aaD && [aaD respondsToSelector:@selector(length)]) {
            NSUInteger al = aaD.length;
            [L appendFormat:@"AAD_LEN: %lu\nAAD_HEX: %@\n", (unsigned long)al,
                hexOf(aaD.bytes, al < 512 ? al : 512)];
            NSString *as = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
            if (as) [L appendFormat:@"AAD_STR: %@\n", as];
        }

        NSData *inD = (__bridge NSData *)data;
        if (inD && [inD respondsToSelector:@selector(length)]) {
            [L appendFormat:@"PT_LEN: %lu\nPT_HEAD: %@\n", (unsigned long)inD.length,
                hexOf(inD.bytes, inD.length < 64 ? inD.length : 64)];
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.zip", (unsigned long)time(NULL)]];
            [inD writeToFile:zp atomically:YES];
            [L appendFormat:@"PT_SAVED: %@\n", zp];
        }

        NSData *bl = (__bridge NSData *)result;
        if (bl && [bl respondsToSelector:@selector(length)])
            [L appendFormat:@"BLOB_LEN: %lu\nBLOB_HEAD: %@\n",
                (unsigned long)bl.length, hexOf(bl.bytes, bl.length < 48 ? bl.length : 48)];

        emit(L);
    } @catch (id e) {
        emit([NSString stringWithFormat:@"log err: %@", e]);
    }
    return result;
}

// ---- safe targeted install (no objc_copyClassList) ----
static int swz(Class c, const char *sel, IMP imp, void *orig) {
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (!m) return 0;
    *(IMP *)orig = method_getImplementation(m);
    method_setImplementation(m, imp);
    return 1;
}

static void tryInstall(void) {
    if (gDone) return;
    @try {
        // Try known class names from Ghidra (HPKE/crypto wrappers)
        const char *candidates[] = {
            "FBHPKEEncryptor",
            "IGHPKEEncryptor",
            "FBEncryptionUtils",
            "IGEncryptionUtils",
            "FBHPKECryptoHelper",
            "IGHPKECryptoHelper",
            "FBCryptoHelper",
            "IGCryptoHelper",
            "FBHybridEncryption",
            "IGHybridEncryption",
            "FBAEADEncryptor",
            "IGAEADEncryptor",
            "FBSealedSenderCipher",
            "FBHPKECipher",
            "FBDeviceIntegrity",
            "IGDeviceIntegrity",
            "FBPrivacyEncryption",
            "FBASSCEncryption",
            "IGASSCEncryption",
            NULL
        };
        SEL sel = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
        for (int i = 0; candidates[i]; i++) {
            Class c = objc_getClass(candidates[i]);
            if (c && class_getInstanceMethod(c, sel)) {
                int ok = swz(c, "encryptData:withPublicKey:withInfo:withAad:", (IMP)my_enc, &o_enc);
                emit([NSString stringWithFormat:@"HOOKED %s (%d)", candidates[i], ok]);
                gDone = YES;
                return;
            }
        }

        // Fallback: scan classes in SMALL SAFE batches
        unsigned int total = 0;
        Class *all = objc_copyClassList(&total);
        if (!all) return;
        for (unsigned int i = 0; i < total; i++) {
            @try {
                if (!class_getInstanceMethod(all[i], sel)) continue;
                const char *name = class_getName(all[i]);
                int ok = swz(all[i], "encryptData:withPublicKey:withInfo:withAad:", (IMP)my_enc, &o_enc);
                emit([NSString stringWithFormat:@"HOOKED %s (%d) [scan at %u/%u]", name, ok, i, total]);
                gDone = YES;
                break;
            } @catch (__unused id e) { continue; }
        }
        free(all);
    } @catch (id e) {
        emit([NSString stringWithFormat:@"install err: %@", e]);
    }
}

static void retryTimer(__unused CFRunLoopTimerRef t, __unused void *ctx) {
    static int att = 0;
    if (gDone || att >= 60) {
        if (!gDone) emit(@"timeout — encrypt method not found after 60 attempts");
        return;
    }
    att++;
    tryInstall();
    if (gDone) emit(@"READY — trigger selfie IDV to capture params");
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v4 loaded");

        // Use CFRunLoopTimer on main loop — fires after app is settled
        CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL,
            CFAbsoluteTimeGetCurrent() + 8.0,  // first fire: 8s after load
            2.0,                                 // repeat every 2s
            0, 0, retryTimer, NULL);
        CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
    }
}
