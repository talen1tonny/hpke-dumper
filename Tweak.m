// hpke_dumper v9 — class_getName scan (safe) + objc_getClass hook
// v8 found: selectors confirmed, __objc_classname section MISSING
// v3-v5 crashed from class_getInstanceMethod on unrealized classes
// v9: class_getName ONLY from objc_copyClassList (no method resolution)
//     then objc_getClass(name) + class_getInstanceMethod (safe on realized)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <time.h>

static NSFileHandle *gFH;
static NSString *gPath;
static BOOL gHooked = NO;

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

typedef void *(*EncFn)(void *, void *, void *, void *, void *, void *);
static EncFn o_enc;

static void *my_enc(void *self, void *_cmd, void *data, void *pk, void *info, void *aad) {
    void *result = o_enc(self, _cmd, data, pk, info, aad);
    @try {
        emit(@"==== HPKE ENCRYPT ====");
        emit([NSString stringWithFormat:@"Class: %s  SEL: %s",
            class_getName([(__bridge id)self class]), sel_getName(_cmd)]);
        NSData *pkD = (__bridge NSData *)pk;
        if (pkD && [pkD respondsToSelector:@selector(length)]) {
            emit([NSString stringWithFormat:@"SERVER_PK_HEX: %@", hexOf(pkD.bytes, pkD.length)]);
            emit([NSString stringWithFormat:@"SERVER_PK_B64: %@", [pkD base64EncodedStringWithOptions:0]]);
            emit([NSString stringWithFormat:@"SERVER_PK_LEN: %lu", (unsigned long)pkD.length]);
        }
        NSData *ifD = (__bridge NSData *)info;
        if (ifD && [ifD respondsToSelector:@selector(length)]) {
            NSString *s = [[NSString alloc] initWithData:ifD encoding:NSUTF8StringEncoding];
            emit([NSString stringWithFormat:@"INFO_HEX: %@", hexOf(ifD.bytes, ifD.length)]);
            emit([NSString stringWithFormat:@"INFO_STR: %@", s ?: @"(bin)"]);
        }
        NSData *aaD = (__bridge NSData *)aad;
        if (aaD && [aaD respondsToSelector:@selector(length)]) {
            emit([NSString stringWithFormat:@"AAD_LEN: %lu", (unsigned long)aaD.length]);
            emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(aaD.bytes, aaD.length < 512 ? aaD.length : 512)]);
            NSString *as = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
            if (as) emit([NSString stringWithFormat:@"AAD_STR: %@", as]);
        }
        NSData *inD = (__bridge NSData *)data;
        if (inD && [inD respondsToSelector:@selector(length)]) {
            emit([NSString stringWithFormat:@"PT_LEN: %lu", (unsigned long)inD.length]);
            emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(inD.bytes, inD.length < 64 ? inD.length : 64)]);
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.zip", (unsigned long)time(NULL)]];
            [inD writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
        NSData *bl = (__bridge NSData *)result;
        if (bl && [bl respondsToSelector:@selector(length)]) {
            emit([NSString stringWithFormat:@"BLOB_LEN: %lu", (unsigned long)bl.length]);
            emit([NSString stringWithFormat:@"BLOB_HEAD: %@", hexOf(bl.bytes, bl.length < 48 ? bl.length : 48)]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"log err: %@", e]); }
    return result;
}

static const char *kSels[] = {
    "encryptData:withPublicKey:withInfo:withAad:",
    "encryptDataPadded:withPublicKey:withInfo:withAad:",
    "encryptStringPadded:withPublicKey:withInfo:withAad:",
    "encryptString:withPublicKey:withInfo:withAad:",
    NULL
};

static BOOL tryHookByName(const char *name) {
    Class c = objc_getClass(name);
    if (!c) return NO;
    for (int s = 0; kSels[s]; s++) {
        SEL sel = sel_registerName(kSels[s]);
        Method m = class_getInstanceMethod(c, sel);
        if (!m) m = class_getClassMethod(c, sel);
        if (!m) continue;
        o_enc = (EncFn)method_getImplementation(m);
        method_setImplementation(m, (IMP)my_enc);
        emit([NSString stringWithFormat:@">>> HOOKED %s -[%s] <<<", name, kSels[s]]);
        gHooked = YES;
        return YES;
    }
    return NO;
}

// ---- PHASE 1: safe class_getName scan (NO class_getInstanceMethod) ----
static void nameOnlyScan(void) {
    emit(@"=== NAME SCAN START ===");
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes) { emit(@"objc_copyClassList returned NULL"); return; }
    emit([NSString stringWithFormat:@"total classes: %u", count]);

    // STEP 1: collect all names (class_getName is safe — no realization)
    NSMutableArray *candidates = [NSMutableArray new];
    for (unsigned int i = 0; i < count; i++) {
        const char *name = NULL;
        @try { name = class_getName(classes[i]); } @catch (__unused id e) { continue; }
        if (!name) continue;

        // Filter: anything with encrypt/HPKE/E2EE/seal/conv3p/authenticity/enrichment
        if (strstr(name, "ncrypt") || strstr(name, "HPKE") || strstr(name, "hpke") ||
            strstr(name, "E2EE") || strstr(name, "e2ee") || strstr(name, "Seal") ||
            strstr(name, "3PConv") || strstr(name, "Conv3P") || strstr(name, "3P_CONV") ||
            strstr(name, "uthenticity") || strstr(name, "nrichment") ||
            strstr(name, "Cipher") || strstr(name, "PublicKey") || strstr(name, "Hybrid") ||
            strstr(name, "AEAD") || strstr(name, "Signal") || strstr(name, "Crypto") ||
            strstr(name, "IDV") || strstr(name, "idv")) {
            NSString *ns = [NSString stringWithUTF8String:name];
            [candidates addObject:ns];
            emit([NSString stringWithFormat:@"NAME: %s", name]);
        }
    }
    free(classes);
    emit([NSString stringWithFormat:@"filtered: %lu candidates", (unsigned long)candidates.count]);

    // STEP 2: for each candidate, use objc_getClass (safe realization) + method check
    for (NSString *ns in candidates) {
        if (gHooked) break;
        const char *name = ns.UTF8String;
        @try {
            if (tryHookByName(name)) {
                emit([NSString stringWithFormat:@"HOOK SUCCESS: %s", name]);
                break;
            }
        } @catch (__unused id e) {
            emit([NSString stringWithFormat:@"hook attempt err on %s", name]);
        }
    }

    emit([NSString stringWithFormat:@"=== NAME SCAN DONE: hooked=%d ===", gHooked ? 1 : 0]);
}

// ---- Known class names ----
static const char *kClasses[] = {
    "FBHPKEEncryptor", "IGHPKEEncryptor",
    "FBEncryptionUtils", "IGEncryptionUtils",
    "FBCryptoHelper", "IGCryptoHelper",
    "FBHybridEncryption", "IGHybridEncryption",
    "FBEndToEndEncryption", "IGEndToEndEncryption",
    "FBEEEncryptor", "IGEEEncryptor",
    "FBEnrichmentEncryptor", "IGEnrichmentEncryptor",
    "FBAuthenticityEncryption", "IGAuthenticityEncryption",
    "AuthenticityOnDeviceSignalsTracker",
    "FBContentEncryption", "IGContentEncryption",
    NULL
};

static BOOL tryKnown(void) {
    for (int c = 0; kClasses[c]; c++) {
        if (tryHookByName(kClasses[c])) return YES;
    }
    return NO;
}

static void retryInstall(int attempt) {
    if (gHooked) { emit(@"READY — trigger selfie IDV"); return; }
    if (attempt >= 20) {
        emit(@"known exhausted → name scan");
        nameOnlyScan();
        return;
    }
    if (tryKnown()) { emit(@"READY — trigger selfie IDV"); return; }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(attempt + 1); });
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v9 loaded");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(0); });
    }
}
