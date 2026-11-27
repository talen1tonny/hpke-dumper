// hpke_dumper v8 — discovery: find class name that owns encryptData:
// v7 confirmed selector in __TEXT,__objc_methname (singular!)
// Now: find crypto class names + try each via objc_getClass (safe)
// Each finding = separate NSLog (no syslog truncation)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <time.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <string.h>

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
        emit([NSString stringWithFormat:@"==== HPKE ENCRYPT ===="]);
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
            emit([NSString stringWithFormat:@"INFO_LEN: %lu", (unsigned long)ifD.length]);
        }
        NSData *aaD = (__bridge NSData *)aad;
        if (aaD && [aaD respondsToSelector:@selector(length)]) {
            NSUInteger al = aaD.length;
            emit([NSString stringWithFormat:@"AAD_LEN: %lu", (unsigned long)al]);
            emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(aaD.bytes, al < 512 ? al : 512)]);
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
    } @catch (id e) {
        emit([NSString stringWithFormat:@"log err: %@", e]);
    }
    return result;
}

// ---- All selectors ----
static const char *kSels[] = {
    "encryptData:withPublicKey:withInfo:withAad:",
    "encryptData:withPublicKey:withInfo:withAAD:",
    "encryptDataPadded:withPublicKey:withInfo:withAad:",
    "encryptStringPadded:withPublicKey:withInfo:withAad:",
    NULL
};

// ---- Try hook a class by name ----
static BOOL tryHookClass(const char *name) {
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

// ---- Discovery: find crypto class names from __objc_classname in main binary ----
static void discoverAndHook(void) {
    emit(@"=== DISCOVERY v8 START ===");

    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh) { emit(@"no main image"); return; }

    // Search for class names in multiple possible section names
    const char *sectNames[] = {"__objc_classname", "__objc_classnames", NULL};
    const char *segNames[] = {"__TEXT", "__DATA", "__DATA_CONST", NULL};

    // Keywords for filtering
    const char *kw[] = {
        "ncrypt", "HPKE", "hpke", "Seal", "Cipher", "PublicKey",
        "Hybrid", "AEAD", "aead", "EE", "E2EE", "e2ee",
        "Enrichment", "enrichment", "Authenticity", "authenticity",
        "IDV", "Selfie", "Recovery", "Signal", "Crypto", "crypto",
        "3PConv", "Conv3P", "CONV", NULL
    };

    int totalFound = 0;

    for (int sg = 0; segNames[sg]; sg++) {
        for (int sc = 0; sectNames[sc]; sc++) {
            unsigned long sz = 0;
            const uint8_t *data = getsectiondata(mh, segNames[sg], sectNames[sc], &sz);
            if (!data || sz == 0) continue;

            emit([NSString stringWithFormat:@"SECT %s,%s = %lu bytes", segNames[sg], sectNames[sc], sz]);

            // Walk null-terminated strings
            unsigned long pos = 0;
            while (pos < sz) {
                const char *name = (const char *)(data + pos);
                size_t nLen = strnlen(name, sz - pos);
                if (nLen == 0) { pos++; continue; }

                // Check keywords
                for (int k = 0; kw[k]; k++) {
                    if (strstr(name, kw[k])) {
                        emit([NSString stringWithFormat:@"CLASS_HIT: %s", name]);
                        totalFound++;

                        // Try to hook it
                        if (!gHooked) {
                            BOOL ok = tryHookClass(name);
                            if (ok) emit([NSString stringWithFormat:@"HOOK SUCCESS via discovery: %s", name]);
                        }
                        break;
                    }
                }
                pos += nLen + 1;
            }
        }
    }

    // Also walk __objc_methname to show full selector strings around our hit
    for (int sg = 0; segNames[sg]; sg++) {
        const char *mSects[] = {"__objc_methname", "__objc_methnames", NULL};
        for (int sc = 0; mSects[sc]; sc++) {
            unsigned long sz = 0;
            const uint8_t *data = getsectiondata(mh, segNames[sg], mSects[sc], &sz);
            if (!data || sz == 0) continue;
            emit([NSString stringWithFormat:@"METHSECT %s,%s = %lu bytes", segNames[sg], mSects[sc], sz]);

            // Find our exact selectors
            unsigned long pos = 0;
            while (pos < sz) {
                const char *s = (const char *)(data + pos);
                size_t sLen = strnlen(s, sz - pos);
                if (sLen == 0) { pos++; continue; }
                if (strstr(s, "encryptData") || strstr(s, "encryptString") || strstr(s, "uploadE2EE")) {
                    emit([NSString stringWithFormat:@"SEL_FULL: %s", s]);
                }
                pos += sLen + 1;
            }
        }
    }

    emit([NSString stringWithFormat:@"=== DISCOVERY v8 DONE: %d crypto classes found, hooked=%d ===",
        totalFound, gHooked ? 1 : 0]);
}

// ---- Known class names ----
static const char *kClasses[] = {
    "FBHPKEEncryptor", "IGHPKEEncryptor",
    "FBEncryptionUtils", "IGEncryptionUtils",
    "FBHPKECryptoHelper", "IGHPKECryptoHelper",
    "FBCryptoHelper", "IGCryptoHelper",
    "FBHybridEncryption", "IGHybridEncryption",
    "FBAEADEncryptor", "IGAEADEncryptor",
    "FBEndToEndEncryption", "IGEndToEndEncryption",
    "FBCryptoService", "IGCryptoService",
    "FBHybridPublicKeyEncryption", "IGHybridPublicKeyEncryption",
    "FBEEEncryptor", "IGEEEncryptor",
    "FBEnrichmentEncryptor", "IGEnrichmentEncryptor",
    "FBContentEncryption", "IGContentEncryption",
    "FBAuthenticityEncryption", "IGAuthenticityEncryption",
    "AuthenticityOnDeviceSignalsTracker",
    "IGAuthenticityOnDeviceSignalsTracker",
    "FBAuthenticityOnDeviceSignalsTracker",
    "FBSealedBox", "IGSealedBox",
    "FBPublicKeyEncryption", "IGPublicKeyEncryption",
    NULL
};

static BOOL tryKnown(void) {
    for (int c = 0; kClasses[c]; c++) {
        if (tryHookClass(kClasses[c])) return YES;
    }
    return NO;
}

static void retryInstall(int attempt) {
    if (gHooked) { emit(@"READY — trigger selfie IDV"); return; }
    if (attempt >= 20) {
        emit(@"known exhausted → discovery");
        discoverAndHook();
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
        emit(@"hpke_dumper v8 loaded");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(0); });
    }
}
