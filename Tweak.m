// hpke_dumper v6 — ZERO runtime class scanning, pure string discovery
// crash history: v3-v5 all crash from walking ObjC class lists/pointers
// v6: only objc_getClass by name (safe) + mach-o string search (no runtime)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <time.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
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

// ---- Hook ----
typedef void *(*EncFn)(void *, void *, void *, void *, void *, void *);
static EncFn o_enc;

static void *my_enc(void *self, void *_cmd, void *data, void *pk, void *info, void *aad) {
    void *result = o_enc(self, _cmd, data, pk, info, aad);
    @try {
        NSMutableString *L = [NSMutableString stringWithFormat:@"\n==== HPKE ENCRYPT ====\nClass: %s\n",
            class_getName([(__bridge id)self class])];
        NSData *pkD = (__bridge NSData *)pk;
        if (pkD && [pkD respondsToSelector:@selector(length)])
            [L appendFormat:@"SERVER_PK_HEX: %@\nSERVER_PK_B64: %@\nSERVER_PK_LEN: %lu\n",
                hexOf(pkD.bytes, pkD.length), [pkD base64EncodedStringWithOptions:0], (unsigned long)pkD.length];
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

// ---- Known class names (safe: objc_getClass returns nil) ----
static const char *kCandidates[] = {
    "FBHPKEEncryptor", "IGHPKEEncryptor",
    "FBEncryptionUtils", "IGEncryptionUtils",
    "FBHPKECryptoHelper", "IGHPKECryptoHelper",
    "FBCryptoHelper", "IGCryptoHelper",
    "FBHybridEncryption", "IGHybridEncryption",
    "FBAEADEncryptor", "IGAEADEncryptor",
    "FBSealedSenderCipher", "FBHPKECipher",
    "FBDeviceIntegrity", "IGDeviceIntegrity",
    "FBPrivacyEncryption", "FBASSCEncryption", "IGASSCEncryption",
    "FBEndToEndEncryption", "IGEndToEndEncryption",
    "FBCryptoService", "IGCryptoService",
    "FBPublicKeyEncryption", "IGPublicKeyEncryption",
    "FBHybridPublicKeyEncryption", "IGHybridPublicKeyEncryption",
    "FBKeyEncapsulation", "IGKeyEncapsulation",
    "FBSealedBox", "IGSealedBox",
    "FBDeviceBasedRecoveryEncryption", "IGDeviceBasedRecoveryEncryption",
    "FBRecoveryEncryption", "IGRecoveryEncryption",
    "FBIdentityVerificationEncryption", "IGIdentityVerificationEncryption",
    "FBAuthenticityEncryption", "IGAuthenticityEncryption",
    "FBSignalEncryption", "IGSignalEncryption",
    "FBContentEncryption", "IGContentEncryption",
    "FBEEEncryptor", "IGEEEncryptor",
    "FBEnrichmentEncryptor", "IGEnrichmentEncryptor",
    "FBMediumEnrichmentEncryptor", "IGMediumEnrichmentEncryptor",
    "FBSelfieEncryptor", "IGSelfieEncryptor",
    "FBIDVEncryptor", "IGIDVEncryptor",
    NULL
};

static BOOL tryKnownClasses(void) {
    SEL sel = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
    for (int i = 0; kCandidates[i]; i++) {
        Class c = objc_getClass(kCandidates[i]);
        if (!c) continue;
        Method m = class_getInstanceMethod(c, sel);
        if (!m) continue;
        o_enc = (EncFn)method_getImplementation(m);
        method_setImplementation(m, (IMP)my_enc);
        emit([NSString stringWithFormat:@"HOOKED %s", kCandidates[i]]);
        gHooked = YES;
        return YES;
    }
    return NO;
}

// ---- SAFE discovery: pure string scan of __objc_classnames + __objc_methnames ----
// NO runtime calls on classes. Just reads readonly mach-o sections.
static void safeDiscovery(void) {
    const char *targetSel = "encryptData:withPublicKey:withInfo:withAad:";
    size_t selLen = strlen(targetSel);

    // Keywords to filter interesting class names
    const char *keywords[] = {
        "ncrypt", "HPKE", "hpke", "Seal", "seal", "Cipher",
        "PublicKey", "Hybrid", "AEAD", "aead", "EE", "Enrichment",
        "enrichment", "Authenticity", "IDV", "idv", "Selfie",
        "Recovery", "DeviceBased", "Signal", NULL
    };

    NSMutableString *out = [NSMutableString stringWithString:@"\n==== DISCOVERY (string scan) ====\n"];
    uint32_t imgCount = _dyld_image_count();
    BOOL selFound = NO;

    for (uint32_t img = 0; img < imgCount; img++) {
        const struct mach_header *mh = _dyld_get_image_header(img);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

        // Check if this image has our selector in __objc_methnames
        unsigned long mnSize = 0;
        const uint8_t *methnames = getsectiondata((const struct mach_header_64 *)mh,
            "__TEXT", "__objc_methnames", &mnSize);
        if (!methnames || mnSize < selLen) continue;

        BOOL hasSel = NO;
        for (unsigned long off = 0; off + selLen <= mnSize; off++) {
            if (methnames[off] == 'e' && memcmp(methnames + off, targetSel, selLen) == 0
                && methnames[off + selLen] == '\0') {
                hasSel = YES;
                break;
            }
        }
        if (!hasSel) continue;

        const char *imgName = _dyld_get_image_name(img);
        [out appendFormat:@"IMAGE %u has selector: %s\n", img, imgName ?: "?"];
        selFound = YES;

        // Now scan __objc_classname in this image for crypto-related class names
        unsigned long cnSize = 0;
        const uint8_t *classnames = getsectiondata((const struct mach_header_64 *)mh,
            "__TEXT", "__objc_classname", &cnSize);
        if (!classnames) continue;

        int hits = 0;
        unsigned long pos = 0;
        while (pos < cnSize && hits < 100) {
            const char *name = (const char *)(classnames + pos);
            size_t nLen = strnlen(name, cnSize - pos);
            if (nLen == 0) { pos++; continue; }

            // Check if name contains any keyword
            for (int k = 0; keywords[k]; k++) {
                if (strstr(name, keywords[k])) {
                    [out appendFormat:@"  CLASS: %s\n", name];
                    hits++;

                    // Try to hook it right now via objc_getClass (safe)
                    if (!gHooked) {
                        Class c = objc_getClass(name);
                        if (c) {
                            SEL sel = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
                            Method m = class_getInstanceMethod(c, sel);
                            if (m) {
                                o_enc = (EncFn)method_getImplementation(m);
                                method_setImplementation(m, (IMP)my_enc);
                                [out appendFormat:@"  >>> HOOKED %s <<<\n", name];
                                gHooked = YES;
                            }
                        }
                    }
                    break;
                }
            }
            pos += nLen + 1;
        }
        [out appendFormat:@"  (%d crypto-related classes found in this image)\n", hits];
    }

    if (!selFound) {
        [out appendString:@"selector NOT found in ANY loaded image\n"];
    }
    if (!gHooked) {
        [out appendString:@"HOOK NOT INSTALLED — add correct class name to kCandidates\n"];
    }
    emit(out);
}

// ---- Retry ----
static void retryInstall(int attempt) {
    if (gHooked) {
        emit(@"READY — trigger selfie IDV to capture HPKE params");
        return;
    }
    if (attempt >= 30) {
        emit(@"known names exhausted, running safe string discovery...");
        safeDiscovery();
        if (gHooked) emit(@"READY (via discovery) — trigger selfie IDV");
        return;
    }
    if (tryKnownClasses()) {
        emit(@"READY — trigger selfie IDV to capture HPKE params");
        return;
    }
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
        emit(@"hpke_dumper v6 loaded");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(0); });
    }
}
