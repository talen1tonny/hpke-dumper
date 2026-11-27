// hpke_dumper v5 — NO objc_copyClassList (crashes IG), discovery + hook
// Pattern: mqtt_dumper v5 (objc_getClass by known name + retry loop)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <time.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <string.h>

static NSFileHandle *gFH;
static NSString *gPath;
static BOOL gHooked = NO;
static BOOL gDiscoveryDone = NO;

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

// ---- Hook (original FIRST, log after) ----
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

// ---- Install by known class name (SAFE — objc_getClass returns nil if absent) ----
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

// ---- DISCOVERY: scan __objc_selrefs to find class name (safe, no objc_copyClassList) ----
// When no known name matches, scan loaded images for the selector string,
// then walk __objc_classlist to find which class owns it.
static void discoverClass(void) {
    if (gDiscoveryDone) return;
    gDiscoveryDone = YES;

    const char *target = "encryptData:withPublicKey:withInfo:withAad:";
    size_t tLen = strlen(target);
    NSMutableString *found = [NSMutableString stringWithString:@"DISCOVERY:\n"];
    int hits = 0;

    // Walk all loaded images looking for the selector in __objc_methnames
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t img = 0; img < imgCount && hits < 20; img++) {
        const struct mach_header *mh = _dyld_get_image_header(img);
        if (!mh) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);

        unsigned long size = 0;
        const uint8_t *sect = getsectiondata((const struct mach_header_64 *)mh,
            "__TEXT", "__objc_methnames", &size);
        if (!sect || size < tLen) continue;

        // Search for our selector string in this section
        for (unsigned long off = 0; off + tLen <= size; off++) {
            if (memcmp(sect + off, target, tLen) == 0 && sect[off + tLen] == '\0') {
                const char *imgName = _dyld_get_image_name(img);
                [found appendFormat:@"  SEL found in image %u: %s (offset 0x%lx)\n",
                    img, imgName ?: "?", off];
                hits++;
                break;
            }
        }
    }

    if (hits == 0) {
        [found appendString:@"  selector NOT FOUND in any loaded image\n"];
    }

    // Also try: scan __objc_classlist of the main image for classes with this method
    // The main executable is image 0
    const struct mach_header *mainMH = _dyld_get_image_header(0);
    if (mainMH) {
        unsigned long clsSize = 0;
        const void **clsList = (const void **)getsectiondata(
            (const struct mach_header_64 *)mainMH, "__DATA", "__objc_classlist", &clsSize);
        if (!clsList) {
            clsList = (const void **)getsectiondata(
                (const struct mach_header_64 *)mainMH, "__DATA_CONST", "__objc_classlist", &clsSize);
        }
        intptr_t mainSlide = _dyld_get_image_vmaddr_slide(0);
        if (clsList && clsSize > 0) {
            unsigned long count = clsSize / sizeof(void *);
            [found appendFormat:@"  main image has %lu class refs\n", count];
            SEL sel = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
            int checked = 0, matched = 0;
            for (unsigned long i = 0; i < count && matched < 10; i++) {
                @try {
                    Class c = (__bridge Class)(void *)((uintptr_t)clsList[i] + mainSlide);
                    if (!c) continue;
                    // class_respondsToSelector is safer than class_getInstanceMethod for unrealized classes
                    const char *name = class_getName(c);
                    if (!name) continue;
                    checked++;
                    Method m = class_getInstanceMethod(c, sel);
                    if (m) {
                        [found appendFormat:@"  MATCH: %s\n", name];
                        matched++;
                        // Auto-hook!
                        if (!gHooked) {
                            o_enc = (EncFn)method_getImplementation(m);
                            method_setImplementation(m, (IMP)my_enc);
                            [found appendFormat:@"  AUTO-HOOKED %s\n", name];
                            gHooked = YES;
                        }
                    }
                } @catch (__unused id e) { continue; }
            }
            [found appendFormat:@"  checked %d classes, %d matches\n", checked, matched];
        }
    }
    emit(found);
}

// ---- Retry loop (dispatch_after on utility queue — same pattern as mqtt_dumper) ----
static void retryInstall(int attempt) {
    if (gHooked) {
        emit(@"READY — trigger selfie IDV to capture HPKE params");
        return;
    }
    if (attempt >= 30) {
        emit(@"known names exhausted after 30 attempts, running discovery...");
        discoverClass();
        if (gHooked) {
            emit(@"READY (via discovery) — trigger selfie IDV");
        } else {
            emit(@"DISCOVERY DONE — check hpke_dump.txt for class names, add to kCandidates");
        }
        return;
    }
    if (tryKnownClasses()) return;
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
        emit(@"hpke_dumper v5 loaded");
        // 3 second delay, then retry every 0.5s for 15s = 30 attempts
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(0); });
    }
}
