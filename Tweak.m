// hpke_dumper v7 — full-image string scan for selector discovery
// v6 searched only __TEXT,__objc_methnames — IG 454.1 (407MB, chained fixups)
// may store selectors elsewhere. v7 scans ALL segments.
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

// ---- Hook ----
typedef void *(*EncFn)(void *, void *, void *, void *, void *, void *);
static EncFn o_enc;

static void *my_enc(void *self, void *_cmd, void *data, void *pk, void *info, void *aad) {
    void *result = o_enc(self, _cmd, data, pk, info, aad);
    @try {
        NSMutableString *L = [NSMutableString stringWithFormat:@"\n==== HPKE ENCRYPT ====\nClass: %s\nSEL: %s\n",
            class_getName([(__bridge id)self class]), sel_getName(_cmd)];
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

// ---- All selectors to try (exact + alternative names from spec) ----
static const char *kSelectors[] = {
    "encryptData:withPublicKey:withInfo:withAad:",
    "encryptData:withPublicKey:withInfo:withAAD:",
    "encryptData:publicKey:info:aad:",
    "encryptDataPadded:withPublicKey:withInfo:withAad:",
    "encryptDataPadded:withPublicKey:withInfo:withAAD:",
    "encryptStringPadded:withPublicKey:withInfo:withAad:",
    "_encryptAndUploadData:forGroup:forUseCase:successCallback:failureCallback:",
    "uploadE2EEData:forGroup:ofUseCase:uploadCallback:",
    NULL
};

// ---- Known class names ----
static const char *kClasses[] = {
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
    "FBEEEncryptor", "IGEEEncryptor",
    "FBEnrichmentEncryptor", "IGEnrichmentEncryptor",
    "FBContentEncryption", "IGContentEncryption",
    "FBAuthenticityEncryption", "IGAuthenticityEncryption",
    "AuthenticityOnDeviceSignalsTracker",
    "IGAuthenticityOnDeviceSignalsTracker",
    "FBAuthenticityOnDeviceSignalsTracker",
    NULL
};

static BOOL tryKnown(void) {
    for (int s = 0; kSelectors[s]; s++) {
        SEL sel = sel_registerName(kSelectors[s]);
        for (int c = 0; kClasses[c]; c++) {
            Class cls = objc_getClass(kClasses[c]);
            if (!cls) continue;
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) m = class_getClassMethod(cls, sel);
            if (!m) continue;
            o_enc = (EncFn)method_getImplementation(m);
            method_setImplementation(m, (IMP)my_enc);
            emit([NSString stringWithFormat:@"HOOKED %s -[%s]", kClasses[c], kSelectors[s]]);
            gHooked = YES;
            return YES;
        }
    }
    return NO;
}

// ---- Discovery: scan ALL segments of ALL images for selector substrings ----
static void fullDiscovery(void) {
    // Needle strings to look for anywhere in the binary
    const char *needles[] = {
        "encryptData:with",
        "encryptData:pub",
        "encryptDataPadded",
        "encryptStringPadded",
        "encryptAndUploadData",
        "uploadE2EEData",
        "HPKE_0020",
        "3P_CONV_ENC",
        "recipientPkB64url",
        NULL
    };

    NSMutableString *out = [NSMutableString stringWithString:@"\n==== FULL IMAGE DISCOVERY ====\n"];
    uint32_t imgCount = _dyld_image_count();
    [out appendFormat:@"Total loaded images: %u\n", imgCount];

    // Only scan first few images (main binary + key frameworks)
    uint32_t scanLimit = imgCount < 15 ? imgCount : 15;

    for (uint32_t img = 0; img < scanLimit; img++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(img);
        if (!mh || mh->header.magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        const char *imgName = _dyld_get_image_name(img);

        // Walk load commands to find all segments
        const uint8_t *ptr = (const uint8_t *)mh + sizeof(struct mach_header_64);
        int foundInImage = 0;

        for (uint32_t cmd = 0; cmd < mh->header.ncmds && foundInImage < 20; cmd++) {
            const struct load_command *lc = (const struct load_command *)ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;
                // Skip __LINKEDIT (huge, no strings), __PAGEZERO
                if (strcmp(seg->segname, "__LINKEDIT") == 0 || strcmp(seg->segname, "__PAGEZERO") == 0) {
                    ptr += lc->cmdsize;
                    continue;
                }

                const struct section_64 *sections = (const struct section_64 *)(ptr + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < seg->nsects && foundInImage < 20; s++) {
                    const uint8_t *data = (const uint8_t *)(sections[s].addr + slide);
                    uint64_t size = sections[s].size;
                    if (size < 10 || size > 300 * 1024 * 1024) continue;

                    for (int n = 0; needles[n]; n++) {
                        size_t nLen = strlen(needles[n]);
                        if (nLen > size) continue;

                        // Safe bounded search
                        for (uint64_t off = 0; off + nLen <= size; off++) {
                            if (data[off] == needles[n][0] && memcmp(data + off, needles[n], nLen) == 0) {
                                // Found! Log context: 80 chars around the match
                                uint64_t ctx_start = off > 40 ? off - 40 : 0;
                                uint64_t ctx_end = off + nLen + 40;
                                if (ctx_end > size) ctx_end = size;
                                NSMutableString *ctx = [NSMutableString new];
                                for (uint64_t i = ctx_start; i < ctx_end; i++) {
                                    char c = (char)data[i];
                                    [ctx appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
                                }
                                [out appendFormat:@"HIT img=%u seg=%.16s sect=%.16s off=0x%llx needle=%s\n  ctx: %@\n",
                                    img, seg->segname, sections[s].sectname, (unsigned long long)off,
                                    needles[n], ctx];
                                foundInImage++;
                                break; // next needle
                            }
                        }
                    }
                }
            }
            ptr += lc->cmdsize;
        }
        if (foundInImage > 0)
            [out appendFormat:@"  image: %s (%d hits)\n", imgName, foundInImage];
    }

    // Also: dump __objc_methnames section info for diagnostics
    const struct mach_header_64 *mainMH = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (mainMH) {
        // Try all known section locations for methnames
        const char *segs[] = {"__TEXT", "__DATA", "__DATA_CONST", "__OBJC", NULL};
        const char *sects[] = {"__objc_methnames", "__objc_selrefs", "__methnames", NULL};
        for (int sg = 0; segs[sg]; sg++) {
            for (int sc = 0; sects[sc]; sc++) {
                unsigned long sz = 0;
                const uint8_t *d = getsectiondata(mainMH, segs[sg], sects[sc], &sz);
                if (d && sz > 0)
                    [out appendFormat:@"SECTION %s,%s exists: %lu bytes at %p\n", segs[sg], sects[sc], sz, d];
            }
        }
    }

    emit(out);
}

// ---- Retry ----
static void retryInstall(int attempt) {
    if (gHooked) {
        emit(@"READY — trigger selfie IDV");
        return;
    }
    if (attempt >= 20) {
        emit(@"known names exhausted, running full discovery...");
        fullDiscovery();
        if (!gHooked) emit(@"DISCOVERY DONE — check syslog/hpke_dump.txt for hits");
        return;
    }
    if (tryKnown()) {
        emit(@"READY — trigger selfie IDV");
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
        emit(@"hpke_dumper v7 loaded");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(0); });
    }
}
