// hpke_dumper v1 — extracts HPKE encryption parameters from Instagram's
// EE blob (MEDIUM_ENRICHMENT_NATIVE) enrichment flow.
//
// Pure ObjC runtime swizzling (NO Substrate/Logos/ElleKit).
// All IMPs typed as void* for ARC neutrality (same pattern as mqtt_dumper v5+).
//
// Hooks:
//   1. -[* encryptData:withPublicKey:withInfo:withAad:] — the HPKE encrypt call
//      → logs SERVER PUBLIC KEY, info (nonce), AAD, plaintext size, blob
//   2. +[SSZipArchive createZipFileAtPath:withContentsOfDirectory:] — ZIP creation
//      → logs the directory being zipped (enrichment signals)
//
// Output: <app>/Documents/hpke_dump.txt + NSLog
// Usage: inject via TrollFools into Instagram 454.1

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// ----------------------------- output sink --------------------------------
static NSFileHandle *gFH;
static NSString     *gPath;

static NSString *nowStr(void) {
    static NSDateFormatter *f;
    if (!f) { f = [NSDateFormatter new]; f.dateFormat = @"HH:mm:ss.SSS"; }
    return [f stringFromDate:[NSDate date]];
}
static void emit(NSString *block) {
    NSLog(@"[HPKE] %@", block);
    if (gFH) {
        NSData *d = [[block stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        @synchronized (gPath) { @try { [gFH writeData:d]; } @catch (__unused NSException *e) {} }
    }
}
static NSString *hexOf(const unsigned char *b, NSUInteger n) {
    NSMutableString *h = [NSMutableString stringWithCapacity:n * 3];
    for (NSUInteger i = 0; i < n; i++) [h appendFormat:@"%02x", b[i]];
    return h;
}

// ----------------------------- swizzle helper (pure ObjC runtime) ----------
static int swizzleInstance(Class c, const char *selname, IMP newImp, void *origStore) {
    Method m = class_getInstanceMethod(c, sel_registerName(selname));
    if (!m) return 0;
    *(IMP *)origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return 1;
}
static int swizzleClass(Class c, const char *selname, IMP newImp, void *origStore) {
    Method m = class_getClassMethod(c, sel_registerName(selname));
    if (!m) return 0;
    *(IMP *)origStore = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return 1;
}

// ----------------------------- Hook 1: encryptData:withPublicKey:withInfo:withAad:
// Signature: -(NSData*)encryptData:(NSData*)data withPublicKey:(NSData*)pk withInfo:(NSData*)info withAad:(NSData*)aad
typedef void *(*EncryptFn)(void *self, void *_cmd, void *data, void *publicKey, void *info, void *aad);
static EncryptFn o_encrypt;

static void *my_encrypt(void *self, void *_cmd, void *data, void *publicKey, void *info, void *aad) {
    @try {
        NSData *pkData  = (__bridge NSData *)publicKey;
        NSData *inData  = (__bridge NSData *)data;
        NSData *infoD   = (__bridge NSData *)info;
        NSData *aadD    = (__bridge NSData *)aad;

        NSMutableString *log = [NSMutableString string];
        [log appendFormat:@"\n╔══════════════════════════════════════════════════╗\n"];
        [log appendFormat:@"║   HPKE encryptData INTERCEPTED @ %@       ║\n", nowStr()];
        [log appendFormat:@"╚══════════════════════════════════════════════════╝\n"];
        [log appendFormat:@"Class: %s\n", class_getName([(__bridge id)self class])];

        // SERVER PUBLIC KEY
        if (pkData && [pkData isKindOfClass:[NSData class]]) {
            [log appendFormat:@"\n★★★ SERVER_PUBLIC_KEY_HEX: %@\n", hexOf(pkData.bytes, pkData.length)];
            [log appendFormat:@"★★★ SERVER_PUBLIC_KEY_B64: %@\n",
                [pkData base64EncodedStringWithOptions:0]];
            [log appendFormat:@"★★★ SERVER_PUBLIC_KEY_LEN: %lu\n", (unsigned long)pkData.length];
        } else {
            [log appendFormat:@"\n★ publicKey is nil or not NSData\n"];
        }

        // INFO (nonce)
        if (infoD && [infoD isKindOfClass:[NSData class]]) {
            NSString *infoStr = [[NSString alloc] initWithData:infoD encoding:NSUTF8StringEncoding];
            [log appendFormat:@"\nINFO_HEX: %@\n", hexOf(infoD.bytes, infoD.length)];
            [log appendFormat:@"INFO_STR: %@\n", infoStr ?: @"(not UTF-8)"];
            [log appendFormat:@"INFO_LEN: %lu\n", (unsigned long)infoD.length];
        } else {
            [log appendFormat:@"\nINFO: (nil)\n"];
        }

        // AAD
        if (aadD && [aadD isKindOfClass:[NSData class]]) {
            NSUInteger aadLen = aadD.length;
            [log appendFormat:@"\nAAD_LEN: %lu\n", (unsigned long)aadLen];
            if (aadLen > 0) {
                [log appendFormat:@"AAD_HEX: %@\n", hexOf(aadD.bytes, aadLen < 512 ? aadLen : 512)];
                NSString *aadStr = [[NSString alloc] initWithData:aadD encoding:NSUTF8StringEncoding];
                if (aadStr) [log appendFormat:@"AAD_STR: %@\n", aadStr];
            } else {
                [log appendFormat:@"AAD: (empty)\n"];
            }
        } else {
            [log appendFormat:@"\nAAD: (nil)\n"];
        }

        // PLAINTEXT
        if (inData && [inData isKindOfClass:[NSData class]]) {
            [log appendFormat:@"\nPLAINTEXT_LEN: %lu\n", (unsigned long)inData.length];
            NSUInteger hdrLen = inData.length < 64 ? inData.length : 64;
            [log appendFormat:@"PLAINTEXT_HEAD: %@\n", hexOf(inData.bytes, hdrLen)];

            // Save plaintext ZIP to Documents for analysis
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zipPath = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_plaintext_%@.zip", nowStr()]];
            [inData writeToFile:zipPath atomically:YES];
            [log appendFormat:@"PLAINTEXT_SAVED: %@\n", zipPath];
        }

        emit(log);
    } @catch (NSException *e) {
        emit([NSString stringWithFormat:@"[HPKE] hook error: %@", e]);
    }

    // Call original
    void *result = o_encrypt(self, _cmd, data, publicKey, info, aad);

    // Log result blob
    @try {
        NSData *blob = (__bridge NSData *)result;
        if (blob && [blob isKindOfClass:[NSData class]]) {
            NSUInteger blobLen = blob.length;
            NSUInteger hdrLen = blobLen < 48 ? blobLen : 48;
            emit([NSString stringWithFormat:@"RESULT_BLOB_LEN: %lu\nRESULT_BLOB_HEAD: %@\n",
                  (unsigned long)blobLen, hexOf(blob.bytes, hdrLen)]);
        }
    } @catch (__unused NSException *e) {}

    return result;
}

// ----------------------------- Hook 2: encryptDataPadded variant
static EncryptFn o_encryptPadded;

static void *my_encryptPadded(void *self, void *_cmd, void *data, void *publicKey, void *info, void *aad) {
    @try {
        NSData *pkData = (__bridge NSData *)publicKey;
        if (pkData && [pkData isKindOfClass:[NSData class]]) {
            emit([NSString stringWithFormat:@"\n=== encryptDataPadded @ %@ ===\n★ SERVER_PK: %@\n",
                  nowStr(), hexOf(pkData.bytes, pkData.length)]);
        }
    } @catch (__unused NSException *e) {}
    return o_encryptPadded(self, _cmd, data, publicKey, info, aad);
}

// ----------------------------- Hook 3: SSZipArchive
typedef void *(*ZipFn)(void *self, void *_cmd, void *path, void *source);
static ZipFn o_zip1; // createZipFileAtPath:withContentsOfDirectory:
static ZipFn o_zip2; // createZipFileAtPath:withFilesAtPaths:

static void *my_zip1(void *self, void *_cmd, void *path, void *source) {
    @try {
        emit([NSString stringWithFormat:@"\n=== SSZipArchive createZip @ %@ ===\n  path: %@\n  dir: %@\n",
              nowStr(), (__bridge NSString *)path, (__bridge NSString *)source]);

        // List the directory contents
        NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:(__bridge NSString *)source error:nil];
        for (NSString *f in files) {
            NSString *fp = [(__bridge NSString *)source stringByAppendingPathComponent:f];
            NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:fp error:nil];
            emit([NSString stringWithFormat:@"  file: %@ (%@ bytes)", f, attrs[NSFileSize]]);
        }
    } @catch (__unused NSException *e) {}
    return o_zip1(self, _cmd, path, source);
}
static void *my_zip2(void *self, void *_cmd, void *path, void *source) {
    @try {
        NSArray *paths = (__bridge NSArray *)source;
        emit([NSString stringWithFormat:@"\n=== SSZipArchive createZipWithFiles @ %@ ===\n  path: %@\n  files: %@\n",
              nowStr(), (__bridge NSString *)path, paths]);
    } @catch (__unused NSException *e) {}
    return o_zip2(self, _cmd, path, source);
}

// ----------------------------- runtime class discovery + hook installation
static BOOL gDoneEncrypt = NO;
static BOOL gDoneZip = NO;

static BOOL installHooks(void) {
    // Find class(es) implementing encryptData:withPublicKey:withInfo:withAad:
    if (!gDoneEncrypt) {
        SEL encSel = sel_registerName("encryptData:withPublicKey:withInfo:withAad:");
        SEL encPadSel = sel_registerName("encryptDataPadded:withPublicKey:withInfo:withAad:");
        unsigned int classCount = 0;
        Class *classes = objc_copyClassList(&classCount);
        for (unsigned int i = 0; i < classCount; i++) {
            if (class_getInstanceMethod(classes[i], encSel)) {
                const char *name = class_getName(classes[i]);
                int n = swizzleInstance(classes[i], "encryptData:withPublicKey:withInfo:withAad:",
                                        (IMP)my_encrypt, &o_encrypt);
                emit([NSString stringWithFormat:@"[HPKE] hooked %s encryptData (%d)", name, n]);

                // Also try padded variant on same class
                if (class_getInstanceMethod(classes[i], encPadSel)) {
                    swizzleInstance(classes[i], "encryptDataPadded:withPublicKey:withInfo:withAad:",
                                   (IMP)my_encryptPadded, &o_encryptPadded);
                    emit([NSString stringWithFormat:@"[HPKE] hooked %s encryptDataPadded", name]);
                }
                gDoneEncrypt = YES;
                break;
            }
        }
        free(classes);
    }

    // SSZipArchive
    if (!gDoneZip) {
        Class zipClass = objc_getClass("SSZipArchive");
        if (zipClass) {
            int n = 0;
            n += swizzleClass(zipClass, "createZipFileAtPath:withContentsOfDirectory:",
                              (IMP)my_zip1, &o_zip1);
            n += swizzleClass(zipClass, "createZipFileAtPath:withFilesAtPaths:",
                              (IMP)my_zip2, &o_zip2);
            emit([NSString stringWithFormat:@"[HPKE] hooked SSZipArchive (%d methods)", n]);
            gDoneZip = YES;
        }
    }

    return gDoneEncrypt && gDoneZip;
}

static void retryInstall(int attempt) {
    if (installHooks()) {
        emit(@"[HPKE] ALL HOOKS INSTALLED — trigger selfie IDV to capture");
        return;
    }
    if (attempt >= 120) {
        emit([NSString stringWithFormat:@"[HPKE] timeout: encrypt=%d zip=%d", gDoneEncrypt, gDoneZip]);
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ retryInstall(attempt + 1); });
}

__attribute__((constructor))
static void init_hpke_dumper(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit([NSString stringWithFormat:@"[HPKE] hpke_dumper v1 loaded — sink=%@", gPath]);
        retryInstall(0);
    }
}
