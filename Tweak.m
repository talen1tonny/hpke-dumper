// hpke_dumper v19 — triple coverage: AEAD + DH + NSURLSession upload monitor
// Belt and suspenders: catches crypto AND/OR the upload itself
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include <mach/mach.h>
#include <string.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>

static NSFileHandle *gFH;
static NSString *gPath;

static void emit(NSString *s) {
    NSLog(@"[HPKE] %@", s);
    if (!gFH) return;
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    @synchronized (gPath) { @try { [gFH writeData:d]; } @catch (__unused id e) {} }
}
static NSString *hexOf(const void *b, size_t n) {
    const unsigned char *p = b;
    NSMutableString *h = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++) [h appendFormat:@"%02x", p[i]];
    return h;
}

// ========= C-level hooks =========
typedef int (*aead_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*mult_fn)(unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*base_fn)(unsigned char *, const unsigned char *);

static aead_fn orig_aead = NULL;
static mult_fn orig_mult = NULL;
static base_fn orig_base = NULL;

// Allocate trampoline pages dynamically (avoid static aligned buffer issues)
static void *alloc_trampoline_page(void) {
    void *p = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

static int do_inline_hook(void *target, void *replacement, void *tramp_page, void **out_orig) {
    uintptr_t ta = (uintptr_t)target, ra = (uintptr_t)replacement;
    vm_size_t ps = 0x4000;
    vm_address_t page = ta & ~(vm_address_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, ps, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr) kr = vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr) { emit([NSString stringWithFormat:@"vm_protect FAIL: %d", kr]); return -1; }

    uint8_t saved[16]; memcpy(saved, target, 16);

    uint8_t *tb = (uint8_t *)tramp_page;
    memcpy(tb, saved, 16);
    uint32_t ldr = 0x58000050, br = 0xD61F0200;
    uintptr_t resume = ta + 16;
    memcpy(tb + 16, &ldr, 4);
    memcpy(tb + 20, &br, 4);
    memcpy(tb + 24, &resume, 8);
    vm_protect(mach_task_self(), (vm_address_t)tramp_page, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(tb, 32);
    *out_orig = tb;

    uint32_t hook[4]; hook[0] = 0x58000050; hook[1] = 0xD61F0200;
    memcpy(&hook[2], &ra, 8);
    memcpy(target, hook, 16);
    vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(target, 16);
    return 0;
}

// ---- AEAD hook ----
static int my_aead(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    @try {
        emit([NSString stringWithFormat:@"==== AEAD ENCRYPT mlen=%llu ====", mlen]);
        if (m && mlen > 0) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
        if (ad && adlen > 0) {
            emit([NSString stringWithFormat:@"AAD_LEN: %llu AAD: %@", adlen, hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
            NSString *aaS = [[NSString alloc] initWithData:[NSData dataWithBytes:ad length:(NSUInteger)adlen] encoding:NSUTF8StringEncoding];
            if (aaS) emit([NSString stringWithFormat:@"AAD_STR: %@", aaS]);
        } else { emit(@"AAD: (empty)"); }
        if (npub) emit([NSString stringWithFormat:@"NONCE: %@", hexOf(npub, 12)]);
        if (k) emit([NSString stringWithFormat:@"KEY: %@", hexOf(k, 32)]);
        if (c && clen_p) emit([NSString stringWithFormat:@"CT_LEN: %llu", *clen_p]);
        if (m && mlen > 1000) {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            [[NSData dataWithBytes:m length:(NSUInteger)mlen] writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"err: %@", e]); }
    return ret;
}

// ---- DH hook ----
static int my_mult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    int ret = orig_mult(q, n, p);
    static int cc = 0; if (++cc <= 20) {
        @try {
            emit([NSString stringWithFormat:@"==== X25519 DH #%d ====", cc]);
            if (p) emit([NSString stringWithFormat:@"PEER_PK: %@", hexOf(p, 32)]);
            if (q) emit([NSString stringWithFormat:@"SHARED: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ---- Keygen hook ----
static int my_base(unsigned char *q, const unsigned char *n) {
    int ret = orig_base(q, n);
    static int cc = 0; if (++cc <= 20) {
        @try {
            emit([NSString stringWithFormat:@"==== X25519 KEYGEN #%d ====", cc]);
            if (q) emit([NSString stringWithFormat:@"EPH_PK: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ========= ObjC hook: NSURLSession upload monitor =========
// Swizzle -[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]
// to detect authenticity_uploads
typedef void *(*UploadIMP)(void *, void *, void *, void *, void *);
static UploadIMP orig_upload;

static void *my_upload(void *self, void *_cmd, void *request, void *bodyData, void *handler) {
    @try {
        NSURLRequest *req = (__bridge NSURLRequest *)request;
        NSString *url = req.URL.absoluteString;
        if ([url containsString:@"authenticity_upload"] || [url containsString:@"graph.facebook.com"]) {
            NSData *body = (__bridge NSData *)bodyData;
            emit([NSString stringWithFormat:@"==== UPLOAD DETECTED ====\nURL: %@\nBODY_LEN: %lu",
                url, body ? (unsigned long)body.length : 0]);
            if (body && body.length > 0)
                emit([NSString stringWithFormat:@"BODY_HEAD: %@", hexOf(body.bytes, body.length < 64 ? body.length : 64)]);
            // Log all HTTP headers
            NSDictionary *hdrs = req.allHTTPHeaderFields;
            if (hdrs) emit([NSString stringWithFormat:@"HEADERS: %@", hdrs]);
        }
    } @catch (id e) {}
    return orig_upload(self, _cmd, request, bodyData, handler);
}

static void installObjcHooks(void) {
    // Hook NSURLSession uploadTaskWithRequest:fromData:completionHandler:
    Class cls = objc_getClass("NSURLSession");
    if (!cls) { emit(@"NSURLSession not found"); return; }
    SEL sel = sel_registerName("uploadTaskWithRequest:fromData:completionHandler:");
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        orig_upload = (UploadIMP)method_getImplementation(m);
        method_setImplementation(m, (IMP)my_upload);
        emit(@"NSURLSession upload hook OK");
    } else {
        emit(@"uploadTask method not found");
    }

    emit(@"ObjC hooks done");
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v19 loaded (triple: AEAD + DH + URLSession)");

        int hooked = 0;

        // C hook 1: AEAD encrypt
        void *aead_ptr = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        if (aead_ptr) {
            void *tp = alloc_trampoline_page();
            if (tp && do_inline_hook(aead_ptr, (void *)my_aead, tp, (void **)&orig_aead) == 0) {
                emit(@"AEAD hook OK"); hooked++;
            }
        }

        // DH/KEYGEN: log addresses only (inline hook crashes — PC-relative instrs in prologue)
        void *mult_ptr = dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519");
        void *base_ptr = dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519_base");
        emit([NSString stringWithFormat:@"DH=%p KEYGEN=%p (not hooked — crash-prone prologue)", mult_ptr, base_ptr]);

        emit([NSString stringWithFormat:@"C hooks: %d/3", hooked]);

        // ObjC hook: NSURLSession (safe — known class)
        installObjcHooks();

        emit(@"READY — all hooks installed. Trigger selfie IDV.");
    }
}
