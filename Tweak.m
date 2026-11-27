// hpke_dumper v18 — v15 (working hook) + delayed main binary scan (diagnostic only)
// v17 crashed from getsectiondata on 407MB __text at startup.
// v18: hook framework first (proven), then scan main binary in background after 10s.
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include <mach/mach.h>
#include <string.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>

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

typedef int (*aead_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);

static aead_fn orig_aead = NULL;
static uint8_t trampoline_buf[4096] __attribute__((aligned(16384)));

static int my_aead(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    @try {
        emit([NSString stringWithFormat:@"==== AEAD ENCRYPT (mlen=%llu) ====", mlen]);
        if (m && mlen > 0) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
        if (ad && adlen > 0) {
            emit([NSString stringWithFormat:@"AAD_LEN: %llu", adlen]);
            emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
            NSData *aaD = [NSData dataWithBytes:ad length:(NSUInteger)adlen];
            NSString *aaS = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
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

static int do_inline_hook(void *target, void *replacement, void **out_orig) {
    uintptr_t ta = (uintptr_t)target, ra = (uintptr_t)replacement;
    vm_size_t ps = 0x4000;
    vm_address_t page = ta & ~(vm_address_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, ps, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr) kr = vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr) { emit([NSString stringWithFormat:@"vm_protect FAIL: %d", kr]); return -1; }

    uint8_t saved[16]; memcpy(saved, target, 16);
    emit([NSString stringWithFormat:@"original: %@", hexOf(saved, 16)]);

    vm_address_t tp = (vm_address_t)trampoline_buf & ~(vm_address_t)(ps - 1);
    vm_protect(mach_task_self(), tp, ps, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    memcpy(trampoline_buf, saved, 16);
    uint32_t ldr = 0x58000050, br = 0xD61F0200;
    uintptr_t resume = ta + 16;
    memcpy(trampoline_buf + 16, &ldr, 4);
    memcpy(trampoline_buf + 20, &br, 4);
    memcpy(trampoline_buf + 24, &resume, 8);
    vm_protect(mach_task_self(), tp, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(trampoline_buf, 32);
    *out_orig = trampoline_buf;

    uint32_t hook[4]; hook[0] = 0x58000050; hook[1] = 0xD61F0200;
    memcpy(&hook[2], &ra, 8);
    memcpy(target, hook, 16);
    vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(target, 16);
    emit(@"hook OK");
    return 0;
}

// ---- Delayed background scan of main binary (diagnostic) ----
static void scanMainBinary(void) {
    emit(@"=== MAIN BINARY SCAN ===");
    const uint8_t prologue[] = {0xff,0x03,0x07,0xd1, 0xfc,0x6f,0x16,0xa9,
                                0xfa,0x67,0x17,0xa9, 0xf8,0x5f,0x18,0xa9};
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    emit([NSString stringWithFormat:@"slide=0x%lx", (long)slide]);

    // Also check Ghidra thunk address
    void *thunk = (void *)((uintptr_t)0x10d5bad3c + slide);
    @try {
        emit([NSString stringWithFormat:@"thunk@%p: %@", thunk, hexOf(thunk, 16)]);
    } @catch (id e) {
        emit([NSString stringWithFormat:@"thunk read fail: %@", e]);
    }

    unsigned long textSize = 0;
    const uint8_t *textData = getsectiondata(mh, "__TEXT", "__text", &textSize);
    emit([NSString stringWithFormat:@"__text: %lu bytes", textSize]);
    if (!textData || textSize < 16) { emit(@"no __text"); return; }

    // Scan in chunks to avoid watchdog (yield every 50MB)
    int found = 0;
    for (unsigned long off = 0; off + 16 <= textSize && found < 10; off += 4) {
        if (textData[off] == 0xff && memcmp(textData + off, prologue, 16) == 0) {
            void *match = (void *)(textData + off);
            emit([NSString stringWithFormat:@"MATCH at %p (off=0x%lx in __text)", match, off]);
            found++;
        }
    }
    emit([NSString stringWithFormat:@"scan done: %d matches", found]);
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v18 loaded");

        // Hook 1: framework copy (proven in v15)
        void *fw = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        emit([NSString stringWithFormat:@"dlsym: %p", fw]);
        if (fw) {
            int r = do_inline_hook(fw, (void *)my_aead, (void **)&orig_aead);
            emit([NSString stringWithFormat:@"hook: %d", r]);
        }
        emit(@"READY (framework hook). Background scan in 10s...");

        // Scan main binary after 10s delay (avoid startup crash)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ scanMainBinary(); });
    }
}
