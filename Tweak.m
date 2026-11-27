// hpke_dumper v17 — hook BOTH: FBSharedFramework copy AND main binary copy
// v15/v16 hooked only FBSharedFramework copy, but main binary has its own
// static copy that HPKE code actually calls.
// Strategy: scan main binary __TEXT for the function prologue signature,
// then inline-hook ALL matches.
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
static int gHookCount = 0;

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

// We need separate trampolines for each hook site
static uint8_t tramp1[4096] __attribute__((aligned(16384)));
static uint8_t tramp2[4096] __attribute__((aligned(16384)));
static aead_fn orig_aead_1 = NULL;
static aead_fn orig_aead_2 = NULL;

static void log_aead(const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k,
    const unsigned char *c, unsigned long long *clen_p, int ret, int hookIdx) {
    @try {
        emit([NSString stringWithFormat:@"==== AEAD ENCRYPT (hook #%d) ====", hookIdx]);
        emit([NSString stringWithFormat:@"PT_LEN: %llu", mlen]);
        if (m && mlen > 0) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
        if (ad && adlen > 0) {
            emit([NSString stringWithFormat:@"AAD_LEN: %llu", adlen]);
            emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
            NSData *aaD = [NSData dataWithBytes:ad length:(NSUInteger)adlen];
            NSString *aaS = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
            if (aaS) emit([NSString stringWithFormat:@"AAD_STR: %@", aaS]);
        } else { emit(@"AAD: (empty)"); }
        if (npub) emit([NSString stringWithFormat:@"NONCE_12B: %@", hexOf(npub, 12)]);
        if (k) emit([NSString stringWithFormat:@"KEY_32B: %@", hexOf(k, 32)]);
        if (c && clen_p) emit([NSString stringWithFormat:@"CT_LEN: %llu", *clen_p]);
        if (m && mlen > 1000) {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            [[NSData dataWithBytes:m length:(NSUInteger)mlen] writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"log err: %@", e]); }
}

static int my_aead_1(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead_1(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    log_aead(m, mlen, ad, adlen, npub, k, c, clen_p, ret, 1);
    return ret;
}

static int my_aead_2(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead_2(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    log_aead(m, mlen, ad, adlen, npub, k, c, clen_p, ret, 2);
    return ret;
}

static int do_inline_hook(void *target, void *replacement, uint8_t *tramp_buf, void **out_orig) {
    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t repl_addr = (uintptr_t)replacement;
    vm_size_t ps = 0x4000;

    vm_address_t page = target_addr & ~(vm_address_t)(ps - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, ps, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS)
        kr = vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"vm_protect(target) FAIL: %d", kr]);
        return -1;
    }

    uint8_t saved[16];
    memcpy(saved, target, 16);

    vm_address_t tp = (vm_address_t)tramp_buf & ~(vm_address_t)(ps - 1);
    kr = vm_protect(mach_task_self(), tp, ps, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) return -2;

    memcpy(tramp_buf, saved, 16);
    uint32_t ldr = 0x58000050, br = 0xD61F0200;
    uintptr_t resume = target_addr + 16;
    memcpy(tramp_buf + 16, &ldr, 4);
    memcpy(tramp_buf + 20, &br, 4);
    memcpy(tramp_buf + 24, &resume, 8);

    kr = vm_protect(mach_task_self(), tp, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) return -3;
    sys_icache_invalidate(tramp_buf, 32);
    *out_orig = tramp_buf;

    uint32_t hook[4];
    hook[0] = 0x58000050;
    hook[1] = 0xD61F0200;
    memcpy(&hook[2], &repl_addr, 8);
    memcpy(target, hook, 16);

    vm_protect(mach_task_self(), page, ps, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(target, 16);
    return 0;
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v17 loaded (dual hook: framework + main binary)");

        // Hook 1: FBSharedFramework copy (via dlsym)
        void *fw_ptr = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        emit([NSString stringWithFormat:@"dlsym(framework): %p", fw_ptr]);
        if (fw_ptr) {
            int r = do_inline_hook(fw_ptr, (void *)my_aead_1, tramp1, (void **)&orig_aead_1);
            emit([NSString stringWithFormat:@"hook1(framework): %d", r]);
            if (r == 0) gHookCount++;
        }

        // Hook 2: main binary copy — scan __TEXT for the same prologue
        // Known prologue: ff0307d1 fc6f16a9 fa6717a9 f85f18a9
        const uint8_t prologue[] = {0xff,0x03,0x07,0xd1, 0xfc,0x6f,0x16,0xa9,
                                    0xfa,0x67,0x17,0xa9, 0xf8,0x5f,0x18,0xa9};
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
        intptr_t slide = _dyld_get_image_vmaddr_slide(0);
        emit([NSString stringWithFormat:@"main binary: mh=%p slide=0x%lx", mh, (long)slide]);

        unsigned long textSize = 0;
        const uint8_t *textData = getsectiondata(mh, "__TEXT", "__text", &textSize);
        emit([NSString stringWithFormat:@"__TEXT,__text: %p size=%lu", textData, textSize]);

        if (textData && textSize > 16) {
            int found = 0;
            // Scan for prologue (functions are 4-byte aligned)
            for (unsigned long off = 0; off + 16 <= textSize && found < 5; off += 4) {
                if (memcmp(textData + off, prologue, 16) == 0) {
                    void *match = (void *)(textData + off);
                    emit([NSString stringWithFormat:@"PROLOGUE MATCH at %p (offset 0x%lx)", match, off]);
                    found++;

                    // Don't re-hook the same address we already hooked
                    if (match == fw_ptr) {
                        emit(@"  same as framework — skip");
                        continue;
                    }

                    if (gHookCount < 2) {
                        int r = do_inline_hook(match, (void *)my_aead_2, tramp2, (void **)&orig_aead_2);
                        emit([NSString stringWithFormat:@"hook2(main): %d", r]);
                        if (r == 0) gHookCount++;
                    }
                }
            }
            if (found == 0) emit(@"NO prologue matches in main binary __text");
        }

        // Also try Ghidra thunk address + slide
        if (gHookCount < 2) {
            void *thunk = (void *)(0x10d5bad3c + slide);
            emit([NSString stringWithFormat:@"Ghidra thunk+slide: %p bytes=%@", thunk, hexOf(thunk, 8)]);
        }

        emit([NSString stringWithFormat:@"total hooks: %d", gHookCount]);
        if (gHookCount > 0) emit(@"READY — trigger selfie IDV");
    }
}
