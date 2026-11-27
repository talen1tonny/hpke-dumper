// hpke_dumper v15 — inline hook via vm_protect (no Dobby, no fishhook)
// v13 on non-JB: vm_protect failed (protection failure)
// v15 on JB: vm_protect should work (jailbreak patches kernel)
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include <mach/mach.h>
#include <string.h>
#include <libkern/OSCacheControl.h>

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

static aead_fn orig_aead_trampoline = NULL;

static int my_aead(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead_trampoline(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    @try {
        if (mlen > 1000) {
            emit(@"==== AEAD ENCRYPT ====");
            emit([NSString stringWithFormat:@"PT_LEN: %llu", mlen]);
            if (m) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
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
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            [[NSData dataWithBytes:m length:(NSUInteger)mlen] writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"aead err: %@", e]); }
    return ret;
}

// ---- Trampoline buffer (page-aligned for vm_protect) ----
static uint8_t trampoline_buf[4096] __attribute__((aligned(16384)));

static int inline_hook(void *target, void *replacement, void **out_trampoline) {
    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replacement_addr = (uintptr_t)replacement;
    vm_size_t page_size = 0x4000; // 16K pages on iOS

    // Make target page writable
    vm_address_t page = target_addr & ~(vm_address_t)(page_size - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"vm_protect(target RW) FAILED: %d %s", kr, mach_error_string(kr)]);
        return -1;
    }

    // Save original 16 bytes
    uint8_t saved[16];
    memcpy(saved, target, 16);
    emit([NSString stringWithFormat:@"original: %@", hexOf(saved, 16)]);

    // Build trampoline: saved instructions + jump to target+16
    vm_address_t tramp_page = (vm_address_t)trampoline_buf & ~(vm_address_t)(page_size - 1);
    kr = vm_protect(mach_task_self(), tramp_page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"vm_protect(tramp RW) FAILED: %d", kr]);
        return -2;
    }

    memcpy(trampoline_buf, saved, 16);
    // LDR X16, [PC, #8]; BR X16; <resume_addr>
    uint32_t ldr_x16 = 0x58000050;
    uint32_t br_x16  = 0xD61F0200;
    uintptr_t resume_addr = target_addr + 16;
    memcpy(trampoline_buf + 16, &ldr_x16, 4);
    memcpy(trampoline_buf + 20, &br_x16, 4);
    memcpy(trampoline_buf + 24, &resume_addr, 8);

    // Make trampoline executable
    kr = vm_protect(mach_task_self(), tramp_page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"vm_protect(tramp RX) FAILED: %d", kr]);
        return -3;
    }
    sys_icache_invalidate(trampoline_buf, 32);
    *out_trampoline = trampoline_buf;

    // Write branch at target: LDR X16, [PC, #8]; BR X16; <replacement>
    uint32_t hook[4];
    hook[0] = 0x58000050;
    hook[1] = 0xD61F0200;
    memcpy(&hook[2], &replacement_addr, 8);
    memcpy(target, hook, 16);

    // Restore target to RX
    kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"WARNING: restore RX failed: %d", kr]);
    }
    sys_icache_invalidate(target, 16);

    emit(@"inline hook OK");
    return 0;
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v15 loaded (inline hook, no Dobby)");

        void *aead_ptr = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        emit([NSString stringWithFormat:@"dlsym aead: %p", aead_ptr]);

        if (!aead_ptr) {
            emit(@"symbol not found");
            return;
        }

        void *tramp = NULL;
        int r = inline_hook(aead_ptr, (void *)my_aead, &tramp);
        if (r == 0) {
            orig_aead_trampoline = (aead_fn)tramp;
            emit(@"READY — AEAD hooked. Trigger selfie IDV.");
        } else {
            emit([NSString stringWithFormat:@"hook failed: %d", r]);
        }
    }
}
