// hpke_dumper v13 — inline hook via vm_protect + ARM64 trampoline
// dlsym finds the function, we patch its prologue to jump to our hook
// Requires JIT/CS_DEBUGGED (TrollStore usually provides this)
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include <mach/mach.h>
#include <string.h>
#include <pthread.h>
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

// ---- Our hook ----
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
            } else { emit(@"AAD: empty"); }
            if (npub) emit([NSString stringWithFormat:@"NONCE: %@", hexOf(npub, 12)]);
            if (k) emit([NSString stringWithFormat:@"KEY: %@", hexOf(k, 32)]);
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

// ---- Trampoline: saved original bytes + jump back ----
// We need RWX memory for the trampoline that executes the original prologue
// then jumps back to original+16
static uint8_t trampoline_buf[64] __attribute__((aligned(4096)));

static int inline_hook(void *target, void *replacement, void **out_trampoline) {
    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replacement_addr = (uintptr_t)replacement;
    vm_address_t page = target_addr & ~(vm_address_t)(0x3FFF); // 16K pages on iOS
    vm_size_t page_size = 0x4000;

    // Step 1: Try to make target page writable
    kern_return_t kr;

    // Try MAP_JIT approach first (TrollStore)
    kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        // Try without COPY
        kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"vm_protect(RW) FAILED: %d (%s)", kr, mach_error_string(kr)]);
        return -1;
    }
    emit(@"vm_protect(RW) OK");

    // Step 2: Save original 16 bytes
    uint8_t saved[16];
    memcpy(saved, target, 16);
    emit([NSString stringWithFormat:@"original prologue: %@", hexOf(saved, 16)]);

    // Step 3: Build trampoline (execute saved bytes + jump to original+16)
    // Make trampoline buffer executable
    vm_address_t tramp_page = (vm_address_t)trampoline_buf & ~(vm_address_t)(0x3FFF);
    kr = vm_protect(mach_task_self(), tramp_page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"trampoline vm_protect(RW) FAILED: %d", kr]);
        return -2;
    }

    // Copy saved instructions
    memcpy(trampoline_buf, saved, 16);
    // Add: LDR X16, [PC, #8]; BR X16; <addr>
    uint32_t ldr_x16 = 0x58000050;  // LDR X16, PC+8
    uint32_t br_x16  = 0xD61F0200;  // BR X16
    memcpy(trampoline_buf + 16, &ldr_x16, 4);
    memcpy(trampoline_buf + 20, &br_x16, 4);
    uintptr_t resume_addr = target_addr + 16;
    memcpy(trampoline_buf + 24, &resume_addr, 8);

    // Make trampoline executable
    kr = vm_protect(mach_task_self(), tramp_page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"trampoline vm_protect(RX) FAILED: %d", kr]);
        return -3;
    }
    sys_icache_invalidate(trampoline_buf, 32);
    *out_trampoline = trampoline_buf;

    // Step 4: Write branch to our hook at target
    // LDR X16, [PC, #8]; BR X16; <replacement_addr>
    uint32_t hook_code[4];
    hook_code[0] = 0x58000050;  // LDR X16, PC+8
    hook_code[1] = 0xD61F0200;  // BR X16
    memcpy(&hook_code[2], &replacement_addr, 8);
    memcpy(target, hook_code, 16);

    // Step 5: Restore target page to RX
    kr = vm_protect(mach_task_self(), page, page_size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        emit([NSString stringWithFormat:@"WARNING: restore vm_protect(RX) FAILED: %d", kr]);
    }
    sys_icache_invalidate(target, 16);

    emit(@"inline hook installed OK");
    return 0;
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v13 loaded (inline hook)");

        void *aead_ptr = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        emit([NSString stringWithFormat:@"dlsym aead: %p", aead_ptr]);

        if (!aead_ptr) {
            emit(@"symbol not found — cannot hook");
            return;
        }

        void *tramp = NULL;
        int r = inline_hook(aead_ptr, (void *)my_aead, &tramp);
        if (r == 0) {
            orig_aead_trampoline = (aead_fn)tramp;
            emit(@"READY — AEAD hooked. Trigger selfie IDV.");
        } else {
            emit([NSString stringWithFormat:@"inline hook failed: %d", r]);
            emit(@"This device may not support JIT/code patching");
            emit(@"Try on the Dopamine JB device instead");
        }
    }
}
