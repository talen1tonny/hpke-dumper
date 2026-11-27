// hpke_dumper v14 — JB device: Dobby inline hook on C-level crypto functions
// Uses DobbyHook (same as mqtt_dumper v14) for crypto_aead_chacha20poly1305_ietf_encrypt
// + crypto_scalarmult_curve25519 (DH to get server pubkey)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <time.h>
#include <stdint.h>
#include "dobby.h"

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

// ========================================================================
// Hook 1: AEAD encrypt — captures plaintext, AAD, nonce, key
// ========================================================================
typedef int (*aead_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);
static aead_fn o_aead;

static int my_aead(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = o_aead(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
    @try {
        // Only log large plaintexts (selfie ZIP >1KB, skip tiny internal crypto)
        if (mlen > 1000) {
            emit(@"==== AEAD ENCRYPT (ChaCha20-Poly1305) ====");
            emit([NSString stringWithFormat:@"PT_LEN: %llu", mlen]);
            if (m) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
            if (ad && adlen > 0) {
                emit([NSString stringWithFormat:@"AAD_LEN: %llu", adlen]);
                emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
                NSData *aaD = [NSData dataWithBytes:ad length:(NSUInteger)adlen];
                NSString *aaS = [[NSString alloc] initWithData:aaD encoding:NSUTF8StringEncoding];
                if (aaS) emit([NSString stringWithFormat:@"AAD_STR: %@", aaS]);
            } else {
                emit(@"AAD: (empty)");
            }
            if (npub) emit([NSString stringWithFormat:@"NONCE_12B: %@", hexOf(npub, 12)]);
            if (k)    emit([NSString stringWithFormat:@"KEY_32B: %@", hexOf(k, 32)]);
            if (c && clen_p && *clen_p > 0) {
                emit([NSString stringWithFormat:@"CT_LEN: %llu", *clen_p]);
                emit([NSString stringWithFormat:@"CT_HEAD: %@", hexOf(c, *clen_p < 48 ? (size_t)*clen_p : 48)]);
            }
            emit([NSString stringWithFormat:@"RET: %d", ret]);
            // Save full plaintext
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            [[NSData dataWithBytes:m length:(NSUInteger)mlen] writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"aead log err: %@", e]); }
    return ret;
}

// ========================================================================
// Hook 2: X25519 DH — captures server public key + shared secret
// ========================================================================
typedef int (*mult_fn)(unsigned char *, const unsigned char *, const unsigned char *);
static mult_fn o_mult;

static int my_mult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    int ret = o_mult(q, n, p);
    static int cc = 0; cc++;
    if (cc <= 10) {
        @try {
            emit(@"==== X25519 DH (scalarmult) ====");
            if (p) emit([NSString stringWithFormat:@"PEER_PK_32B: %@", hexOf(p, 32)]);
            if (n) emit([NSString stringWithFormat:@"OUR_SK_32B: %@", hexOf(n, 32)]);
            if (q) emit([NSString stringWithFormat:@"SHARED_32B: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ========================================================================
// Hook 3: X25519 keygen — captures ephemeral keypair
// ========================================================================
typedef int (*base_fn)(unsigned char *, const unsigned char *);
static base_fn o_base;

static int my_base(unsigned char *q, const unsigned char *n) {
    int ret = o_base(q, n);
    static int cc = 0; cc++;
    if (cc <= 10) {
        @try {
            emit(@"==== X25519 KEYGEN (scalarmult_base) ====");
            if (q) emit([NSString stringWithFormat:@"EPH_PK_32B: %@", hexOf(q, 32)]);
            if (n) emit([NSString stringWithFormat:@"EPH_SK_32B: %@", hexOf(n, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v14 loaded (Dobby inline hooks)");

        // Resolve symbols via DobbySymbolResolver (same approach as mqtt_dumper)
        void *aead_ptr = (void *)DobbySymbolResolver(NULL, "crypto_aead_chacha20poly1305_ietf_encrypt");
        void *mult_ptr = (void *)DobbySymbolResolver(NULL, "crypto_scalarmult_curve25519");
        void *base_ptr = (void *)DobbySymbolResolver(NULL, "crypto_scalarmult_curve25519_base");
        emit([NSString stringWithFormat:@"resolver: aead=%p mult=%p base=%p", aead_ptr, mult_ptr, base_ptr]);

        // Fallback to dlsym if resolver fails
        if (!aead_ptr) aead_ptr = dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        if (!mult_ptr) mult_ptr = dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519");
        if (!base_ptr) base_ptr = dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519_base");
        emit([NSString stringWithFormat:@"final: aead=%p mult=%p base=%p", aead_ptr, mult_ptr, base_ptr]);

        int hooked = 0;
        if (aead_ptr) {
            int rc = DobbyHook(aead_ptr, (void *)my_aead, (void **)&o_aead);
            emit([NSString stringWithFormat:@"DobbyHook(aead): rc=%d orig=%p", rc, o_aead]);
            if (rc == 0) hooked++;
        }
        if (mult_ptr) {
            int rc = DobbyHook(mult_ptr, (void *)my_mult, (void **)&o_mult);
            emit([NSString stringWithFormat:@"DobbyHook(mult): rc=%d orig=%p", rc, o_mult]);
            if (rc == 0) hooked++;
        }
        if (base_ptr) {
            int rc = DobbyHook(base_ptr, (void *)my_base, (void **)&o_base);
            emit([NSString stringWithFormat:@"DobbyHook(base): rc=%d orig=%p", rc, o_base]);
            if (rc == 0) hooked++;
        }

        emit([NSString stringWithFormat:@"hooks installed: %d/3", hooked]);
        if (hooked > 0) {
            emit(@"READY — trigger selfie IDV to capture ALL crypto params");
        } else {
            emit(@"FAILED — no hooks installed");
        }
    }
}
