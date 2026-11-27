// hpke_dumper v10 — C-level hook via fishhook (ZERO ObjC runtime scanning)
// Hooks crypto_aead_chacha20poly1305_ietf_encrypt (libsodium)
// This is what HPKE calls for the final AEAD seal step.
// Also hooks crypto_scalarmult_curve25519 (DH key agreement)
// to capture the server public key.
#import <Foundation/Foundation.h>
#include "fishhook.h"
#include <time.h>
#include <stdint.h>

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
// Hook 1: crypto_aead_chacha20poly1305_ietf_encrypt
// int crypto_aead_chacha20poly1305_ietf_encrypt(
//   unsigned char *c, unsigned long long *clen_p,
//   const unsigned char *m, unsigned long long mlen,
//   const unsigned char *ad, unsigned long long adlen,
//   const unsigned char *nsec,
//   const unsigned char *npub,  // 12-byte nonce
//   const unsigned char *k)     // 32-byte key
// ========================================================================
typedef int (*aead_encrypt_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);

static aead_encrypt_fn orig_aead_encrypt;

static int my_aead_encrypt(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k) {

    int ret = orig_aead_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);

    @try {
        emit(@"==== AEAD ENCRYPT (ChaCha20-Poly1305) ====");
        emit([NSString stringWithFormat:@"PT_LEN: %llu", mlen]);
        if (m && mlen > 0)
            emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
        if (ad && adlen > 0) {
            emit([NSString stringWithFormat:@"AAD_LEN: %llu", adlen]);
            emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
            NSData *aaData = [NSData dataWithBytes:ad length:(NSUInteger)adlen];
            NSString *aaStr = [[NSString alloc] initWithData:aaData encoding:NSUTF8StringEncoding];
            if (aaStr) emit([NSString stringWithFormat:@"AAD_STR: %@", aaStr]);
        } else {
            emit(@"AAD: empty");
        }
        if (npub)
            emit([NSString stringWithFormat:@"NONCE: %@", hexOf(npub, 12)]);
        if (k)
            emit([NSString stringWithFormat:@"KEY: %@", hexOf(k, 32)]);
        if (c && clen_p && *clen_p > 0) {
            emit([NSString stringWithFormat:@"CT_LEN: %llu", *clen_p]);
            emit([NSString stringWithFormat:@"CT_HEAD: %@", hexOf(c, *clen_p < 48 ? (size_t)*clen_p : 48)]);
        }
        emit([NSString stringWithFormat:@"RET: %d", ret]);

        // Save plaintext as file
        if (m && mlen > 1000) {
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            NSData *ptData = [NSData dataWithBytes:m length:(NSUInteger)mlen];
            [ptData writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) {
        emit([NSString stringWithFormat:@"aead log err: %@", e]);
    }
    return ret;
}

// ========================================================================
// Hook 2: crypto_scalarmult_curve25519 (X25519 DH)
// int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
//                                  const unsigned char *p)
// q = shared secret (32B), n = our private key, p = their public key
// ========================================================================
typedef int (*scalarmult_fn)(unsigned char *, const unsigned char *, const unsigned char *);
static scalarmult_fn orig_scalarmult;

static int my_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    int ret = orig_scalarmult(q, n, p);
    @try {
        emit(@"==== X25519 DH (scalarmult) ====");
        if (p) emit([NSString stringWithFormat:@"PEER_PK: %@", hexOf(p, 32)]);
        if (n) emit([NSString stringWithFormat:@"OUR_SK: %@", hexOf(n, 32)]);
        if (q) emit([NSString stringWithFormat:@"SHARED: %@", hexOf(q, 32)]);
        emit([NSString stringWithFormat:@"RET: %d", ret]);
    } @catch (id e) {}
    return ret;
}

// ========================================================================
// Hook 3: crypto_scalarmult_curve25519_base (eph pubkey gen)
// int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
// q = public key (32B), n = secret key (32B)
// ========================================================================
typedef int (*scalarmult_base_fn)(unsigned char *, const unsigned char *);
static scalarmult_base_fn orig_scalarmult_base;

static int my_scalarmult_base(unsigned char *q, const unsigned char *n) {
    int ret = orig_scalarmult_base(q, n);
    @try {
        emit(@"==== X25519 KEYGEN (scalarmult_base) ====");
        if (q) emit([NSString stringWithFormat:@"EPH_PK: %@", hexOf(q, 32)]);
        if (n) emit([NSString stringWithFormat:@"EPH_SK: %@", hexOf(n, 32)]);
    } @catch (id e) {}
    return ret;
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v10 loaded (fishhook C-level)");

        struct rebinding rebindings[] = {
            {"crypto_aead_chacha20poly1305_ietf_encrypt", (void *)my_aead_encrypt, (void **)&orig_aead_encrypt},
            {"crypto_scalarmult_curve25519", (void *)my_scalarmult, (void **)&orig_scalarmult},
            {"crypto_scalarmult_curve25519_base", (void *)my_scalarmult_base, (void **)&orig_scalarmult_base},
        };
        int r = rebind_symbols(rebindings, 3);
        emit([NSString stringWithFormat:@"fishhook rebind: %d (0=ok)", r]);
        emit([NSString stringWithFormat:@"orig_aead=%p orig_mult=%p orig_base=%p",
            orig_aead_encrypt, orig_scalarmult, orig_scalarmult_base]);

        if (orig_aead_encrypt) {
            emit(@"READY — AEAD hook installed. Trigger selfie IDV to capture crypto params.");
        } else {
            emit(@"WARNING: orig_aead_encrypt is NULL — symbol may be statically linked");
        }
    }
}
