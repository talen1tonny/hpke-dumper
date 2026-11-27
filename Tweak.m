// hpke_dumper v11 — DYLD_INTERPOSE (zero iteration, zero ObjC runtime)
// dyld reads __DATA,__interpose at load time — no code runs to install hooks
// + dlsym fallback for original function addresses
#import <Foundation/Foundation.h>
#include <dlfcn.h>
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
// AEAD: crypto_aead_chacha20poly1305_ietf_encrypt
// ========================================================================
typedef int (*aead_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);

int crypto_aead_chacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int my_aead_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k) {

    int ret = crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);

    @try {
        // Only log large plaintexts (selfie ZIP, not small internal crypto)
        if (mlen > 1000) {
            emit(@"==== AEAD ENCRYPT (ChaCha20-Poly1305) ====");
            emit([NSString stringWithFormat:@"PT_LEN: %llu", mlen]);
            if (m) emit([NSString stringWithFormat:@"PT_HEAD: %@", hexOf(m, mlen < 64 ? (size_t)mlen : 64)]);
            if (ad && adlen > 0) {
                emit([NSString stringWithFormat:@"AAD_LEN: %llu", adlen]);
                emit([NSString stringWithFormat:@"AAD_HEX: %@", hexOf(ad, adlen < 512 ? (size_t)adlen : 512)]);
                NSData *aaData = [NSData dataWithBytes:ad length:(NSUInteger)adlen];
                NSString *aaStr = [[NSString alloc] initWithData:aaData encoding:NSUTF8StringEncoding];
                if (aaStr) emit([NSString stringWithFormat:@"AAD_STR: %@", aaStr]);
            } else {
                emit(@"AAD: empty");
            }
            if (npub) emit([NSString stringWithFormat:@"NONCE: %@", hexOf(npub, 12)]);
            if (k) emit([NSString stringWithFormat:@"KEY: %@", hexOf(k, 32)]);
            if (c && clen_p && *clen_p > 0) {
                emit([NSString stringWithFormat:@"CT_LEN: %llu", *clen_p]);
                emit([NSString stringWithFormat:@"CT_HEAD: %@", hexOf(c, *clen_p < 48 ? (size_t)*clen_p : 48)]);
            }
            // Save plaintext
            NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *zp = [docs stringByAppendingPathComponent:
                [NSString stringWithFormat:@"hpke_pt_%lu.bin", (unsigned long)time(NULL)]];
            NSData *ptData = [NSData dataWithBytes:m length:(NSUInteger)mlen];
            [ptData writeToFile:zp atomically:YES];
            emit([NSString stringWithFormat:@"PT_SAVED: %@", zp]);
        }
    } @catch (id e) { emit([NSString stringWithFormat:@"aead err: %@", e]); }
    return ret;
}

// ========================================================================
// DH: crypto_scalarmult_curve25519
// ========================================================================
int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n, const unsigned char *p);

int my_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    int ret = crypto_scalarmult_curve25519(q, n, p);
    static int call_count = 0;
    call_count++;
    // Log only first few calls to avoid spam
    if (call_count <= 5) {
        @try {
            emit(@"==== X25519 DH ====");
            if (p) emit([NSString stringWithFormat:@"PEER_PK: %@", hexOf(p, 32)]);
            if (q) emit([NSString stringWithFormat:@"SHARED: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ========================================================================
// Keygen: crypto_scalarmult_curve25519_base
// ========================================================================
int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);

int my_scalarmult_base(unsigned char *q, const unsigned char *n) {
    int ret = crypto_scalarmult_curve25519_base(q, n);
    static int call_count = 0;
    call_count++;
    if (call_count <= 5) {
        @try {
            emit(@"==== X25519 KEYGEN ====");
            if (q) emit([NSString stringWithFormat:@"EPH_PK: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ========================================================================
// DYLD_INTERPOSE — just data, no code at hook time
// ========================================================================
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void* r; const void* e; } \
    _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = \
    { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

DYLD_INTERPOSE(my_aead_encrypt, crypto_aead_chacha20poly1305_ietf_encrypt)
DYLD_INTERPOSE(my_scalarmult, crypto_scalarmult_curve25519)
DYLD_INTERPOSE(my_scalarmult_base, crypto_scalarmult_curve25519_base)

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v11 loaded (DYLD_INTERPOSE)");
        emit(@"READY — trigger selfie IDV to capture crypto params");
    }
}
