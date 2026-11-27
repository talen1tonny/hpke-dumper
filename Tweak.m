// hpke_dumper v11b — dlsym-only hooks, no DYLD_INTERPOSE, no fishhook
// Find libsodium functions via dlsym, patch via manual GOT replacement
// If symbols are statically linked, use function-pointer swizzle at call time
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

// ---- Function pointer types ----
typedef int (*aead_fn)(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long,
    const unsigned char *, unsigned long long,
    const unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*scalarmult_fn)(unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*scalarmult_base_fn)(unsigned char *, const unsigned char *);

static aead_fn orig_aead = NULL;
static scalarmult_fn orig_mult = NULL;
static scalarmult_base_fn orig_base = NULL;

// ---- Hooks ----
static int my_aead(unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub, const unsigned char *k) {
    int ret = orig_aead(c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
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

static int my_mult(unsigned char *q, const unsigned char *n, const unsigned char *p) {
    int ret = orig_mult(q, n, p);
    static int cc = 0; cc++;
    if (cc <= 5) {
        @try {
            emit(@"==== X25519 DH ====");
            if (p) emit([NSString stringWithFormat:@"PEER_PK: %@", hexOf(p, 32)]);
            if (q) emit([NSString stringWithFormat:@"SHARED: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

static int my_base(unsigned char *q, const unsigned char *n) {
    int ret = orig_base(q, n);
    static int cc = 0; cc++;
    if (cc <= 5) {
        @try {
            emit(@"==== X25519 KEYGEN ====");
            if (q) emit([NSString stringWithFormat:@"EPH_PK: %@", hexOf(q, 32)]);
        } @catch (id e) {}
    }
    return ret;
}

// ---- Manual GOT patch for ONE symbol in ONE image ----
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <sys/mman.h>

static void patch_got_for_symbol(const char *sym_name, void *replacement, void **out_original) {
    // Walk ONLY the main binary (image 0) — no iteration over all images
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!mh) return;
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    const struct segment_command_64 *linkedit_seg = NULL;
    const struct segment_command_64 *data_seg = NULL;
    const struct segment_command_64 *data_const_seg = NULL;

    const uint8_t *ptr = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) linkedit_seg = seg;
            else if (strcmp(seg->segname, "__DATA") == 0) data_seg = seg;
            else if (strcmp(seg->segname, "__DATA_CONST") == 0) data_const_seg = seg;
        } else if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)ptr;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)ptr;
        }
        ptr += lc->cmdsize;
    }
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_seg) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_seg->vmaddr - linkedit_seg->fileoff;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    // Patch lazy + non-lazy symbol pointers in __DATA and __DATA_CONST
    const struct segment_command_64 *segs[] = {data_seg, data_const_seg, NULL};
    for (int si = 0; segs[si]; si++) {
        const struct section_64 *sections = (const struct section_64 *)((uint8_t *)segs[si] + sizeof(struct segment_command_64));
        for (uint32_t j = 0; j < segs[si]->nsects; j++) {
            uint32_t type = sections[j].flags & SECTION_TYPE;
            if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;

            uint32_t *indices = indirect_symtab + sections[j].reserved1;
            void **bindings = (void **)(slide + sections[j].addr);
            uint32_t count = (uint32_t)(sections[j].size / sizeof(void *));

            for (uint32_t k = 0; k < count; k++) {
                uint32_t idx = indices[k];
                if (idx == 0x40000000 || idx == 0x80000000 || idx == 0xC0000000) continue;
                uint32_t strx = symtab[idx].n_un.n_strx;
                const char *name = strtab + strx;
                // Symbol names have leading underscore
                if (name[0] == '_' && strcmp(name + 1, sym_name) == 0) {
                    if (out_original && bindings[k] != replacement)
                        *out_original = bindings[k];
                    bindings[k] = replacement;
                    return;
                }
            }
        }
    }
}

__attribute__((constructor))
static void init(void) {
    @autoreleasepool {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        gPath = [docs stringByAppendingPathComponent:@"hpke_dump.txt"];
        [[NSFileManager defaultManager] createFileAtPath:gPath contents:nil attributes:nil];
        gFH = [NSFileHandle fileHandleForWritingAtPath:gPath];
        emit(@"hpke_dumper v11b loaded");

        // Try dlsym first (works if symbols are dynamically linked)
        orig_aead = (aead_fn)dlsym(RTLD_DEFAULT, "crypto_aead_chacha20poly1305_ietf_encrypt");
        orig_mult = (scalarmult_fn)dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519");
        orig_base = (scalarmult_base_fn)dlsym(RTLD_DEFAULT, "crypto_scalarmult_curve25519_base");

        emit([NSString stringWithFormat:@"dlsym: aead=%p mult=%p base=%p",
            orig_aead, orig_mult, orig_base]);

        if (orig_aead) {
            // Symbols are dynamic — patch GOT of main binary only
            emit(@"symbols found via dlsym — patching main binary GOT");
            patch_got_for_symbol("crypto_aead_chacha20poly1305_ietf_encrypt",
                (void *)my_aead, (void **)&orig_aead);
            patch_got_for_symbol("crypto_scalarmult_curve25519",
                (void *)my_mult, (void **)&orig_mult);
            patch_got_for_symbol("crypto_scalarmult_curve25519_base",
                (void *)my_base, (void **)&orig_base);
            emit([NSString stringWithFormat:@"after patch: aead=%p mult=%p base=%p",
                orig_aead, orig_mult, orig_base]);
            emit(@"READY — trigger selfie IDV");
        } else {
            emit(@"symbols NOT found via dlsym — may be statically linked");
            emit(@"try alternative: hook ObjC selector via delayed scan");
        }
    }
}
