// Copyright (c) Meta Platforms, Inc. and affiliates.
// BSD-3-Clause license
#ifndef fishhook_h
#define fishhook_h
#include <stddef.h>
#include <stdint.h>

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);
int rebind_symbols_image(void *header, intptr_t slide,
                         struct rebinding rebindings[], size_t rebindings_nel);
#endif
