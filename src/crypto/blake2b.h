#ifndef MICH_CRYPTO_BLAKE2B_H
#define MICH_CRYPTO_BLAKE2B_H

#include "types.h"

#define BLAKE2B_BLOCK_SIZE 128u
#define BLAKE2B_OUT_MAX 64u
#define BLAKE2B_KEY_MAX 64u

// BLAKE2b (RFC 7693). AdytumFS v3 addresses blocks by content, and a 32-bit
// content address collides around 77 thousand blocks, which is silent data
// substitution rather than a detected error. Content addressing and the Merkle
// tree above it need a collision resistant hash, which CRC32C is not.
struct blake2b_state {
    u64 h[8];
    u64 t[2];
    u8 buffer[BLAKE2B_BLOCK_SIZE];
    u32 length;
    u32 outlen;
};

int blake2b_init(struct blake2b_state *state, u32 outlen, const u8 *key,
                 u32 keylen);
int blake2b_update(struct blake2b_state *state, const void *data, u32 length);
int blake2b_final(struct blake2b_state *state, u8 *out, u32 outlen);
int blake2b(u8 *out, u32 outlen, const void *data, u32 length);

#endif
