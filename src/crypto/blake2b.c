#include "blake2b.h"
#include "crypto.h"

// The SHA-512 initial hash values, which BLAKE2b reuses unchanged.
static const u64 blake2b_iv[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

// Ten message word permutations. Rounds 10 and 11 repeat the first two, so
// the table carries twelve rows rather than ten plus an index modulo.
static const u8 blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

// RFC 7693 specifies right rotation. SipHash rotates left, so this cannot
// share that helper.
static u64 rotr(u64 value, u32 bits) {
    return (value >> bits) | (value << (64 - bits));
}

static u64 load_le64(const u8 *p) {
    u64 value = 0;
    for (u32 index = 0; index < 8; index++)
        value |= (u64)p[index] << (index * 8);
    return value;
}

#define BLAKE2B_G(v, a, b, c, d, x, y)                                       \
    do {                                                                     \
        v[a] = v[a] + v[b] + (x);                                            \
        v[d] = rotr(v[d] ^ v[a], 32);                                        \
        v[c] = v[c] + v[d];                                                  \
        v[b] = rotr(v[b] ^ v[c], 24);                                        \
        v[a] = v[a] + v[b] + (y);                                            \
        v[d] = rotr(v[d] ^ v[a], 16);                                        \
        v[c] = v[c] + v[d];                                                  \
        v[b] = rotr(v[b] ^ v[c], 63);                                        \
    } while (0)

// The final block inverts v[14] before mixing, which is what separates a
// truncated message from a padded one of the same length.
static void blake2b_compress(struct blake2b_state *state, const u8 *block,
                             u32 last) {
    u64 m[16];
    u64 v[16];
    for (u32 index = 0; index < 16; index++)
        m[index] = load_le64(block + index * 8);
    for (u32 index = 0; index < 8; index++) {
        v[index] = state->h[index];
        v[index + 8] = blake2b_iv[index];
    }
    v[12] ^= state->t[0];
    v[13] ^= state->t[1];
    if (last) v[14] = ~v[14];
    for (u32 round = 0; round < 12; round++) {
        const u8 *s = blake2b_sigma[round];
        BLAKE2B_G(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
        BLAKE2B_G(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
        BLAKE2B_G(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
        BLAKE2B_G(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        BLAKE2B_G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        BLAKE2B_G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        BLAKE2B_G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        BLAKE2B_G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (u32 index = 0; index < 8; index++)
        state->h[index] ^= v[index] ^ v[index + 8];
    crypto_zero(m, sizeof(m));
    crypto_zero(v, sizeof(v));
}

static void blake2b_increment(struct blake2b_state *state, u64 count) {
    u64 low = state->t[0];
    state->t[0] += count;
    if (state->t[0] < low) state->t[1]++;
}

int blake2b_init(struct blake2b_state *state, u32 outlen, const u8 *key,
                 u32 keylen) {
    if (!state || !outlen || outlen > BLAKE2B_OUT_MAX ||
        keylen > BLAKE2B_KEY_MAX || (keylen && !key))
        return -1;
    for (u32 index = 0; index < 8; index++)
        state->h[index] = blake2b_iv[index];
    // The first parameter block word packs output length, key length, fanout
    // and depth. Sequential hashing fixes fanout and depth at 1.
    state->h[0] ^= 0x01010000ULL ^ ((u64)keylen << 8) ^ (u64)outlen;
    state->t[0] = 0;
    state->t[1] = 0;
    state->length = 0;
    state->outlen = outlen;
    if (!keylen) return 0;
    // A key is processed as a zero-padded first block, so it enters the same
    // path as message bytes instead of a separate mixing step.
    u8 block[BLAKE2B_BLOCK_SIZE];
    for (u32 index = 0; index < BLAKE2B_BLOCK_SIZE; index++)
        block[index] = index < keylen ? key[index] : 0;
    int result = blake2b_update(state, block, BLAKE2B_BLOCK_SIZE);
    crypto_zero(block, sizeof(block));
    return result;
}

int blake2b_update(struct blake2b_state *state, const void *data, u32 length) {
    if (!state || (length && !data)) return -1;
    const u8 *bytes = (const u8 *)data;
    for (u32 index = 0; index < length; index++) {
        // Compress only when a further byte arrives, never on a full buffer.
        // The last block must stay unprocessed so final can flag it.
        if (state->length == BLAKE2B_BLOCK_SIZE) {
            blake2b_increment(state, BLAKE2B_BLOCK_SIZE);
            blake2b_compress(state, state->buffer, 0);
            state->length = 0;
        }
        state->buffer[state->length++] = bytes[index];
    }
    return 0;
}

int blake2b_final(struct blake2b_state *state, u8 *out, u32 outlen) {
    if (!state || !out || outlen != state->outlen) return -1;
    blake2b_increment(state, state->length);
    for (u32 index = state->length; index < BLAKE2B_BLOCK_SIZE; index++)
        state->buffer[index] = 0;
    blake2b_compress(state, state->buffer, 1);
    u8 digest[BLAKE2B_OUT_MAX];
    for (u32 index = 0; index < 8; index++) {
        for (u32 byte = 0; byte < 8; byte++)
            digest[index * 8 + byte] = (u8)(state->h[index] >> (byte * 8));
    }
    for (u32 index = 0; index < outlen; index++)
        out[index] = digest[index];
    crypto_zero(digest, sizeof(digest));
    return 0;
}

int blake2b(u8 *out, u32 outlen, const void *data, u32 length) {
    struct blake2b_state state;
    if (blake2b_init(&state, outlen, 0, 0)) return -1;
    if (blake2b_update(&state, data, length)) return -1;
    return blake2b_final(&state, out, outlen);
}
