
// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <string.h>

/** Initialize RIPEMD-160 state. */
static void inline initialize(uint32_t* s)
{
    s[0] = 0x67452301ul;
    s[1] = 0xEFCDAB89ul;
    s[2] = 0x98BADCFEul;
    s[3] = 0x10325476ul;
    s[4] = 0xC3D2E1F0ul;
}

static uint32_t inline f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t inline f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t inline f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static uint32_t inline f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t inline f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }
static uint32_t inline rol(uint32_t x, int i) { return (x << i) | (x >> (32 - i)); }
static void inline round(uint32_t *a, uint32_t b, uint32_t *c, uint32_t d, uint32_t e, uint32_t f, uint32_t x, uint32_t k, int r)
{
    *a = rol(*a + f + x + k, r) + e;
    *c = rol(*c, 10);
}

static void inline R11(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f1(b, *c, d), x, 0, r); }
static void inline R21(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f2(b, *c, d), x, 0x5A827999ul, r); }
static void inline R31(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f3(b, *c, d), x, 0x6ED9EBA1ul, r); }
static void inline R41(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f4(b, *c, d), x, 0x8F1BBCDCul, r); }
static void inline R51(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f5(b, *c, d), x, 0xA953FD4Eul, r); }
static void inline R12(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f5(b, *c, d), x, 0x50A28BE6ul, r); }
static void inline R22(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f4(b, *c, d), x, 0x5C4DD124ul, r); }
static void inline R32(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f3(b, *c, d), x, 0x6D703EF3ul, r); }
static void inline R42(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f2(b, *c, d), x, 0x7A6D76E9ul, r); }
static void inline R52(uint32_t* a, uint32_t b, uint32_t* c, uint32_t d, uint32_t e, uint32_t x, int r) { round(a, b, c, d, e, f1(b, *c, d), x, 0, r); }

#define read32(p)           (*((uint32_t *)(p)))

/** Perform a RIPEMD-160 transformation, processing a 64-byte chunk. */
static void transform(uint32_t* s, const unsigned char* chunk)
{
    uint32_t a1 = s[0], b1 = s[1], c1 = s[2], d1 = s[3], e1 = s[4];
    uint32_t a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    uint32_t w0 = read32(chunk + 0), w1 = read32(chunk + 4), w2 = read32(chunk + 8), w3 = read32(chunk + 12);
    uint32_t w4 = read32(chunk + 16), w5 = read32(chunk + 20), w6 = read32(chunk + 24), w7 = read32(chunk + 28);
    uint32_t w8 = read32(chunk + 32), w9 = read32(chunk + 36), w10 = read32(chunk + 40), w11 = read32(chunk + 44);
    uint32_t w12 = read32(chunk + 48), w13 = read32(chunk + 52), w14 = read32(chunk + 56), w15 = read32(chunk + 60);

    R11(&a1, b1, &c1, d1, e1, w0, 11);
    R12(&a2, b2, &c2, d2, e2, w5, 8);
    R11(&e1, a1, &b1, c1, d1, w1, 14);
    R12(&e2, a2, &b2, c2, d2, w14, 9);
    R11(&d1, e1, &a1, b1, c1, w2, 15);
    R12(&d2, e2, &a2, b2, c2, w7, 9);
    R11(&c1, d1, &e1, a1, b1, w3, 12);
    R12(&c2, d2, &e2, a2, b2, w0, 11);
    R11(&b1, c1, &d1, e1, a1, w4, 5);
    R12(&b2, c2, &d2, e2, a2, w9, 13);
    R11(&a1, b1, &c1, d1, e1, w5, 8);
    R12(&a2, b2, &c2, d2, e2, w2, 15);
    R11(&e1, a1, &b1, c1, d1, w6, 7);
    R12(&e2, a2, &b2, c2, d2, w11, 15);
    R11(&d1, e1, &a1, b1, c1, w7, 9);
    R12(&d2, e2, &a2, b2, c2, w4, 5);
    R11(&c1, d1, &e1, a1, b1, w8, 11);
    R12(&c2, d2, &e2, a2, b2, w13, 7);
    R11(&b1, c1, &d1, e1, a1, w9, 13);
    R12(&b2, c2, &d2, e2, a2, w6, 7);
    R11(&a1, b1, &c1, d1, e1, w10, 14);
    R12(&a2, b2, &c2, d2, e2, w15, 8);
    R11(&e1, a1, &b1, c1, d1, w11, 15);
    R12(&e2, a2, &b2, c2, d2, w8, 11);
    R11(&d1, e1, &a1, b1, c1, w12, 6);
    R12(&d2, e2, &a2, b2, c2, w1, 14);
    R11(&c1, d1, &e1, a1, b1, w13, 7);
    R12(&c2, d2, &e2, a2, b2, w10, 14);
    R11(&b1, c1, &d1, e1, a1, w14, 9);
    R12(&b2, c2, &d2, e2, a2, w3, 12);
    R11(&a1, b1, &c1, d1, e1, w15, 8);
    R12(&a2, b2, &c2, d2, e2, w12, 6);

    R21(&e1, a1, &b1, c1, d1, w7, 7);
    R22(&e2, a2, &b2, c2, d2, w6, 9);
    R21(&d1, e1, &a1, b1, c1, w4, 6);
    R22(&d2, e2, &a2, b2, c2, w11, 13);
    R21(&c1, d1, &e1, a1, b1, w13, 8);
    R22(&c2, d2, &e2, a2, b2, w3, 15);
    R21(&b1, c1, &d1, e1, a1, w1, 13);
    R22(&b2, c2, &d2, e2, a2, w7, 7);
    R21(&a1, b1, &c1, d1, e1, w10, 11);
    R22(&a2, b2, &c2, d2, e2, w0, 12);
    R21(&e1, a1, &b1, c1, d1, w6, 9);
    R22(&e2, a2, &b2, c2, d2, w13, 8);
    R21(&d1, e1, &a1, b1, c1, w15, 7);
    R22(&d2, e2, &a2, b2, c2, w5, 9);
    R21(&c1, d1, &e1, a1, b1, w3, 15);
    R22(&c2, d2, &e2, a2, b2, w10, 11);
    R21(&b1, c1, &d1, e1, a1, w12, 7);
    R22(&b2, c2, &d2, e2, a2, w14, 7);
    R21(&a1, b1, &c1, d1, e1, w0, 12);
    R22(&a2, b2, &c2, d2, e2, w15, 7);
    R21(&e1, a1, &b1, c1, d1, w9, 15);
    R22(&e2, a2, &b2, c2, d2, w8, 12);
    R21(&d1, e1, &a1, b1, c1, w5, 9);
    R22(&d2, e2, &a2, b2, c2, w12, 7);
    R21(&c1, d1, &e1, a1, b1, w2, 11);
    R22(&c2, d2, &e2, a2, b2, w4, 6);
    R21(&b1, c1, &d1, e1, a1, w14, 7);
    R22(&b2, c2, &d2, e2, a2, w9, 15);
    R21(&a1, b1, &c1, d1, e1, w11, 13);
    R22(&a2, b2, &c2, d2, e2, w1, 13);
    R21(&e1, a1, &b1, c1, d1, w8, 12);
    R22(&e2, a2, &b2, c2, d2, w2, 11);

    R31(&d1, e1, &a1, b1, c1, w3, 11);
    R32(&d2, e2, &a2, b2, c2, w15, 9);
    R31(&c1, d1, &e1, a1, b1, w10, 13);
    R32(&c2, d2, &e2, a2, b2, w5, 7);
    R31(&b1, c1, &d1, e1, a1, w14, 6);
    R32(&b2, c2, &d2, e2, a2, w1, 15);
    R31(&a1, b1, &c1, d1, e1, w4, 7);
    R32(&a2, b2, &c2, d2, e2, w3, 11);
    R31(&e1, a1, &b1, c1, d1, w9, 14);
    R32(&e2, a2, &b2, c2, d2, w7, 8);
    R31(&d1, e1, &a1, b1, c1, w15, 9);
    R32(&d2, e2, &a2, b2, c2, w14, 6);
    R31(&c1, d1, &e1, a1, b1, w8, 13);
    R32(&c2, d2, &e2, a2, b2, w6, 6);
    R31(&b1, c1, &d1, e1, a1, w1, 15);
    R32(&b2, c2, &d2, e2, a2, w9, 14);
    R31(&a1, b1, &c1, d1, e1, w2, 14);
    R32(&a2, b2, &c2, d2, e2, w11, 12);
    R31(&e1, a1, &b1, c1, d1, w7, 8);
    R32(&e2, a2, &b2, c2, d2, w8, 13);
    R31(&d1, e1, &a1, b1, c1, w0, 13);
    R32(&d2, e2, &a2, b2, c2, w12, 5);
    R31(&c1, d1, &e1, a1, b1, w6, 6);
    R32(&c2, d2, &e2, a2, b2, w2, 14);
    R31(&b1, c1, &d1, e1, a1, w13, 5);
    R32(&b2, c2, &d2, e2, a2, w10, 13);
    R31(&a1, b1, &c1, d1, e1, w11, 12);
    R32(&a2, b2, &c2, d2, e2, w0, 13);
    R31(&e1, a1, &b1, c1, d1, w5, 7);
    R32(&e2, a2, &b2, c2, d2, w4, 7);
    R31(&d1, e1, &a1, b1, c1, w12, 5);
    R32(&d2, e2, &a2, b2, c2, w13, 5);

    R41(&c1, d1, &e1, a1, b1, w1, 11);
    R42(&c2, d2, &e2, a2, b2, w8, 15);
    R41(&b1, c1, &d1, e1, a1, w9, 12);
    R42(&b2, c2, &d2, e2, a2, w6, 5);
    R41(&a1, b1, &c1, d1, e1, w11, 14);
    R42(&a2, b2, &c2, d2, e2, w4, 8);
    R41(&e1, a1, &b1, c1, d1, w10, 15);
    R42(&e2, a2, &b2, c2, d2, w1, 11);
    R41(&d1, e1, &a1, b1, c1, w0, 14);
    R42(&d2, e2, &a2, b2, c2, w3, 14);
    R41(&c1, d1, &e1, a1, b1, w8, 15);
    R42(&c2, d2, &e2, a2, b2, w11, 14);
    R41(&b1, c1, &d1, e1, a1, w12, 9);
    R42(&b2, c2, &d2, e2, a2, w15, 6);
    R41(&a1, b1, &c1, d1, e1, w4, 8);
    R42(&a2, b2, &c2, d2, e2, w0, 14);
    R41(&e1, a1, &b1, c1, d1, w13, 9);
    R42(&e2, a2, &b2, c2, d2, w5, 6);
    R41(&d1, e1, &a1, b1, c1, w3, 14);
    R42(&d2, e2, &a2, b2, c2, w12, 9);
    R41(&c1, d1, &e1, a1, b1, w7, 5);
    R42(&c2, d2, &e2, a2, b2, w2, 12);
    R41(&b1, c1, &d1, e1, a1, w15, 6);
    R42(&b2, c2, &d2, e2, a2, w13, 9);
    R41(&a1, b1, &c1, d1, e1, w14, 8);
    R42(&a2, b2, &c2, d2, e2, w9, 12);
    R41(&e1, a1, &b1, c1, d1, w5, 6);
    R42(&e2, a2, &b2, c2, d2, w7, 5);
    R41(&d1, e1, &a1, b1, c1, w6, 5);
    R42(&d2, e2, &a2, b2, c2, w10, 15);
    R41(&c1, d1, &e1, a1, b1, w2, 12);
    R42(&c2, d2, &e2, a2, b2, w14, 8);

    R51(&b1, c1, &d1, e1, a1, w4, 9);
    R52(&b2, c2, &d2, e2, a2, w12, 8);
    R51(&a1, b1, &c1, d1, e1, w0, 15);
    R52(&a2, b2, &c2, d2, e2, w15, 5);
    R51(&e1, a1, &b1, c1, d1, w5, 5);
    R52(&e2, a2, &b2, c2, d2, w10, 12);
    R51(&d1, e1, &a1, b1, c1, w9, 11);
    R52(&d2, e2, &a2, b2, c2, w4, 9);
    R51(&c1, d1, &e1, a1, b1, w7, 6);
    R52(&c2, d2, &e2, a2, b2, w1, 12);
    R51(&b1, c1, &d1, e1, a1, w12, 8);
    R52(&b2, c2, &d2, e2, a2, w5, 5);
    R51(&a1, b1, &c1, d1, e1, w2, 13);
    R52(&a2, b2, &c2, d2, e2, w8, 14);
    R51(&e1, a1, &b1, c1, d1, w10, 12);
    R52(&e2, a2, &b2, c2, d2, w7, 6);
    R51(&d1, e1, &a1, b1, c1, w14, 5);
    R52(&d2, e2, &a2, b2, c2, w6, 8);
    R51(&c1, d1, &e1, a1, b1, w1, 12);
    R52(&c2, d2, &e2, a2, b2, w2, 13);
    R51(&b1, c1, &d1, e1, a1, w3, 13);
    R52(&b2, c2, &d2, e2, a2, w13, 6);
    R51(&a1, b1, &c1, d1, e1, w8, 14);
    R52(&a2, b2, &c2, d2, e2, w14, 5);
    R51(&e1, a1, &b1, c1, d1, w11, 11);
    R52(&e2, a2, &b2, c2, d2, w0, 15);
    R51(&d1, e1, &a1, b1, c1, w6, 8);
    R52(&d2, e2, &a2, b2, c2, w3, 13);
    R51(&c1, d1, &e1, a1, b1, w15, 5);
    R52(&c2, d2, &e2, a2, b2, w9, 11);
    R51(&b1, c1, &d1, e1, a1, w13, 6);
    R52(&b2, c2, &d2, e2, a2, w11, 11);

    uint32_t t = s[0];
    s[0] = s[1] + c1 + d2;
    s[1] = s[2] + d1 + e2;
    s[2] = s[3] + e1 + a2;
    s[3] = s[4] + a1 + b2;
    s[4] = t + b1 + c2;
}

////// RIPEMD160

typedef struct
{
    uint32_t s[5];
    unsigned char buf[64];
    size_t bytes;
} RIPEMD160_CTX;

static void ripemd160_init(RIPEMD160_CTX *cxt)
{
    cxt->bytes = 0;
    initialize(cxt->s);
}

static void ripemd160_update(RIPEMD160_CTX *cxt, const unsigned char* data,
    size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = cxt->bytes % 64;
    if (bufsize && bufsize + len >= 64)
    {
        // Fill the buffer, and process it.
        memcpy(cxt->buf + bufsize, data, 64 - bufsize);
        cxt->bytes += 64 - bufsize;
        data += 64 - bufsize;
        transform(cxt->s, cxt->buf);
        bufsize = 0;
    }
    while (end >= data + 64)
    {
        // Process full chunks directly from the source.
        transform(cxt->s, data);
        cxt->bytes += 64;
        data += 64;
    }
    if (end > data)
    {
        // Fill the buffer with what remains.
        memcpy(cxt->buf + bufsize, data, end - data);
        cxt->bytes += end - data;
    }
}

#define write64(p, v)       (*((uint64_t *)(p)) = (v))
#define write32(p, v)       (*((uint32_t *)(p)) = (v))

static void ripemd160_final(RIPEMD160_CTX *cxt, unsigned char *hash)
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    write64(sizedesc, cxt->bytes << 3);
    ripemd160_update(cxt, pad, 1 + ((119 - (cxt->bytes % 64)) % 64));
    ripemd160_update(cxt, sizedesc, 8);
    write32(hash, cxt->s[0]);
    write32(hash + 4, cxt->s[1]);
    write32(hash + 8, cxt->s[2]);
    write32(hash + 12, cxt->s[3]);
    write32(hash + 16, cxt->s[4]);
}

extern void ripemd160(const void *data, size_t len, void *res)
{
    RIPEMD160_CTX cxt;
    ripemd160_init(&cxt);
    ripemd160_update(&cxt, data, len);
    ripemd160_final(&cxt, res);
}

