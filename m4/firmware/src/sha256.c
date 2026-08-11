/* Minimal SHA-256 (FIPS 180-4) for HKDF/HMAC in the TLS 1.3 PSK client path.
   Self-contained. */
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2, i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | ((uint32_t)p[i*4+3]);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void sha256_init(sha256_ctx *c) {
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
    c->bitlen=0; c->datalen=0;
}

void sha256_update(sha256_ctx *c, const uint8_t *p, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        c->data[c->datalen++] = p[i];
        if (c->datalen == 64) {
            sha256_transform(c, c->data);
            c->bitlen += 512;
            c->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx *c, uint8_t hash[32]) {
    uint32_t i;
    i = c->datalen;
    c->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) c->data[i++] = 0;
        sha256_transform(c, c->data);
        i = 0;
    }
    while (i < 56) c->data[i++] = 0;
    c->bitlen += c->datalen * 8;
    c->data[63] = (uint8_t)(c->bitlen);
    c->data[62] = (uint8_t)(c->bitlen >> 8);
    c->data[61] = (uint8_t)(c->bitlen >> 16);
    c->data[60] = (uint8_t)(c->bitlen >> 24);
    c->data[59] = (uint8_t)(c->bitlen >> 32);
    c->data[58] = (uint8_t)(c->bitlen >> 40);
    c->data[57] = (uint8_t)(c->bitlen >> 48);
    c->data[56] = (uint8_t)(c->bitlen >> 56);
    sha256_transform(c, c->data);
    for (i = 0; i < 4; i++) {
        hash[i]    = (uint8_t)(c->state[0] >> (24 - i*8));
        hash[i+4]  = (uint8_t)(c->state[1] >> (24 - i*8));
        hash[i+8]  = (uint8_t)(c->state[2] >> (24 - i*8));
        hash[i+12] = (uint8_t)(c->state[3] >> (24 - i*8));
        hash[i+16] = (uint8_t)(c->state[4] >> (24 - i*8));
        hash[i+20] = (uint8_t)(c->state[5] >> (24 - i*8));
        hash[i+24] = (uint8_t)(c->state[6] >> (24 - i*8));
        hash[i+28] = (uint8_t)(c->state[7] >> (24 - i*8));
    }
}

void hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen, uint8_t out[32]) {
    uint8_t ipad[64], opad[64], inner[32];
    sha256_ctx c;
    size_t i;
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    if (keylen > 64) {
        uint8_t kh[32];
        sha256_ctx kc;
        sha256_init(&kc);
        sha256_update(&kc, key, keylen);
        sha256_final(&kc, kh);
        for (i = 0; i < 32; i++) { ipad[i] ^= kh[i]; opad[i] ^= kh[i]; }
    } else {
        for (i = 0; i < keylen; i++) { ipad[i] ^= key[i]; opad[i] ^= key[i]; }
    }
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

void hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                        const uint8_t *salt, size_t saltlen,
                        const uint8_t *info, size_t infolen,
                        uint8_t *out, size_t outlen) {
    uint8_t prk[32], t[32], block[32 + 32 + 1];
    size_t pos = 0, tlen = 0;
    uint8_t ctr = 1;
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    while (pos < outlen) {
        memcpy(block, t, tlen);
        memcpy(block + tlen, info, infolen);
        block[tlen + infolen] = ctr;
        hmac_sha256(prk, 32, block, tlen + infolen + 1, t);
        tlen = 32;
        {
            size_t n = (outlen - pos < 32) ? (outlen - pos) : 32;
            memcpy(out + pos, t, n);
            pos += 32;
        }
        ctr++;
    }
}
