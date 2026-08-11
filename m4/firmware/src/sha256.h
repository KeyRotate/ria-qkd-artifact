#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *p, size_t len);
void sha256_final(sha256_ctx *c, uint8_t hash[32]);

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const uint8_t *msg, size_t msglen, uint8_t out[32]);

/* HKDF-Expand producing `outlen` bytes (limited to 255*32). */
void hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                 const uint8_t *salt, size_t saltlen,
                 const uint8_t *info, size_t infolen,
                 uint8_t *out, size_t outlen);
#endif