/* RIA-QKD client handshake on STM32F407 (Cortex-M4F, 168MHz) over USART2.
   Wire format B: 4-byte big-endian total length prefix; internal >H field lens. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "kem/api.h"
#include "sign/api.h"
#include "sha256.h"
#include "usart2.h"

#define KEM_PK 800
#define KEM_SK 1632
#define KEM_CT 768
#define KEM_SS 32
#define DSA_PK 1312
#define DSA_SIG 2420

#define PROTO_SERVER_SIG_PREFIX (const uint8_t*)"RIA-QKD-V1-Server"
#define PROTO_SERVER_SIG_PREFIX_LEN 17
#define SERVER_ID (const uint8_t*)"RIA-QKD-GW"
#define SERVER_ID_LEN 10
#define CLIENT_ID (const uint8_t*)"default"
#define CLIENT_ID_LEN 7
#define EPOCH0 0x00,0x00,0x00,0x01

#define DWT_CYCCNT (*(volatile uint32_t*)0xE0001004)
#define DWT_CTRL   (*(volatile uint32_t*)0xE0001000)
#define DEMCR      (*(volatile uint32_t*)0xE000EDFC)
#define GPIOA_BSRR (*(volatile uint32_t*)0x40020018)
#define RCC_AHB1ENR (*(volatile uint32_t*)0x40023830)

#define FRAMING_MAX 8192
#define RESULTS_ADDR 0x10000000
typedef struct { uint32_t magic; uint32_t cycles; uint32_t accepted; uint32_t done; } hs_results_t;
#define RESULTS ((volatile hs_results_t*)RESULTS_ADDR)

static uint8_t m1[900];
static uint8_t m2[FRAMING_MAX];
static uint8_t m3[900];
static uint8_t m4[64];
static uint8_t ss1[KEM_SS], ss2[KEM_SS], ss3[KEM_SS];
static uint8_t x[KEM_SS*3];
static uint8_t tr[32], tr2[32], prk[32], k_fin[32];
static uint8_t epoch[4] = {EPOCH0};

#include "m4_creds.h"

__attribute__((noinline,optimize("O1")))
void *memset(void*d,int c,size_t n){ unsigned char*p=(unsigned char*)d; while(n){ *p++=(unsigned char)c; n--; } return d; }
__attribute__((noinline,optimize("O1")))
void *memcpy(void*d,const void*s,size_t n){ unsigned char*a=(unsigned char*)d; const unsigned char*b=(const unsigned char*)s; while(n){ *a++=*b++; n--; } return d; }

static void pack16(uint8_t *d, uint16_t v){ d[0]=v>>8; d[1]=v&0xff; }

/* send framed message: 4-byte BE total length + payload */
static void send_frame(const uint8_t *payload, size_t n){
    uint8_t hdr[4] = { n>>24, n>>16, n>>8, n&0xff };
    usart2_send(hdr, 4);
    usart2_send(payload, n);
}

static int recv_frame(uint8_t *buf, size_t *n, uint32_t timeout_ms){
    uint8_t hdr[4];
    if(usart2_recv_byte(&hdr[0], timeout_ms)) return -1;
    if(usart2_recv_byte(&hdr[1], timeout_ms)) return -1;
    if(usart2_recv_byte(&hdr[2], timeout_ms)) return -1;
    if(usart2_recv_byte(&hdr[3], timeout_ms)) return -1;
    size_t len = ((size_t)hdr[0]<<24)|((size_t)hdr[1]<<16)|((size_t)hdr[2]<<8)|hdr[3];
    if(len > FRAMING_MAX) return -2;
    for(size_t i=0;i<len;i++){
        if(usart2_recv_byte(&buf[i], timeout_ms)) return -1;
    }
    *n = len;
    return 0;
}

static uint32_t rd16(const uint8_t *p){ return ((uint32_t)p[0]<<8)|p[1]; }

void mark_on(void){ GPIOA_BSRR = 1UL<<5; }
void mark_off(void){ GPIOA_BSRR = 1UL<<21; }

int main(void){
    size_t siglen=0;
    RCC_AHB1ENR |= 1UL;
    *(volatile uint32_t*)0x40020000 |= (1UL<<10);   /* PA5 output */
    __asm__ volatile("dsb"); __asm__ volatile("isb");
    *(volatile uint32_t*)0xE000ED88 |= (0xFUL<<20);
    __asm__ volatile("dsb"); __asm__ volatile("isb");
    DEMCR|=1UL<<24; DWT_CYCCNT=0; DWT_CTRL|=1UL;
    usart2_init(115200);
    RESULTS->magic=0x48415348; RESULTS->cycles=0; RESULTS->accepted=0; RESULTS->done=0;
    uint32_t hs_t0 = DWT_CYCCNT;

    /* --- m1: CLIENT_HELLO --- */
    uint8_t pk_eph[KEM_PK], sk_eph[KEM_SK];
    uint8_t r_c[32];
    crypto_kem_keypair(pk_eph, sk_eph);
    for(int i=0;i<32;i++) r_c[i]=(uint8_t)(i*7+3);
    size_t off=0;
    pack16(m1+off, CLIENT_ID_LEN); off+=2;
    memcpy(m1+off, CLIENT_ID, CLIENT_ID_LEN); off+=CLIENT_ID_LEN;
    memcpy(m1+off, epoch, 4); off+=4;
    memcpy(m1+off, r_c, 32); off+=32;
    pack16(m1+off, KEM_PK); off+=2;
    memcpy(m1+off, pk_eph, KEM_PK); off+=KEM_PK;
    size_t m1_len = off;
    mark_on();
    send_frame(m1, m1_len);

    /* --- recv m2: SERVER_HELLO --- */
    size_t m2_len=0;
    if(recv_frame(m2, &m2_len, 30000)) { mark_off(); while(1); }
    off=0;
    size_t srv_eph_pk_len = rd16(m2+off); off+=2;
    uint8_t *srv_eph_pk = m2+off; off+=srv_eph_pk_len;
    size_t ct1_len = rd16(m2+off); off+=2;
    uint8_t *ct1 = m2+off; off+=ct1_len;
    size_t ct2_len = rd16(m2+off); off+=2;
    uint8_t *ct2 = m2+off; off+=ct2_len;
    size_t sig_len = rd16(m2+off); off+=2;
    uint8_t *sig = m2+off; off+=sig_len;

    /* verify server sig: SHA256("RIA-QKD-V1-Server"+SERVER_ID+cli_id+epoch+r_c+srv_eph_pk+ct1+ct2) */
    sha256_ctx hc; sha256_init(&hc);
    sha256_update(&hc, PROTO_SERVER_SIG_PREFIX, PROTO_SERVER_SIG_PREFIX_LEN);
    sha256_update(&hc, SERVER_ID, SERVER_ID_LEN);
    sha256_update(&hc, CLIENT_ID, CLIENT_ID_LEN);
    sha256_update(&hc, epoch, 4);
    sha256_update(&hc, r_c, 32);
    sha256_update(&hc, srv_eph_pk, srv_eph_pk_len);
    sha256_update(&hc, ct1, ct1_len);
    sha256_update(&hc, ct2, ct2_len);
    uint8_t sig_tr[32]; sha256_final(&hc, sig_tr);
    if(crypto_sign_verify_ctx(sig, sig_len, sig_tr, 32, 0, 0, (uint8_t*)M4_SERVER_SIG_PK)!=0){ mark_off(); while(1); }

    /* decap ss1 (static), ss2 (eph) */
    crypto_kem_dec(ss1, ct1, (uint8_t*)M4_CLIENT_STATIC_SK);
    crypto_kem_dec(ss2, ct2, sk_eph);
    /* encap ss3 -> ct3 to srv_eph_pk */
    uint8_t ct3[KEM_CT];
    crypto_kem_enc(ct3, ss3, srv_eph_pk);

    /* tr = SHA256(m1 + m2 + ct3) */
    sha256_init(&hc);
    sha256_update(&hc, m1, m1_len);
    sha256_update(&hc, m2, m2_len);
    sha256_update(&hc, ct3, KEM_CT);
    sha256_final(&hc, tr);
    memcpy(x, ss1, 32); memcpy(x+32, ss2, 32); memcpy(x+64, ss3, 32);
    /* k_fin = HKDF(anchor, ss1||ss2||ss3, info="finished"+tr) == extract+expand */
    uint8_t info[8+32]; memcpy(info,"finished",8); memcpy(info+8,tr,32);
    hkdf_sha256(x, 96, M4_ANCHOR, 32, info, sizeof(info), k_fin, 32);

    /* t_c = HMAC(k_fin, tr+"CL_FIN") */
    uint8_t fin_msg[32+6]; memcpy(fin_msg, tr, 32); memcpy(fin_msg+32,"CL_FIN",6);
    uint8_t t_c[32]; hmac_sha256(k_fin, 32, fin_msg, 38, t_c);

    /* m3 = pack(ct3_len, ct3, t_c) */
    off=0;
    pack16(m3+off, KEM_CT); off+=2;
    memcpy(m3+off, ct3, KEM_CT); off+=KEM_CT;
    memcpy(m3+off, t_c, 32); off+=32;
    size_t m3_len=off;
    send_frame(m3, m3_len);

    /* --- recv m4: SERVER_FINISHED (32 bytes) --- */
    size_t m4_len=0;
    if(recv_frame(m4, &m4_len, 30000)) { mark_off(); while(1); }
    /* tr2 = SHA256(tr + m3) */
    sha256_init(&hc);
    sha256_update(&hc, tr, 32);
    sha256_update(&hc, m3, m3_len);
    sha256_final(&hc, tr2);
    uint8_t sv_msg[32+6]; memcpy(sv_msg, tr2, 32); memcpy(sv_msg+32,"SV_FIN",6);
    uint8_t expect[32]; hmac_sha256(k_fin, 32, sv_msg, 38, expect);
    int accepted = 1;
    for(int _i=0;_i<32;_i++){ if(expect[_i]!=m4[_i]){ accepted=0; break; } }
    RESULTS->accepted = (uint32_t)accepted;
    RESULTS->cycles = DWT_CYCCNT - hs_t0;
    RESULTS->done = 1;
    mark_off();

    /* transmit results frame over USART2: magic(4)+cycles(4)+accepted(4)+done(4) */
    {
        uint8_t res[16];
        uint32_t v;
        v=0x48415348; res[0]=v>>24; res[1]=v>>16; res[2]=v>>8; res[3]=v;
        v=RESULTS->cycles; res[4]=v>>24; res[5]=v>>16; res[6]=v>>8; res[7]=v;
        v=RESULTS->accepted; res[8]=v>>24; res[9]=v>>16; res[10]=v>>8; res[11]=v;
        v=RESULTS->done; res[12]=v>>24; res[13]=v>>16; res[14]=v>>8; res[15]=v;
        send_frame(res, 16);
    }

    while(1){}
}
