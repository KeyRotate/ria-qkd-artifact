/* USART2 driver on PA2(TX)/PA3(RX), 8-bit, no parity, 1 stop. */
#include "usart2.h"

#define RCC_AHB1ENR  (*(volatile uint32_t*)0x40023830)
#define RCC_APB1ENR  (*(volatile uint32_t*)0x40023840)
#define GPIOA_MODER  (*(volatile uint32_t*)0x40020000)
#define GPIOA_AFRL   (*(volatile uint32_t*)0x40020020)
#define USART2_SR    (*(volatile uint32_t*)0x40004400)
#define USART2_DR    (*(volatile uint32_t*)0x40004404)
#define USART2_BRR   (*(volatile uint32_t*)0x40004408)
#define USART2_CR1   (*(volatile uint32_t*)0x4000440C)

void usart2_init(uint32_t baud){
    RCC_AHB1ENR |= (1UL<<0);            /* GPIOA */
    RCC_APB1ENR |= (1UL<<17);           /* USART2 */
    /* PA2, PA3 -> AF7 */
    GPIOA_MODER &= ~(0xF0UL);           /* clear bits [7:4] */
    GPIOA_MODER |=  (0xA0UL);           /* PA2,PA3 = AF (10) */
    GPIOA_AFRL &= ~(0xFF00UL);          /* clear AFRL bits [15:8] */
    GPIOA_AFRL |=  (0x7700UL);          /* AF7 for pins 2,3 */
    /* APB1 = 42 MHz */
    USART2_BRR = 42000000UL / baud;
    USART2_CR1 = (1UL<<13) | (1UL<<3) | (1UL<<2);  /* UE | TE | RE */
}

void usart2_send(const uint8_t *p, size_t n){
    for(size_t i=0;i<n;i++){
        while(!(USART2_SR & (1UL<<7))); /* TXE */
        USART2_DR = p[i];
    }
    while(!(USART2_SR & (1UL<<6)));     /* TC */
}

static void delay_loop(uint32_t n){ volatile uint32_t i; for(i=0;i<n;i++); }

int usart2_recv_byte(uint8_t *b, uint32_t timeout_ms){
    uint32_t t=0;
    while(!(USART2_SR & (1UL<<5))){     /* RXNE */
        delay_loop(1000);
        if(++t > timeout_ms*10) return -1;
    }
    *b = (uint8_t)USART2_DR;
    return 0;
}

size_t usart2_avail(void){
    return (USART2_SR & (1UL<<5)) ? 1 : 0;
}

void usart2_flush(void){
    while(USART2_SR & (1UL<<5)){ (void)USART2_DR; }
}
