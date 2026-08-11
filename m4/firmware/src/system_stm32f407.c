/* STM32F407: configure HSE 8MHz -> PLL -> 168MHz SYSCLK (APB1=42MHz, APB2=84MHz). */
#define RCC_BASE     0x40023800UL
#define RCC_CR       (*(volatile unsigned long*)(RCC_BASE+0x00))
#define RCC_PLLCFGR  (*(volatile unsigned long*)(RCC_BASE+0x04))
#define RCC_CFGR     (*(volatile unsigned long*)(RCC_BASE+0x08))
#define RCC_AHB1ENR  (*(volatile unsigned long*)(RCC_BASE+0x30))
#define FLASH_ACR    (*(volatile unsigned long*)0x40023C00)

void SystemInit(void) {
    RCC_AHB1ENR |= 0x0FUL;                 /* GPIOA-D + FPU clock */
    *(volatile unsigned long*)0xE000ED88 |= (0xFUL<<20); /* enable FPU */

    FLASH_ACR = (FLASH_ACR & ~0xF) | 5UL;  /* 5 wait states for 168MHz */
    FLASH_ACR |= (3UL<<8);                 /* prefetch + icache + dcache */

    RCC_CR |= (1UL<<16);                   /* HSE ON */
    while(!(RCC_CR & (1UL<<17)));          /* wait HSERDY */

    /* AHB div1, APB1 div4 (42MHz), APB2 div2 (84MHz) */
    RCC_CFGR &= ~((0xFUL<<4)|(0x7UL<<10)|(0x7UL<<13));
    RCC_CFGR |=  (0x5UL<<10)|(0x4UL<<13);

    /* PLL: M=8, N=336, P=2 (168MHz), Q=7 (48MHz), src=HSE */
    RCC_PLLCFGR = 8UL | (336UL<<6) | (0UL<<16) | (7UL<<24) | (1UL<<22);

    RCC_CR |= (1UL<<24);                   /* PLL ON */
    while(!(RCC_CR & (1UL<<25)));          /* wait PLLRDY */

    RCC_CFGR = (RCC_CFGR & ~(3UL<<0)) | (2UL<<0);  /* SW=PLL */
    while(((RCC_CFGR>>2)&0x3)!=0x2);       /* wait SWS=PLL */
}
