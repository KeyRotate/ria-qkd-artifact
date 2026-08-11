#ifndef USART2_H
#define USART2_H
#include <stdint.h>
#include <stddef.h>
void usart2_init(uint32_t baud);
void usart2_send(const uint8_t *p, size_t n);
int  usart2_recv_byte(uint8_t *b, uint32_t timeout_ms);
void usart2_flush(void);
size_t usart2_avail(void);
#endif
