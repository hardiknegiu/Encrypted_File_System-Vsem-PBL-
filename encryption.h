#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>

#define XOR_KEY 0xAA  

void xor_encrypt_buffer(unsigned char *buf, size_t len);
void xor_decrypt_buffer(unsigned char *buf, size_t len);

#endif