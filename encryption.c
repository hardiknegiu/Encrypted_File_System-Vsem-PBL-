#include "encryption.h"

void xor_encrypt_buffer(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] ^= (unsigned char)XOR_KEY;
    }
}

void xor_decrypt_buffer(unsigned char *buf, size_t len) {
    xor_encrypt_buffer(buf, len);
}