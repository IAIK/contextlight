#define PARANOID 1
#include <stdio.h>
#include "aes-ni.h"
#include "../context-light.h"

#define REPEAT 10000000

uint8_t plain[]      = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
uint8_t nospec enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0};
uint8_t cipher[]     = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
uint8_t computed_cipher[16];
uint8_t original_plain[16];
__m128i nospec key_schedule[20];

uint64_t nospecrdtsc();


int main() {
    int out = 0;

    size_t start = nospecrdtsc();
    for(size_t i = 0; i < REPEAT; i++) {
        // (i - 1) % 2 adds an artificial dependency to prevent gcc from optimizing the loop away
        aes128_load_key(enc_key + (i - 1) % 2, key_schedule);
    }
    size_t end = nospecrdtsc();
    printf("Key init: %zd cycles (%zd per key init)\n", end - start, (end - start) / REPEAT);

    memcpy(original_plain, plain, sizeof(plain));

    start = nospecrdtsc();
    for(size_t i = 0; i < REPEAT; i++) {
        aes128_enc(key_schedule, plain, computed_cipher);
        aes128_dec(key_schedule, computed_cipher, plain);
    }
    end = nospecrdtsc();
    printf("%zd cycles (%zd per enc/dec)\n", end - start, (end - start) / REPEAT);

    if(memcmp(cipher, computed_cipher, sizeof(cipher))) out = 1;
    if(memcmp(plain, original_plain, sizeof(plain))) out |= 2;

    return out;
}
