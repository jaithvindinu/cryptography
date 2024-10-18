#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Constants for SHA-1
#define H0_INIT 0x67452301
#define H1_INIT 0xEFCDAB89
#define H2_INIT 0x98BADCFE
#define H3_INIT 0x10325476
#define H4_INIT 0xC3D2E1F0

// Rotate left function
#define LEFT_ROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Function prototypes
void msg_schedule(const uint8_t msg[64], uint32_t w[80]);
uint32_t mod_add(uint32_t in1, uint32_t in2);
uint32_t f_stage1(uint32_t b, uint32_t c, uint32_t d);
uint32_t f_stage2(uint32_t b, uint32_t c, uint32_t d);
uint32_t f_stage3(uint32_t b, uint32_t c, uint32_t d);
uint32_t f_stage4(uint32_t b, uint32_t c, uint32_t d);
void sha1_compress(const uint8_t msg[64], uint32_t h[5]);
void sha1(const uint8_t *initial_msg, size_t initial_len, uint32_t h[5]);

// Message scheduling function
void msg_schedule(const uint8_t msg[64], uint32_t w[80])
{
    for (int i = 0; i < 16; i++)
    {
        w[i] = (msg[i * 4] << 24) | (msg[i * 4 + 1] << 16) | (msg[i * 4 + 2] << 8) | msg[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++)
    {
        w[i] = LEFT_ROTATE((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
    }
}

// Modular addition function
uint32_t mod_add(uint32_t in1, uint32_t in2)
{
    return in1 + in2;
}

// SHA-1 stage functions
uint32_t f_stage1(uint32_t b, uint32_t c, uint32_t d)
{
    return (b & c) | (~b & d);
}

uint32_t f_stage2(uint32_t b, uint32_t c, uint32_t d)
{
    return b ^ c ^ d;
}

uint32_t f_stage3(uint32_t b, uint32_t c, uint32_t d)
{
    return (b & c) | (b & d) | (c & d);
}

uint32_t f_stage4(uint32_t b, uint32_t c, uint32_t d)
{
    return b ^ c ^ d;
}

// SHA-1 compression function
void sha1_compress(const uint8_t msg[64], uint32_t h[5])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;

    // Initialize working variables
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    // Message schedule
    msg_schedule(msg, w);

    // Compression function main loop
    for (int i = 0; i < 80; i++)
    {
        if (i < 20)
        {
            temp = LEFT_ROTATE(a, 5) + f_stage1(b, c, d) + e + w[i] + 0x5A827999;
        }
        else if (i < 40)
        {
            temp = LEFT_ROTATE(a, 5) + f_stage2(b, c, d) + e + w[i] + 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            temp = LEFT_ROTATE(a, 5) + f_stage3(b, c, d) + e + w[i] + 0x8F1BBCDC;
        }
        else
        {
            temp = LEFT_ROTATE(a, 5) + f_stage4(b, c, d) + e + w[i] + 0xCA62C1D6;
        }

        e = d;
        d = c;
        c = LEFT_ROTATE(b, 30);
        b = a;
        a = temp;
    }

    // Add the compressed chunk to the current hash value
    h[0] = mod_add(h[0], a);
    h[1] = mod_add(h[1], b);
    h[2] = mod_add(h[2], c);
    h[3] = mod_add(h[3], d);
    h[4] = mod_add(h[4], e);
}

// SHA-1 function
void sha1(const uint8_t *initial_msg, size_t initial_len, uint32_t h[5])
{
    // IV
    h[0] = H0_INIT;
    h[1] = H1_INIT;
    h[2] = H2_INIT;
    h[3] = H3_INIT;
    h[4] = H4_INIT;

    // Padding
    size_t full_block_len = (((initial_len + 8) / 64) + 1) * 64;
    uint8_t msg[full_block_len];
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append a '1' bit (10000000)
    memset(msg + initial_len + 1, 0, full_block_len - initial_len - 1);

    // Append the original message length in bits at the end of the padded message
    uint64_t bits_len = 8 * initial_len; // note, SHA-1 works with bits not bytes
    msg[full_block_len - 8] = bits_len >> 56;
    msg[full_block_len - 7] = bits_len >> 48;
    msg[full_block_len - 6] = bits_len >> 40;
    msg[full_block_len - 5] = bits_len >> 32;
    msg[full_block_len - 4] = bits_len >> 24;
    msg[full_block_len - 3] = bits_len >> 16;
    msg[full_block_len - 2] = bits_len >> 8;
    msg[full_block_len - 1] = bits_len;

    // Process 512-bit chunks:
    for (int i = 0; i < full_block_len; i += 64)
    {
        sha1_compress(msg + i, h);
    }
}

int main()
{
    const char *input = "Welcome to SLIIT";

    uint32_t h[5];
    sha1((const uint8_t *)input, strlen(input), h);

    // Print resulting hash
    printf("SHA-1 hash: %08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4]);

    return 0;
}
