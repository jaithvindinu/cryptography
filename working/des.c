#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "des_tables.c"

/* Function to get a bit from data */
int get_bit(uint8_t *data, int pos) {
    int byte_pos = pos / 8;
    int bit_pos = 7 - (pos % 8);
    return (data[byte_pos] >> bit_pos) & 0x01;
}

/* Function to set a bit in data */
void set_bit(uint8_t *data, int pos, int val) {
    int byte_pos = pos / 8;
    int bit_pos = 7 - (pos % 8);
    if (val)
        data[byte_pos] |= (1 << bit_pos);
    else
        data[byte_pos] &= ~(1 << bit_pos);
}

/* Permutation function */
void permute(uint8_t *in, uint8_t *out, int *table, int n) {
    memset(out, 0, (n + 7) / 8);                // Clear output buffer
    for (int i = 0; i < n; i++) {  
        int val = get_bit(in, table[i] - 1);    // Get bit from input
        set_bit(out, i, val);                   // Set bit in output
    }
}

/* Key schedule: Generate 16 subkeys */
void generate_subkeys(uint8_t *key, uint8_t subkeys[16][6]) {
    uint8_t permuted_key[7] = {0}; // 56 bits
    permute(key, permuted_key, PC1, 56);

    uint32_t C = 0, D = 0;
    // Split permuted_key into C and D
    for (int i = 0; i < 28; i++) {
        int val = get_bit(permuted_key, i);
        C |= val << (27 - i);
    }
    for (int i = 0; i < 28; i++) {
        int val = get_bit(permuted_key, i + 28);
        D |= val << (27 - i);
    }

    // Generate 16 subkeys
    for (int round = 0; round < 16; round++) {
        // Left shift C and D
        C = ((C << shifts[round]) | (C >> (28 - shifts[round]))) & 0x0FFFFFFF;
        D = ((D << shifts[round]) | (D >> (28 - shifts[round]))) & 0x0FFFFFFF;

        // Combine C and D into CD (56 bits)
        uint8_t CD[7] = {0};
        for (int i = 0; i < 28; i++) {
            int val = (C >> (27 - i)) & 0x01;
            set_bit(CD, i, val);
        }
        for (int i = 0; i < 28; i++) {
            int val = (D >> (27 - i)) & 0x01;
            set_bit(CD, i + 28, val);
        }

        // Apply PC2 to get subkey
        memset(subkeys[round], 0, 6);
        permute(CD, subkeys[round], PC2, 48);
    }
}

/* Feistel function */
void feistel(uint8_t *R, uint8_t *subkey, uint8_t *out) {
    uint8_t expanded_R[6] = {0};
    permute(R, expanded_R, E, 48);

    // XOR with subkey
    for (int i = 0; i < 6; i++) {
        expanded_R[i] ^= subkey[i];
    }

    // Apply S-boxes
    uint8_t S_output[4] = {0};
    int bit_pos = 0;
    for (int i = 0; i < 8; i++) {
        int row = ((get_bit(expanded_R, i * 6) << 1) | get_bit(expanded_R, i * 6 + 5));
        int col = 0;
        for (int j = 1; j < 5; j++) {
            col |= get_bit(expanded_R, i * 6 + j) << (4 - j);
        }

        int s_val = 0;
        switch (i) {
            case 0: s_val = S1[row][col]; break;
            case 1: s_val = S2[row][col]; break;
            case 2: s_val = S3[row][col]; break;
            case 3: s_val = S4[row][col]; break;
            case 4: s_val = S5[row][col]; break;
            case 5: s_val = S6[row][col]; break;
            case 6: s_val = S7[row][col]; break;
            case 7: s_val = S8[row][col]; break;
        }

        for (int j = 0; j < 4; j++) {
            int val = (s_val >> (3 - j)) & 0x01;
            set_bit(S_output, bit_pos++, val);
        }
    }

    // Apply P-permutation
    permute(S_output, out, P, 32);
}

/* DES encryption/decryption function */
void DES(uint8_t *input, uint8_t *output, uint8_t *key, int mode) {
    uint8_t subkeys[16][6];
    generate_subkeys(key, subkeys);

    uint8_t permuted_input[8] = {0};
    permute(input, permuted_input, IP, 64);

    uint32_t L = 0, R = 0;
    // Split permuted_input into L and R
    for (int i = 0; i < 32; i++) {
        int val = get_bit(permuted_input, i);
        L |= val << (31 - i);
    }
    for (int i = 0; i < 32; i++) {
        int val = get_bit(permuted_input, i + 32);
        R |= val << (31 - i);
    }

    for (int round = 0; round < 16; round++) {
        uint32_t previous_R = R;
        uint8_t R_block[4] = {0};
        for (int i = 0; i < 32; i++) {
            int val = (R >> (31 - i)) & 0x01;
            set_bit(R_block, i, val);
        }

        uint8_t f_output[4] = {0};
        if (mode == 0) // Encryption
            feistel(R_block, subkeys[round], f_output);
        else // Decryption
            feistel(R_block, subkeys[15 - round], f_output);

        uint32_t f = 0;
        for (int i = 0; i < 32; i++) {
            int val = get_bit(f_output, i);
            f |= val << (31 - i);
        }

        R = L ^ f;
        L = previous_R;
    }

    // Combine R and L (note the swap)
    uint8_t pre_output[8] = {0};
    for (int i = 0; i < 32; i++) {
        int val = (R >> (31 - i)) & 0x01;
        set_bit(pre_output, i, val);
    }
    for (int i = 0; i < 32; i++) {
        int val = (L >> (31 - i)) & 0x01;
        set_bit(pre_output, i + 32, val);
    }

    // Apply final permutation
    permute(pre_output, output, FP, 64);
}

/* Function to pad the last block */
void pad_block(uint8_t *block, int len) {
    uint8_t padding = 8 - (len % 8);
    for (int i = len; i < 8; i++) {
        block[i] = padding;
    }
}

/* Function to remove padding from the last block */
int remove_padding(uint8_t *block) {
    uint8_t padding = block[7];
    if (padding > 0 && padding <= 8) {
        for (int i = 8 - padding; i < 7; i++) {
            if (block[i] != padding) {
                return 8; // Invalid padding
            }
        }
        return 8 - padding;
    }
    return 8; // No padding or invalid padding
}

/* Function to encrypt a file */
void encrypt_file(const char *input_file, const char *output_file, uint8_t *key) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    
    if (!in || !out) {
        perror("Error opening files");
        exit(1);
    }

    uint8_t block[8], encrypted[8];
    int bytes_read;

    while ((bytes_read = fread(block, 1, 8, in)) > 0) {
        if (bytes_read < 8) {
            pad_block(block, bytes_read);
        }
        DES(block, encrypted, key, 0); // 0 for encryption
        fwrite(encrypted, 1, 8, out);
    }

    fclose(in);
    fclose(out);
}

/* Function to decrypt a file */
void decrypt_file(const char *input_file, const char *output_file, uint8_t *key) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    
    if (!in || !out) {
        perror("Error opening files");
        exit(1);
    }

    uint8_t block[8], decrypted[8];
    int bytes_read;
    long file_size, processed_bytes = 0;

    fseek(in, 0, SEEK_END);
    file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    while ((bytes_read = fread(block, 1, 8, in)) > 0) {
        DES(block, decrypted, key, 1); // 1 for decryption
        processed_bytes += bytes_read;
        
        if (processed_bytes == file_size) {
            // Last block, remove padding
            int valid_bytes = remove_padding(decrypted);
            fwrite(decrypted, 1, valid_bytes, out);
        } else {
            fwrite(decrypted, 1, 8, out);
        }
    }

    fclose(in);
    fclose(out);
}

/* Main function to test file encryption and decryption */
int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <e|d> <input_file> <output_file> <key>\n", argv[0]);
        return 1;
    }

    char mode = argv[1][0];
    char *input_file = argv[2];
    char *output_file = argv[3];
    char *key_str = argv[4];

    uint8_t key[8];
    if (strlen(key_str) != 16) {
        fprintf(stderr, "Key must be 16 hexadecimal characters\n");
        return 1;
    }
    for (int i = 0; i < 8; i++) {
        sscanf(&key_str[i*2], "%2hhx", &key[i]);
    }

    if (mode == 'e') {
        encrypt_file(input_file, output_file, key);
        printf("File encrypted successfully.\n");
    } else if (mode == 'd') {
        decrypt_file(input_file, output_file, key);
        printf("File decrypted successfully.\n");
    } else {
        fprintf(stderr, "Invalid mode. Use 'e' for encryption or 'd' for decryption.\n");
        return 1;
    }

    return 0;
}

/* Main function to test the DES implementation 
int main() {
    uint8_t key[8] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}; // Example 64-bit key
    uint8_t plaintext[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF}; // Example 64-bit plaintext
    uint8_t ciphertext[8];
    uint8_t decryptedtext[8];

    // Encrypt
    DES(plaintext, ciphertext, key, 0);
    printf("Ciphertext: ");
    for(int i = 0; i < 8; i++)
        printf("%02X ", ciphertext[i]);
    printf("\n");

    // Decrypt
    DES(ciphertext, decryptedtext, key, 1);
    printf("Decrypted text: ");
    for(int i = 0; i < 8; i++)
        printf("%02X ", decryptedtext[i]);
    printf("\n");

    return 0;
}
*/
