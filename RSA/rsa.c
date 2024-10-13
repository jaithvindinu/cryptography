#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEY_LENGTH 2048
#define PUB_EXP 65537

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *createRSA(int keyLength, int pubExp) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0) handleErrors();

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void saveRSAKey(EVP_PKEY *pkey, int isPublic) {
    FILE *fp;
    if (isPublic) {
        fp = fopen("public.pem", "wb");
        PEM_write_PUBKEY(fp, pkey);
    } else {
        fp = fopen("private.pem", "wb");
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    }
    fclose(fp);
}

EVP_PKEY *loadRSAKey(int isPublic) {
    FILE *fp;
    EVP_PKEY *pkey = NULL;
    if (isPublic) {
        fp = fopen("public.pem", "rb");
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        fp = fopen("private.pem", "rb");
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    }
    fclose(fp);
    return pkey;
}

void encryptFile(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    EVP_PKEY *pkey = loadRSAKey(1);  // Load public key

    if (!in || !out || !pkey) handleErrors();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    unsigned char inBuf[256];
    unsigned char outBuf[256];
    size_t outLen;

    while (fread(inBuf, 1, sizeof(inBuf), in) > 0) {
        outLen = sizeof(outBuf);
        if (EVP_PKEY_encrypt(ctx, outBuf, &outLen, inBuf, sizeof(inBuf)) <= 0) handleErrors();
        fwrite(outBuf, 1, outLen, out);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(in);
    fclose(out);
}

void decryptFile(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    FILE *out = fopen(outfile, "wb");
    EVP_PKEY *pkey = loadRSAKey(0);  // Load private key

    if (!in || !out || !pkey) handleErrors();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    unsigned char inBuf[256];
    unsigned char outBuf[256];
    size_t outLen;

    while (fread(inBuf, 1, sizeof(inBuf), in) > 0) {
        outLen = sizeof(outBuf);
        if (EVP_PKEY_decrypt(ctx, outBuf, &outLen, inBuf, sizeof(inBuf)) <= 0) handleErrors();
        fwrite(outBuf, 1, outLen, out);
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(in);
    fclose(out);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [genkey|encrypt|decrypt] [input_file] [output_file]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Usage for key generation: %s genkey\n", argv[0]);
            return 1;
        }
        EVP_PKEY *pkey = createRSA(KEY_LENGTH, PUB_EXP);
        saveRSAKey(pkey, 1);  // Save public key
        saveRSAKey(pkey, 0);  // Save private key
        EVP_PKEY_free(pkey);
        printf("RSA key pair generated and saved.\n");
    } 
    else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage for encryption: %s encrypt [input_file] [output_file]\n", argv[0]);
            return 1;
        }
        encryptFile(argv[2], argv[3]);
        printf("File encrypted successfully.\n");
    } 
    else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage for decryption: %s decrypt [input_file] [output_file]\n", argv[0]);
            return 1;
        }
        decryptFile(argv[2], argv[3]);
        printf("File decrypted successfully.\n");
    } 
    else {
        fprintf(stderr, "Invalid operation. Use 'genkey', 'encrypt', or 'decrypt'.\n");
        return 1;
    }

    return 0;
}

