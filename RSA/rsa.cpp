#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MIN_RSA_KEY_SIZE 512 // Minimum RSA key size

// Function to encode binary data to Base64
char* base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    // Create a Base64 filter BIO
    b64 = BIO_new(BIO_f_base64());
    // Create a memory BIO
    bio = BIO_new(BIO_s_mem());
    // Link the BIOs
    bio = BIO_push(b64, bio);

    // Write the data to the BIO chain
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    // Get the pointer to the data
    BIO_get_mem_ptr(bio, &buffer_ptr);

    // Allocate memory for the Base64 encoded string
    char *b64_text = (char *)malloc((buffer_ptr->length + 1) * sizeof(char));
    memcpy(b64_text, buffer_ptr->data, buffer_ptr->length);
    b64_text[buffer_ptr->length] = '\0';

    // Free the BIO chain
    BIO_free_all(bio);
    return b64_text;
}

// Function to decode Base64 data to binary
unsigned char* base64_decode(const char* base64_str, size_t *out_len) {
    BIO *bio, *b64;
    int decode_len = strlen(base64_str);
    unsigned char *buffer = (unsigned char *)malloc(decode_len);

    // Create a memory BIO from the input string
    bio = BIO_new_mem_buf(base64_str, -1);
    // Create a Base64 filter BIO
    b64 = BIO_new(BIO_f_base64());
    // Link the BIOs
    bio = BIO_push(b64, bio);

    // Read the decoded data
    *out_len = BIO_read(bio, buffer, decode_len);
    BIO_free_all(bio);

    return buffer;
}

// Function to generate RSA key pair
void generate_key(int key_size) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    // Initialize key generation
    EVP_PKEY_keygen_init(ctx);
    // Set RSA key size
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size);
    // Generate the key
    EVP_PKEY_keygen(ctx, &pkey);

    // Open files to write the keys
    FILE *private_key_file = fopen("private.pem", "wb");
    FILE *public_key_file = fopen("public.pem", "wb");

    // Write the keys to files
    PEM_write_PrivateKey(private_key_file, pkey, NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(public_key_file, pkey);

    // Close files and free resources
    fclose(private_key_file);
    fclose(public_key_file);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    printf("RSA key pair generated successfully.\n");
}

// Function to encrypt text using the public key
void encrypt_text(const char *plaintext) {
    // Read the public key from file
    FILE *pub_key_file = fopen("public.pem", "rb");
    EVP_PKEY *pkey = PEM_read_PUBKEY(pub_key_file, NULL, NULL, NULL);

    // Create encryption context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    // Set padding mode
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    // Determine the output length
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char *)plaintext, strlen(plaintext));

    // Allocate memory for the encrypted data
    unsigned char *out = OPENSSL_malloc(outlen);
    // Perform the encryption
    EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char *)plaintext, strlen(plaintext));

    // Encode the encrypted data to Base64
    char *encrypted_base64 = base64_encode(out, outlen);
    printf("Encrypted text (base64): %s\n", encrypted_base64);

    // Free resources
    OPENSSL_free(out);
    free(encrypted_base64);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// Function to decrypt text using the private key
void decrypt_text(const char *encrypted_base64) {
    // Read the private key from file
    FILE *priv_key_file = fopen("private.pem", "rb");
    EVP_PKEY *pkey = PEM_read_PrivateKey(priv_key_file, NULL, NULL, NULL);

    // Decode the Base64 input
    size_t encrypted_len;
    unsigned char *encrypted_data = base64_decode(encrypted_base64, &encrypted_len);

    // Create decryption context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    // Set padding mode
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    // Determine the output length
    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data, encrypted_len);

    // Allocate memory for the decrypted data
    unsigned char *out = OPENSSL_malloc(outlen);
    // Perform the decryption
    EVP_PKEY_decrypt(ctx, out, &outlen, encrypted_data, encrypted_len);

    // Print the decrypted text
    printf("Decrypted text: %.*s\n", (int)outlen, out);

    // Free resources
    OPENSSL_free(out);
    free(encrypted_data);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [gen|e|d] [args...]\n", argv[0]);
        return 1;
    }

    // Parse command line arguments
    if (strcmp(argv[1], "gen") == 0) {
        // Generate key pair
        if (argc != 3) {
            fprintf(stderr, "Usage: %s gen [512|1024|2048|4096]\n", argv[0]);
            return 1;
        }
        int key_size = atoi(argv[2]);
        generate_key(key_size);
    } else if (strcmp(argv[1], "e") == 0) {
        // Encrypt text
        if (argc != 3) {
            fprintf(stderr, "Usage: %s e [plaintext]\n", argv[0]);
            return 1;
        }
        encrypt_text(argv[2]);
    } else if (strcmp(argv[1], "d") == 0) {
        // Decrypt text
        if (argc != 3) {
            fprintf(stderr, "Usage: %s d [encrypted_base64]\n", argv[0]);
            return 1;
        }
        decrypt_text(argv[2]);
    } else {
        fprintf(stderr, "Invalid option. Use 'gen', 'e', or 'd'.\n");
        return 1;
    }

    return 0;
}
