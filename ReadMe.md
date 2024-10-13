DES key shoul be hexadecimal - Ex: A1B2C3D4E5F60708



#include <openssl/rsa.h>
In the code, this header was used for:

Defining the RSA structure (RSA *rsa)
Creating new RSA key pairs (RSA_generate_key_ex)
Performing encryption (RSA_public_encrypt)
Performing decryption (RSA_private_decrypt)
Managing RSA objects (RSA_new, RSA_free)


#include <openssl/pem.h>
This header was utilized for:

Writing the public key to a file (PEM_write_RSAPublicKey)
Writing the private key to a file (PEM_write_RSAPrivateKey)
Reading the public key from a file (PEM_read_RSAPublicKey)
Reading the private key from a file (PEM_read_RSAPrivateKey)


#include <openssl/err.h>
This header was used for error handling:

Printing detailed error messages (ERR_print_errors_fp)
Loading error strings (ERR_load_crypto_strings)
Cleaning up error-related resources (ERR_free_strings)







/usr/bin/time -v ./des e test/wallhaven.png test/enc.png A1B2C3D4E5F60708


gcc -o rsa rsa.c -lssl -lcrypto

/usr/bin/time -v ./rsa e This_is_a_test_message_for_RSA


docker run -it --cpus=".5" --memory="512m" alpine /bin/sh


