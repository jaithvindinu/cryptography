# Compile RSA program
```bash
g++ -o rsa rsa.c -lssl -lcrypto
```

# Key generation
```bash
./rsa gen <key_size[512|1024|2048|4096]>
```
- key will be automatically saved in current directly `public.pem` and `private.pem`

# Encrypt RSA program
```bash
./rsa e <input_string>
```
- saved key in `public.pem` will be used to encrypt the input string

# Decrypt RSA program
```bash
./rsa d <input_string>
```
- saved key in `private.pem` will be used to decrypt the input string


