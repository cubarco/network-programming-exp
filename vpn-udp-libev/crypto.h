#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

EVP_CIPHER_CTX e_ctx;
EVP_CIPHER_CTX d_ctx;

int crypto_init(char *password);
int crypto_encrypt(unsigned char *input, unsigned char *output, int inlen);
int crypto_decrypt(unsigned char *input, unsigned char *output, int inlen);

#endif
