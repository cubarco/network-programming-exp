#include "common.h"
#include "crypto.h"

int u_len;
int f_len;


int crypto_init(char *password)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];

    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
            (unsigned char *)password, strlen(password), nrounds, key, iv);
    if (i != 32) {
        fprintf(stderr, "EVP_BytesToKey error\n");
        return -1;
    }

    EVP_CIPHER_CTX_init(&e_ctx);
    EVP_EncryptInit_ex(&e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(&d_ctx);
    EVP_DecryptInit_ex(&d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

int crypto_encrypt(unsigned char *input, unsigned char *output, int inlen)
{
    EVP_EncryptInit_ex(&e_ctx, NULL, NULL, NULL, NULL);
    if (1 != EVP_EncryptUpdate(&e_ctx, output, &u_len, input, inlen))
        return -1;
    if (1 != EVP_EncryptFinal_ex(&e_ctx, output + u_len, &f_len))
        return -1;

    return u_len + f_len;
}

int crypto_decrypt(unsigned char *input, unsigned char *output, int inlen)
{
    EVP_DecryptInit_ex(&d_ctx, NULL, NULL, NULL, NULL);
    if (1 != EVP_DecryptUpdate(&d_ctx, output, &u_len, input, inlen))
        return -1;
    if (1 != EVP_DecryptFinal_ex(&d_ctx, output + u_len, &f_len))
        return -1;

    return u_len + f_len;
}
