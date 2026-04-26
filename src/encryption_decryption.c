#include <openssl/bn.h>
#include "keys.h"
#include <string.h>

int encrypt(BIGNUM *cipherText, BIGNUM *input, PublicKey *pub) {
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(cipherText, input, pub->e, pub->n, ctx); // input^e mod n
    BN_CTX_free(ctx);
    return 0; 
}

int decrypt(BIGNUM *plainText, BIGNUM *cipherText, PrivateKey *priv) {
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(plainText, cipherText, priv->d, priv->n, ctx); // cipherText^d mod n
    BN_CTX_free(ctx);
    return 0;
}

BIGNUM *stringToBN(const char *input) {
    BIGNUM *bn = BN_new();
    BN_bin2bn((unsigned char *)input, strlen(input), bn);
    return bn;
}

char *BNToString(BIGNUM *bn) {
    int len = BN_num_bytes(bn);
    char *buffer = malloc(len + 1);        // +1 for null terminator
    BN_bn2bin(bn, (unsigned char *)buffer);
    buffer[len] = '\0';                    // null terminate the string
    return buffer;
}