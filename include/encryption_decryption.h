#ifndef ENCRYPTION_DECRYPTION_H
#define ENCRYPTION_DECRYPTION_H

#include <openssl/bn.h>

int encrypt(BIGNUM *cipherText, BIGNUM *message, PublicKey *pub);
int decrypt(BIGNUM *plainText, BIGNUM *cipherText, PrivateKey *priv);
BIGNUM *stringToBN(const char *input);
char *BNToString(BIGNUM *bn);

#endif