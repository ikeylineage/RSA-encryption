#ifndef ENCRYPTION_DECRYPTION_H
#define ENCRYPTION_DECRYPTION_H

#include <openssl/bn.h>
#include "keys.h"

int encrypt(BIGNUM *cipherText, BIGNUM *input, PublicKey *pub);
int decrypt(BIGNUM *plainText, BIGNUM *cipherText, PrivateKey *priv);
BIGNUM *stringToBN(const char *input);
char *BNToString(BIGNUM *bn);

int encryptFile(const char *inputFile, const char *outputFile, PublicKey *pub);
int decryptFile(const char *inputFile, const char *outputFile, PrivateKey *priv);

#endif
