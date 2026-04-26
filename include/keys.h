#ifndef KEYS_H
#define KEYS_H

#include <openssl/bn.h>

typedef struct {
    BIGNUM *e;
    BIGNUM *n;
} PublicKey;

typedef struct {
    BIGNUM *d;
    BIGNUM *n;
} PrivateKey;

int generateKeypair(PublicKey *pub, PrivateKey *priv);
void freeKeys(PublicKey *pub, PrivateKey *priv);
#endif