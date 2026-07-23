#ifndef KEYS_H
#define KEYS_H

#include <openssl/bn.h>

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
} PublicKey;

typedef struct {
    BIGNUM *n;
    BIGNUM *d;
} PrivateKey;

int generateKeypair(PublicKey *pub, PrivateKey *priv);
void freeKeys(PublicKey *pub, PrivateKey *priv);

int savePublicKey(const char *filename, PublicKey *pub);
int savePrivateKey(const char *filename, PrivateKey *priv);
int loadPublicKey(const char *filename, PublicKey *pub);
int loadPrivateKey(const char *filename, PrivateKey *priv);

#endif
