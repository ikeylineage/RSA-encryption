#include <openssl/bn.h>
#include "keys.h"

int generateKeypair(PublicKey *pub, PrivateKey *priv) {
    BIGNUM *p = BN_new(); // prime 1
    BIGNUM *q = BN_new(); // prime 2
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p1 = BN_new();  // p-1
    BIGNUM *q1 = BN_new();  // q-1
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();

    BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

    BN_CTX *ctx = BN_CTX_new(); // scratch space for OpenSSL calculations

    BN_mul(n, p, q, ctx); // n = p * q
    BN_sub(p1, p, BN_value_one()); // p1 = (p-1)
    BN_sub(q1, q, BN_value_one()); // q1 = (q-1)
    BN_mul(phi, p1, q1, ctx); // phi = (p-1)(q-1) 
    BN_set_word(e, 65537);
    BN_mod_inverse(d, e, phi, ctx);

    pub->n = n; // store computed values in key structs
    pub->e = e;
    priv->n = n;
    priv->d = d;
    
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(p1);
    BN_free(q1);
    //n, e and d must be freed later on

    return 0;
}

void freeKeys(PublicKey *pub, PrivateKey *priv) { // frees n, e, d when no longer needed
    BN_free(pub->e);
    BN_free(pub->n);
    BN_free(priv->d);
}