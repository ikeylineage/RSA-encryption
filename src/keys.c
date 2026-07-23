#include <stdio.h>
#include <openssl/bn.h>
#include "keys.h"

int generateKeypair(PublicKey *pub, PrivateKey *priv) {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();

    BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

    BN_CTX *ctx = BN_CTX_new();

    BN_mul(n, p, q, ctx);
    BN_sub(p1, p, BN_value_one());
    BN_sub(q1, q, BN_value_one());
    BN_mul(phi, p1, q1, ctx);
    BN_set_word(e, 65537);
    BN_mod_inverse(d, e, phi, ctx);

    pub->n = n;
    pub->e = e;
    priv->n = BN_dup(n);
    priv->d = d;

    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(p1);
    BN_free(q1);

    return 0;
}

void freeKeys(PublicKey *pub, PrivateKey *priv) {
    if (pub) {
        if (pub->e) BN_free(pub->e);
        if (pub->n) BN_free(pub->n);
        pub->e = NULL;
        pub->n = NULL;
    }
    if (priv) {
        if (priv->d) BN_free(priv->d);
        if (priv->n) BN_free(priv->n);
        priv->d = NULL;
        priv->n = NULL;
    }
}

int savePublicKey(const char *filename, PublicKey *pub) {
    FILE *f = fopen(filename, "w");
    if (!f) return -1;

    char *n_hex = BN_bn2hex(pub->n);
    char *e_hex = BN_bn2hex(pub->e);

    fprintf(f, "%s\n%s\n", n_hex, e_hex);

    OPENSSL_free(n_hex);
    OPENSSL_free(e_hex);
    fclose(f);
    return 0;
}

int savePrivateKey(const char *filename, PrivateKey *priv) {
    FILE *f = fopen(filename, "w");
    if (!f) return -1;

    char *n_hex = BN_bn2hex(priv->n);
    char *d_hex = BN_bn2hex(priv->d);

    fprintf(f, "%s\n%s\n", n_hex, d_hex);

    OPENSSL_free(n_hex);
    OPENSSL_free(d_hex);
    fclose(f);
    return 0;
}

int loadPublicKey(const char *filename, PublicKey *pub) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char n_hex[1024], e_hex[1024];
    if (fscanf(f, "%1023s\n%1023s", n_hex, e_hex) != 2) {
        fclose(f);
        return -1;
    }

    pub->n = BN_new();
    pub->e = BN_new();
    BN_hex2bn(&pub->n, n_hex);
    BN_hex2bn(&pub->e, e_hex);

    fclose(f);
    return 0;
}

int loadPrivateKey(const char *filename, PrivateKey *priv) {
    FILE *f = fopen(filename, "r");
    if (!f) return -1;

    char n_hex[1024], d_hex[1024];
    if (fscanf(f, "%1023s\n%1023s", n_hex, d_hex) != 2) {
        fclose(f);
        return -1;
    }

    priv->n = BN_new();
    priv->d = BN_new();
    BN_hex2bn(&priv->n, n_hex);
    BN_hex2bn(&priv->d, d_hex);

    fclose(f);
    return 0;
}
