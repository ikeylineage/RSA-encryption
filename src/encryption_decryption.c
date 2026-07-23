#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "keys.h"
#include "encryption_decryption.h"

#define CHUNK_SIZE 128

int encrypt(BIGNUM *cipherText, BIGNUM *input, PublicKey *pub) {
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(cipherText, input, pub->e, pub->n, ctx);
    BN_CTX_free(ctx);
    return 0; 
}

int decrypt(BIGNUM *plainText, BIGNUM *cipherText, PrivateKey *priv) {
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(plainText, cipherText, priv->d, priv->n, ctx);
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
    char *buffer = malloc(len + 1);
    if (!buffer) return NULL;
    BN_bn2bin(bn, (unsigned char *)buffer);
    buffer[len] = '\0';
    return buffer;
}

int encryptFile(const char *inputFile, const char *outputFile, PublicKey *pub) {
    FILE *in = fopen(inputFile, "rb");
    FILE *out = fopen(outputFile, "wb");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return -1;
    }

    unsigned char buffer[CHUNK_SIZE];
    size_t bytesRead;

    BIGNUM *bn_in = BN_new();
    BIGNUM *bn_out = BN_new();

    while ((bytesRead = fread(buffer, 1, CHUNK_SIZE, in)) > 0) {
        BN_bin2bn(buffer, (int)bytesRead, bn_in);
        encrypt(bn_out, bn_in, pub);

        unsigned char encryptedBlock[256] = {0};
        int numBytes = BN_num_bytes(bn_out);
        BN_bn2bin(bn_out, encryptedBlock + (256 - numBytes));
        
        fwrite(encryptedBlock, 1, 256, out);
    }

    BN_free(bn_in);
    BN_free(bn_out);
    fclose(in);
    fclose(out);
    return 0;
}

int decryptFile(const char *inputFile, const char *outputFile, PrivateKey *priv) {
    FILE *in = fopen(inputFile, "rb");
    FILE *out = fopen(outputFile, "wb");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return -1;
    }

    unsigned char encryptedBlock[256];
    BIGNUM *bn_in = BN_new();
    BIGNUM *bn_out = BN_new();

    while (fread(encryptedBlock, 1, 256, in) == 256) {
        BN_bin2bn(encryptedBlock, 256, bn_in);
        decrypt(bn_out, bn_in, priv);

        unsigned char plainBuffer[256];
        int plainLen = BN_num_bytes(bn_out);
        BN_bn2bin(bn_out, plainBuffer);

        fwrite(plainBuffer, 1, plainLen, out);
    }

    BN_free(bn_in);
    BN_free(bn_out);
    fclose(in);
    fclose(out);
    return 0;
}
