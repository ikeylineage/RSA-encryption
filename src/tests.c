#include <stdio.h>
#include <openssl/bn.h>
#include "keys.h"
#include "encryption_decryption.h"
#include "tests.h"

void testWrongKey(void) { // test case: wrong key
    // generate keys
    PublicKey pub;
    PrivateKey priv;
    generateKeypair(&pub, &priv);

    // encrypt a test message
    BIGNUM *message = stringToBN("hello");
    BIGNUM *cipherText = BN_new();
    encrypt(cipherText, message, &pub);

    // try decrypting with wrong key
    PrivateKey fakePriv;
    fakePriv.n = priv.n;
    fakePriv.d = BN_new();
    BN_rand(fakePriv.d, 1024, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY);

    BIGNUM *wrongPlainText = BN_new();
    decrypt(wrongPlainText, cipherText, &fakePriv);

    char *wrongResult = BNToString(wrongPlainText);
    printf("wrong key result: %s\n", wrongResult);

    BN_free(message);
    BN_free(cipherText);
    BN_free(fakePriv.d);
    BN_free(wrongPlainText);
    free(wrongResult);
    freeKeys(&pub, &priv);
}