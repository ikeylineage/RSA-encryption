#include <stdio.h>
#include <string.h>
#include "keys.h"
#include "encryption_decryption.h"
#include "tests.h"

PublicKey pub;
PrivateKey priv;


int main(void) {

    char input[100];
    generateKeypair(&pub, &priv);
    printf("-----------------------------------\n");
    printf("TEST CASE 1: INCORRECT PRIVATE KEY\n");
    printf("-----------------------------------\n");
    testWrongKey();

    printf("-----------------------------------\n");
    printf("TEST CASE 2: CORRECT PRIVATE KEY\n");
    printf("-----------------------------------\n");

    printf("please input: \n");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    BIGNUM *bn_input = stringToBN(input);
    BIGNUM *cipherText = BN_new();
    BIGNUM *plainText = BN_new();

    encrypt(cipherText, bn_input, &pub);
    printf("encrypted: %s\n", BN_bn2hex(cipherText));
    decrypt(plainText, cipherText, &priv);

    char *result = BNToString(plainText);
    printf("decrypted: %s\n", result);

    BN_free(bn_input);
    BN_free(cipherText);
    BN_free(plainText);
    free(result);
    freeKeys(&pub, &priv);

    return 0;
}