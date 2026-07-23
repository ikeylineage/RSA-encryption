#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "keys.h"
#include "encryption_decryption.h"

#define PUB_KEY_FILE "public.key"
#define PRIV_KEY_FILE "private.key"

// Helper function to remove trailing newline from fgets
void stripNewline(char *str) {
    str[strcspn(str, "\r\n")] = '\0';
}

// Ensures keypair exists on disk; generates a set if missing
void ensureKeysExist() {
    if (access(PUB_KEY_FILE, F_OK) != 0 || access(PRIV_KEY_FILE, F_OK) != 0) {
        printf("[+] Keys not found. Generating new 2048-bit RSA keypair...\n");
        PublicKey pub;
        PrivateKey priv;
        generateKeypair(&pub, &priv);
        savePublicKey(PUB_KEY_FILE, &pub);
        savePrivateKey(PRIV_KEY_FILE, &priv);
        freeKeys(&pub, &priv);
        printf("[+] Keys successfully saved to '%s' and '%s'.\n\n", PUB_KEY_FILE, PRIV_KEY_FILE);
    } else {
        printf("[+] Found existing key files ('%s', '%s').\n\n", PUB_KEY_FILE, PRIV_KEY_FILE);
    }
}

int main(void) {
    int choice = 0;
    char inputFile[256];
    char outputFile[256];

    printf("=========================================\n");
    printf("        RSA File Encryption Tool         \n");
    printf("=========================================\n");

    ensureKeysExist();

    while (1) {
        printf("-----------------------------------------\n");
        printf("1. Encrypt a file\n");
        printf("2. Decrypt a file\n");
        printf("3. Exit\n");
        printf("Select an option (1-3): ");

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n'); // clear invalid input
            continue;
        }
        while (getchar() != '\n'); // clear remaining newline

        if (choice == 3) {
            printf("Exiting program. Goodbye!\n");
            break;
        }

        if (choice == 1) {
            printf("\nEnter path of file to ENCRYPT: ");
            if (!fgets(inputFile, sizeof(inputFile), stdin)) continue;
            stripNewline(inputFile);

            printf("Enter destination path for ENCRYPTED file (e.g. output.enc): ");
            if (!fgets(outputFile, sizeof(outputFile), stdin)) continue;
            stripNewline(outputFile);

            PublicKey pub;
            if (loadPublicKey(PUB_KEY_FILE, &pub) != 0) {
                printf("[-] Error: Could not load public key!\n");
                continue;
            }

            printf("[*] Encrypting '%s'...\n", inputFile);
            if (encryptFile(inputFile, outputFile, &pub) == 0) {
                printf("[+] Success! Encrypted file saved to '%s'.\n", outputFile);
            } else {
                printf("[-] Error: Failed to encrypt file. Check if the input file exists.\n");
            }
            freeKeys(&pub, NULL);

        } else if (choice == 2) {
            printf("\nEnter path of file to DECRYPT: ");
            if (!fgets(inputFile, sizeof(inputFile), stdin)) continue;
            stripNewline(inputFile);

            printf("Enter destination path for DECRYPTED file (e.g. restored.txt): ");
            if (!fgets(outputFile, sizeof(outputFile), stdin)) continue;
            stripNewline(outputFile);

            PrivateKey priv;
            if (loadPrivateKey(PRIV_KEY_FILE, &priv) != 0) {
                printf("[-] Error: Could not load private key!\n");
                continue;
            }

            printf("[*] Decrypting '%s'...\n", inputFile);
            if (decryptFile(inputFile, outputFile, &priv) == 0) {
                printf("[+] Success! Decrypted file saved to '%s'.\n", outputFile);
            } else {
                printf("[-] Error: Failed to decrypt file. Check if the input file exists.\n");
            }
            freeKeys(NULL, &priv);

        } else {
            printf("Invalid option. Please enter 1, 2, or 3.\n");
        }
    }

    return 0;
}
