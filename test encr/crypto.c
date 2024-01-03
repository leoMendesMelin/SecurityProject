/*#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "crypto.h"

// Charger la clé privée depuis un fichier PEM
RSA *loadPrivateKey(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Erreur lors de l'ouverture du fichier de clé privée");
        exit(EXIT_FAILURE);
    }

    RSA *key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (!key) {
        perror("Erreur lors de la lecture de la clé privée");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    fclose(fp);
    return key;
}

// Charger la clé publique depuis un fichier PEM
RSA *loadPublicKey(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Erreur lors de l'ouverture du fichier de clé publique");
        exit(EXIT_FAILURE);
    }

    RSA *key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if (!key) {
        perror("Erreur lors de la lecture de la clé publique");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    fclose(fp);
    return key;
}

// Générer une clé de session aléatoire
void generateRandomKey(unsigned char *key, size_t keySize) {
    if (RAND_bytes(key, keySize) != 1) {
        perror("Erreur lors de la génération de la clé aléatoire");
        exit(EXIT_FAILURE);
    }
}

// Chiffrer avec RSA
int rsaEncrypt(const unsigned char *input, int inputLen, RSA *key, unsigned char *encrypted) {
    int encryptedLen = RSA_public_encrypt(inputLen, input, encrypted, key, RSA_PKCS1_PADDING);
    if (encryptedLen == -1) {
        perror("Erreur lors du chiffrement RSA");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return encryptedLen;
}

// Déchiffrer avec RSA
int rsaDecrypt(const unsigned char *encrypted, int encryptedLen, RSA *key, unsigned char *decrypted) {
    int decryptedLen = RSA_private_decrypt(encryptedLen, encrypted, decrypted, key, RSA_PKCS1_PADDING);
    if (decryptedLen == -1) {
        perror("Erreur lors du déchiffrement RSA");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return decryptedLen;
}
*/