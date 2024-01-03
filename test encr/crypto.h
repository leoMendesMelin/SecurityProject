#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// Charger la clé privée depuis un fichier PEM
RSA *loadPrivateKey(const char *filename);

// Charger la clé publique depuis un fichier PEM
RSA *loadPublicKey(const char *filename);

// Générer une clé de session aléatoire
void generateRandomKey(unsigned char *key, size_t keySize);

// Chiffrer avec RSA
int rsaEncrypt(const unsigned char *input, int inputLen, RSA *key, unsigned char *encrypted);

// Déchiffrer avec RSA
int rsaDecrypt(const unsigned char *encrypted, int encryptedLen, RSA *key, unsigned char *decrypted);
