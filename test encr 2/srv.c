
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
#include "client.h"

#define PORT_SRV 8080
#define PORT_CLI 2047
#define BUFFER_SIZE 1024

void printHex(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
}

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
        // Fermer la connexion
        stopserver();
        perror("Erreur lors du chiffrement RSA");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return encryptedLen;
}

int main() {
    startserver(PORT_SRV);

    printf("loading keys\n");
    // Charger la clé privée du serveur
    printf("*");
    RSA *privateKey = loadPrivateKey("server-private.pem");
    printf("*\n");
    printf("*");
    RSA *publicKey = loadPublicKey("server-public.pem");
    printf("*\n");
    printf("successfuly loaded\n");

    // Attendre la demande de clé du client
    char request[BUFFER_SIZE];
    
    printf("started : waiting for client\n");

    getmsg(request);
    stopserver();
    printf("message recu : \n");
    printHex(request, strlen(request));

    printf("message recieved\n");

    printf("generate random key session\n");
    printf("*");
    // Générer une clé de session aléatoire
    unsigned char sessionKey[32];
    generateRandomKey(sessionKey, sizeof(sessionKey));
    printf("*\n");
    printf("random sessionKey :\n");
    printHex(sessionKey, strlen(sessionKey));

    printf("rsa encypt session key\n");
    printf("*");
    // Chiffrer la clé de session avec la clé publique du client
    unsigned char encryptedSessionKey[BUFFER_SIZE];
    printf("---- %s\n", encryptedSessionKey);
    int encryptedSessionKeyLen = rsaEncrypt(sessionKey, sizeof(sessionKey), publicKey, encryptedSessionKey);
    printf("send key\n");
    printf("successfuly sended");
    printf("*\n");
    printf("encryptedSessionKey : \n");
    printHex(encryptedSessionKey, strlen(encryptedSessionKey));
    printf("size of session rsa Encrypt :%d\n", encryptedSessionKeyLen);

    // Envoyer la clé de session chiffrée au client
    sndmsg(encryptedSessionKey, PORT_CLI);

    startserver(PORT_SRV);
    // Fermer la connexion

    return 0;
}