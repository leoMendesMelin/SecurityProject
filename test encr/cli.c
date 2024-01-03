#include "client.h"
#include "server.h"

#include "crypto.h"

#define PORT_SRV 8080
#define PORT_CLI 8081
#define BUFFER_SIZE 1024
#define AES_KEY_SIZE 256


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

int main() {
    // Initialiser OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    // Connecter au serveur
    if (startserver(PORT_CLI) != 0) {
        fprintf(stderr, "Erreur lors de la connexion au serveur.\n");
        return 1;
    }

    RSA* privateKey = loadPrivateKey("client-private.pem");
    RSA* publicKey = loadPublicKey("client-public.pem");

    // Générer une clé de session aléatoire
    unsigned char sessionKey[AES_KEY_SIZE / 8];
    RAND_bytes(sessionKey, sizeof(sessionKey));

    // Chiffrer la clé de session avec la clé publique RSA
    unsigned char encryptedSessionKey[BUFFER_SIZE];
    int encryptedSessionKeyLen = rsaEncrypt(sessionKey, sizeof(sessionKey), publicKey, encryptedSessionKey);

    // Envoyer la clé de session chiffrée au serveur
    sndmsg(encryptedSessionKey, PORT_SRV);

    // Recevoir un message du serveur
    char receivedMessage[BUFFER_SIZE];
    getmsg(receivedMessage);
    int receivedMessageLen = strlen(receivedMessage);

    // Déchiffrer le message reçu du serveur
    unsigned char decryptedMessage[BUFFER_SIZE];
    
    printf("size of session rsa Encrypt :%d\n", receivedMessageLen);
    rsaDecrypt(receivedMessage, receivedMessageLen, privateKey, decryptedMessage);
    printf("Message reçu du serveur : %s\n", decryptedMessage);

    // Libérer la mémoire de la clé publique
    RSA_free(publicKey);

    // Fermer la connexion
    stopserver();

    return 0;
}
