#include "encrypt.h"

#define PUB_KEY_LENGTH 1024  // Longueur de la clé publique
#define PRIV_KEY_LENGTH 1024 // Longueur de la clé privée
#define SHARED_KEY_SIZE 32


int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    DH *dh;
    unsigned char *clientPubKey, *clientPrivKey;
    unsigned char *serverPubKey, *serverPrivKey;

    generateKeyPair(&dh, &clientPubKey, &clientPrivKey);
    generateKeyPair(&dh, &serverPubKey, &serverPrivKey);

    // Échange de clés publiques entre le client et le serveur
    // (dans un scénario réel, cela se ferait sur un canal sécurisé)

    // Simulons l'échange en copiant les clés publiques
    memcpy(clientPubKey, serverPubKey, PUB_KEY_LENGTH);
    memcpy(serverPubKey, clientPubKey, PUB_KEY_LENGTH);

    // Maintenant, chaque partie peut dériver la clé secrète partagée
    // ICI
    unsigned char *clientSharedKey = (unsigned char *)malloc(SHARED_KEY_SIZE);
    if (!clientSharedKey) {
        perror("Erreur lors de l'allocation de mémoire pour clientSharedKey");
        exit(EXIT_FAILURE);
    }
    unsigned char *serverSharedKey = (unsigned char *)malloc(SHARED_KEY_SIZE);
    if (!serverSharedKey) {
        perror("Erreur lors de l'allocation de mémoire pour serverSharedKey");
        exit(EXIT_FAILURE);
    }

    DH_compute_key(clientSharedKey, serverPubKey, dh);
    DH_compute_key(serverSharedKey, clientPubKey, dh);

    // Vos clés partagées sont maintenant disponibles dans clientSharedKey et serverSharedKey
    // Elles peuvent être utilisées pour le chiffrement symétrique, comme avec AES.

    // Nettoyer et libérer la mémoire
    DH_free(dh);
    free(clientPubKey);
    free(clientPrivKey);

    free(serverPubKey);
    free(serverPrivKey);
    
    free(clientSharedKey);
    free(serverSharedKey);

    return 0;
}

void generateKeyPair(DH **dh, unsigned char **pubKey, unsigned char **privKey) {
    *dh = DH_new();
    if (!(*dh)) {
        perror("Erreur lors de la création de l'objet Diffie-Hellman");
        exit(EXIT_FAILURE);
    }

    // Générer les paramètres DH
    if (!DH_generate_parameters_ex(*dh, PUB_KEY_LENGTH, DH_GENERATOR_2, NULL)) {
        perror("Erreur lors de la génération des paramètres Diffie-Hellman");
        ERR_print_errors_fp(stderr);
        DH_free(*dh);
        exit(EXIT_FAILURE);
    }

    // Allouer de l'espace pour les clés publiques et privées
    *pubKey = (unsigned char *)malloc(DH_size(*dh));
    *privKey = (unsigned char *)malloc(DH_size(*dh));

    if (!(*pubKey) || !(*privKey)) {
        perror("Erreur lors de l'allocation mémoire pour les clés");
        DH_free(*dh);
        exit(EXIT_FAILURE);
    }

    // Obtenir les clés publiques et privées
    const BIGNUM *pubKeyBN, *privKeyBN;
    if (!DH_generate_key(*dh)) {
        perror("Erreur lors de la génération des clés Diffie-Hellman");
        ERR_print_errors_fp(stderr);
        DH_free(*dh);
        free(*pubKey);
        free(*privKey);
        exit(EXIT_FAILURE);
    }
    DH_get0_key(*dh, &pubKeyBN, &privKeyBN);

    // Vérifier si les clés sont valides
    if (!pubKeyBN || !privKeyBN) {
        perror("Erreur lors de l'obtention des clés publiques et privées");
        DH_free(*dh);
        free(*pubKey);
        free(*privKey);
        exit(EXIT_FAILURE);
    }

    // Copier les clés dans les buffers
    memset(*pubKey, 0, DH_size(*dh));  // Assurer que le buffer est initialisé
    BN_bn2bin(pubKeyBN, *pubKey);
    memset(*privKey, 0, DH_size(*dh));  // Assurer que le buffer est initialisé
    BN_bn2bin(privKeyBN, *privKey);
}