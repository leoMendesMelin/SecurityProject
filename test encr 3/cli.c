#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "client.h"
#include "server.h"


// Bibliothèque pour la gestion des connexions
// #include "votre_bibliotheque.h"

#define SERVER_PORT 12345

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *generate_keypair() {
    RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
    return keypair;
}

int main() {
    // Initialisation des librairies OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Générer une paire de clés RSA
    RSA *keypair = generate_keypair();

    // Obtenir la clé publique du client au format PEM
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, keypair);
    char *pub_key;
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);

    // Envoyer la clé publique du client au serveur
    sndmsg(pub_key, SERVER_PORT);

    // Lancer un serveur pour recevoir la réponse
    startserver(12346);  // Utiliser un autre port pour le client

    // Recevoir la clé publique du serveur avec getmsg
    char server_pub_key[1024];
    getmsg(server_pub_key);

    // Convertir la clé publique du serveur en format RSA
    BIO *bio_pub_server = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_server, server_pub_key, strlen(server_pub_key));
    RSA *server_rsa_key = PEM_read_bio_RSAPublicKey(bio_pub_server, NULL, NULL, NULL);

     // Chiffrer le message et envoyer sa longueur et lui-même
    char plain_text[] = "hello";
    unsigned char encrypted_text[256];
    int encrypted_len = RSA_public_encrypt(strlen(plain_text), (unsigned char *)plain_text, encrypted_text, server_rsa_key, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_len == -1) {
        handleErrors();
    }

    int net_encrypted_len = htonl(encrypted_len); // Convertir en format réseau
    sndmsg((char *)&net_encrypted_len, sizeof(net_encrypted_len));
    sndmsg((char *)encrypted_text, encrypted_len);

    // Recevoir et déchiffrer la réponse
    unsigned char encrypted_response[256];
    getmsg((char *)encrypted_response);

    unsigned char decrypted_response[256];
    int decrypted_response_len = RSA_private_decrypt(encrypted_len, encrypted_response, decrypted_response, keypair, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_response_len == -1) {
        handleErrors();
    }

    // Afficher la réponse déchiffrée
    printf("Réponse du serveur: %.*s\n", decrypted_response_len, decrypted_response);

    // Libérer la mémoire et arrêter le serveur client
    stopserver();
    RSA_free(keypair);
    RSA_free(server_rsa_key);
    BIO_free_all(bio_pub);
    BIO_free_all(bio_pub_server);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
