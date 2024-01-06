#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "server.h"
#include "client.h"

// Bibliothèque pour la gestion des connexions
// #include "votre_bibliotheque.h"

#define SERVER_PORT 12345
#define CLIENT_PORT 12346

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

    // Démarrer le serveur
    startserver(SERVER_PORT);

    // Générer une paire de clés RSA
    RSA *keypair = generate_keypair();

    // Obtenir la clé publique du serveur au format PEM
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, keypair);
    char *pub_key;
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);

    // Envoyer la clé publique du serveur au client
    sndmsg(pub_key, SERVER_PORT);

    // Attendre la connexion du client et recevoir sa clé publique
    char client_pub_key[1024];
    getmsg(client_pub_key);

    // Convertir la clé publique du client en format RSA
    BIO *bio_pub_client = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_client, client_pub_key, strlen(client_pub_key));
    RSA *client_rsa_key = PEM_read_bio_RSAPublicKey(bio_pub_client, NULL, NULL, NULL);

    // Recevoir la longueur du message chiffré
    int net_encrypted_len;
    getmsg((char *)&net_encrypted_len);
    int encrypted_len = ntohl(net_encrypted_len); // Convertir du format réseau

    // Recevoir le message chiffré
    unsigned char encrypted_text[256];
    getmsg((char *)encrypted_text);

    // Déchiffrer le message
    unsigned char decrypted_text[256];
    int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted_text, decrypted_text, keypair, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_len == -1) {
        handleErrors();
    }

    // Afficher le message déchiffré
    printf("Message du client: %.*s\n", decrypted_len, decrypted_text);

    // Chiffrer et envoyer la réponse au client
    char response[] = "hello";
    unsigned char encrypted_response[256];
    int encrypted_response_len = RSA_public_encrypt(strlen(response), (unsigned char *)response, encrypted_response, client_rsa_key, RSA_PKCS1_OAEP_PADDING);
    sndmsg((char *)encrypted_response, SERVER_PORT);

    // Libérer la mémoire et arrêter le serveur
    stopserver();
    RSA_free(keypair);
    RSA_free(client_rsa_key);
    BIO_free_all(bio_pub);
    BIO_free_all(bio_pub_client);
    ERR_free_strings();
    EVP_cleanup();

    return 0;
}
