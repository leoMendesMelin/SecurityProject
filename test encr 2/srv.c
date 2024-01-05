#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <arpa/inet.h>

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

    // Créer une socket pour le serveur
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_socket, 5);

    // Accepter la connexion du client
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);

    // Générer une paire de clés RSA
    RSA *keypair = generate_keypair();

    // Obtenir la clé publique du serveur au format PEM
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, keypair);
    char *pub_key;
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);

    // Envoyer la taille de la clé publique du serveur au client
    write(client_socket, &pub_key_len, sizeof(pub_key_len));

    // Envoyer la clé publique du serveur au client
    write(client_socket, pub_key, pub_key_len);

    // Recevoir la taille de la clé publique du client
    long client_pub_key_len;
    read(client_socket, &client_pub_key_len, sizeof(client_pub_key_len));

    // Recevoir la clé publique du client
    char *client_pub_key = malloc(client_pub_key_len);
    read(client_socket, client_pub_key, client_pub_key_len);

    // Convertir la clé publique du client en format RSA
    BIO *bio_pub_client = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_client, client_pub_key, client_pub_key_len);
    RSA *client_rsa_key = PEM_read_bio_RSAPublicKey(bio_pub_client, NULL, NULL, NULL);

    // Utiliser la clé publique du client pour déchiffrer le message
    unsigned char encrypted_text[256];  // Utiliser la bonne taille de données chiffrées
    int encrypted_len = read(client_socket, encrypted_text, sizeof(encrypted_text));

    // Utiliser la clé privée du serveur pour déchiffrer le message
    unsigned char decrypted_text[256];  // Utiliser la bonne taille pour le message déchiffré
    int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted_text, decrypted_text, keypair, RSA_PKCS1_OAEP_PADDING);

    if (decrypted_len == -1) {
        handleErrors();
    }

    // Afficher le message déchiffré
    printf("Message du client: %.*s\n", decrypted_len, decrypted_text);

    // Répondre au client avec "hello"
    char response[] = "hello";
    unsigned char encrypted_response[256];
    int encrypted_response_len = RSA_public_encrypt(strlen(response), (unsigned char *)response, encrypted_response, client_rsa_key, RSA_PKCS1_OAEP_PADDING);

    // Envoyer la réponse chiffrée au client
    write(client_socket, encrypted_response, encrypted_response_len);

    // Libérer la mémoire
    RSA_free(keypair);
    RSA_free(client_rsa_key);
    free(client_pub_key);
    BIO_free(bio_pub);
    BIO_free(bio_pub_client);
    ERR_free_strings();
    EVP_cleanup();
    close(client_socket);
    close(server_socket);

    return 0;
}
