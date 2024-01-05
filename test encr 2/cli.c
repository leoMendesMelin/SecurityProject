#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
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

    // Se connecter au serveur
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Générer une paire de clés RSA
    RSA *keypair = generate_keypair();

    // Obtenir la clé publique du client au format PEM
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, keypair);
    char *pub_key;
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);

    // Envoyer la taille de la clé publique du client au serveur
    write(sockfd, &pub_key_len, sizeof(pub_key_len));

    // Envoyer la clé publique du client au serveur
    write(sockfd, pub_key, pub_key_len);

    // Recevoir la taille de la clé publique du serveur
    long server_pub_key_len;
    read(sockfd, &server_pub_key_len, sizeof(server_pub_key_len));

    // Recevoir la clé publique du serveur
    char *server_pub_key = malloc(server_pub_key_len);
    read(sockfd, server_pub_key, server_pub_key_len);

    // Convertir la clé publique du serveur en format RSA
    BIO *bio_pub_server = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_server, server_pub_key, server_pub_key_len);
    RSA *server_rsa_key = PEM_read_bio_RSAPublicKey(bio_pub_server, NULL, NULL, NULL);

    // Utiliser la clé publique du serveur pour chiffrer le message
    char plain_text[] = "hello";
    int plain_text_len = strlen(plain_text);

    unsigned char encrypted_text[256];  // Utiliser la bonne taille de données chiffrées
    int encrypted_len = RSA_public_encrypt(plain_text_len, (unsigned char *)plain_text, encrypted_text, server_rsa_key, RSA_PKCS1_OAEP_PADDING);

    // Envoyer le message chiffré au serveur
    write(sockfd, encrypted_text, encrypted_len);

    // Recevoir la réponse chiffrée du serveur
    unsigned char encrypted_response[256];
    int encrypted_response_len = read(sockfd, encrypted_response, sizeof(encrypted_response));

    // Déchiffrer la réponse avec la clé privée du client
    unsigned char decrypted_response[256];
    int decrypted_response_len = RSA_private_decrypt(encrypted_response_len, encrypted_response, decrypted_response, keypair, RSA_PKCS1_OAEP_PADDING);

    if (decrypted_response_len == -1) {
        handleErrors();
    }

    // Afficher la réponse déchiffrée
    printf("Réponse du serveur: %.*s\n", decrypted_response_len, decrypted_response);

    // Libérer la mémoire
    RSA_free(keypair);
    RSA_free(server_rsa_key);
    free(server_pub_key);
    BIO_free(bio_pub);
    BIO_free(bio_pub_server);
    ERR_free_strings();
    EVP_cleanup();
    close(sockfd);

    return 0;
}
