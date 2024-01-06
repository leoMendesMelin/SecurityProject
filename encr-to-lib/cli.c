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

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define CLIENT_PORT 12346
#define BUFFER_SIZE 1024

void printHex(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
}


void sendEncrypted(char *message, char* sended, RSA *rsa_key, int port) {
    
    int message_len = strlen(message);
    unsigned char encrypted_text[BUFFER_SIZE];  // Utiliser la bonne taille de données chiffrées
    int encrypted_len = RSA_public_encrypt(message_len, (unsigned char *)message, encrypted_text, rsa_key, RSA_PKCS1_OAEP_PADDING);

    // Envoyer le message chiffré au serveur
    char *encrypted_len_str = malloc(BUFFER_SIZE);
    int hex_len = encrypted_len;
    string2hexString(encrypted_text, sended, hex_len);
    sprintf(encrypted_len_str, "%d.0", hex_len);
    sndmsg(encrypted_len_str, port);
    sndmsg(sended, port);
    return encrypted_len;
}

int getDecrypted(char *response, RSA *keypair) {   

    int encrypted_len;
    char encrypted_len_str[BUFFER_SIZE];
    getmsg(encrypted_len_str);
    encrypted_len = atoi(encrypted_len_str);

    char encrypted_text[BUFFER_SIZE];  // Utiliser la bonne taille de données chiffrées
    getmsg(encrypted_text);

    char unhex[encrypted_len*2];
    hexString2string(encrypted_text, unhex, encrypted_len*2);
    // Utiliser la clé privée du serveur pour déchiffrer le message
    int decrypted_len = RSA_private_decrypt(encrypted_len, unhex, response, keypair, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_len == -1) {
        handleErrors();
    }

    return decrypted_len;

}

void string2hexString(char* input, char* output, int size)
{
    
    int loop;
    int i;
    i = 0;
    loop = 0;

    while (loop < size) {
        sprintf((char*)(output + i), "%2.2hhX", input[loop]);
        loop += 1;
        i += 2;
    }
}

void hexString2string(const char *input, char *output, int taille)
{
    int i, j;

    if (taille % 2 != 0) {
        printf("Erreur: La taille doit être un multiple de 2.\n");
        return;
    }

    for (i = 0, j = 0; i < taille; i += 2, ++j) {
        char octet[3];
        strncpy(octet, &input[i], 2);
        octet[2] = '\0';
        output[j] = (char)strtol(octet, NULL, 16);
    }

    output[j] = '\0';
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *generate_keypair() {
    RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
    return keypair;
}


RSA *getServerKey(BIO *bio_pub) {
    // Recevoir la taille de la clé publique du client
    long pub_key_len;
    char pub_key_len_str[256];
    getmsg(pub_key_len_str);
    pub_key_len = atoi(pub_key_len_str);
    // Recevoir la clé publique du client
    
    char pub_key[BUFFER_SIZE];
    getmsg(pub_key);

    // Convertir la clé publique du client en format RSA
    bio_pub = BIO_new(BIO_s_mem());
    BIO_write(bio_pub, pub_key, pub_key_len);
    
    return PEM_read_bio_RSAPublicKey(bio_pub, NULL, NULL, NULL);
}

RSA *pairing(BIO *obtain_bio_key, char *current_key, char *current_key_size, int port) {
    sndmsg(current_key_size, port);
    sndmsg(current_key, port);
    RSA *rsa = getServerKey(obtain_bio_key);
    return rsa;
}

int main() {
    startserver(CLIENT_PORT);
    // Initialisation des librairies OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Génération RSA
    RSA *keypair;
    BIO *bio_pub;
    char *pub_key;
    keypair = generate_keypair();
    bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio_pub, keypair);
    long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);
    //tostring format
    char pub_key_len_str[256];
    sprintf(pub_key_len_str, "%d", pub_key_len);
/*
    // Envoyer la taille de la clé publique du serveur au client
    sndmsg(pub_key_len_str, SERVER_PORT);

    // Envoyer la clé publique du client au serveur
    sndmsg(pub_key, SERVER_PORT);

    // Recevoir la taille de la clé publique du serveur
    char server_pub_key_len_str[BUFFER_SIZE];
    getmsg((char*) server_pub_key_len_str);
    long server_pub_key_len = atoi(server_pub_key_len_str);

    // Recevoir la clé publique du serveur
    char *server_pub_key = malloc(server_pub_key_len);
    getmsg((char*)server_pub_key);

    // Convertir la clé publique du serveur en format RSA
    BIO *bio_pub_server = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_server, server_pub_key, server_pub_key_len);
*/
    BIO *bio_pub_server;
    RSA *server_rsa_key;
    
    //server_rsa_key = PEM_read_bio_RSAPublicKey(bio_pub_server, NULL, NULL, NULL);

    server_rsa_key = pairing(bio_pub_server, pub_key, pub_key_len_str, SERVER_PORT);

    // Utiliser la clé publique du serveur pour chiffrer le message
    char plain_text[] = "hello";
    char messageSended[BUFFER_SIZE];
    sendEncrypted(plain_text, messageSended, server_rsa_key, SERVER_PORT);

    char response[BUFFER_SIZE];

    int response_len = getDecrypted(response, keypair);

    printf("response : %.*s\n", response_len, response);
    /*
    // Recevoir la réponse chiffrée du serveur
    long encrypted_response_len;
    char *encrypted_response_len_str[256];
    getmsg(encrypted_response_len_str);

    sndmsg("", SERVER_PORT);
    encrypted_response_len = atoi(encrypted_response_len_str);

    unsigned char encrypted_response[256];  // Utiliser la bonne taille de données chiffrées
    getmsg(encrypted_response);


    // Déchiffrer la réponse avec la clé privée du client
    unsigned char decrypted_response[256];
    int decrypted_response_len = RSA_private_decrypt(encrypted_response_len, encrypted_response, decrypted_response, keypair, RSA_PKCS1_OAEP_PADDING);

    if (decrypted_response_len == -1) {
        handleErrors();
    }

    // Afficher la réponse déchiffrée
    printf("Réponse du serveur: %.*s\n", decrypted_response_len, decrypted_response);
*/
    // Libérer la mémoire
    RSA_free(keypair);
    RSA_free(server_rsa_key);
    BIO_free(bio_pub);
    ERR_free_strings();
    EVP_cleanup();
    stopserver();

    return 0;
}
