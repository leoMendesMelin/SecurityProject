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

#define SERVER_PORT 12345
#define CLIENT_PORT 12346
#define BUFFER_SIZE 512

void printHex(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
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

RSA *getClientKey(BIO *bio_pub_client) {
    // Recevoir la taille de la clé publique du client
    long client_pub_key_len;
    char client_pub_key_len_str[256];
    getmsg(client_pub_key_len_str);
    client_pub_key_len = atoi(client_pub_key_len_str);
    // Recevoir la clé publique du client
    
    char client_pub_key[BUFFER_SIZE];
    getmsg(client_pub_key);

    // Convertir la clé publique du client en format RSA
    bio_pub_client = BIO_new(BIO_s_mem());
    BIO_write(bio_pub_client, client_pub_key, client_pub_key_len);
    
    return PEM_read_bio_RSAPublicKey(bio_pub_client, NULL, NULL, NULL);
}

RSA *pairing(BIO *obtain_bio_key, char *current_key, char *current_key_size, int port) {
    RSA *obtain_rsa_key = getClientKey(obtain_bio_key);
    sndmsg(current_key_size, port);
    sndmsg(current_key, port);
    return obtain_rsa_key;
}

int main() {
    startserver(SERVER_PORT);
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

    RSA *client_rsa_key;
    BIO *bio_pub_client;

    client_rsa_key = pairing(bio_pub_client, pub_key, pub_key_len_str, CLIENT_PORT);
    
    // Afficher le message déchiffré
    char decrypted_text[BUFFER_SIZE];
    int decrypted_len = getDecrypted(decrypted_text, keypair);

    printf("Message du client: %.*s\n", decrypted_len, decrypted_text);

    char sended[BUFFER_SIZE];
    sendEncrypted("hello", sended, client_rsa_key, CLIENT_PORT);

    // Libérer la mémoire
    RSA_free(keypair);
    RSA_free(client_rsa_key);
    BIO_free(bio_pub);
    ERR_free_strings();
    EVP_cleanup();
    stopserver();

    return 0;
}
