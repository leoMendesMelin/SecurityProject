#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 1024
#define CLIENT_PORT 8081
#define SERVER_PORT 8080
#define KEY_SIZE 512

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_MAX_LENGTH 64
#define PASSWORD_HASH_MAX_LENGTH 65

// Prototypes de fonctions
void uploadFile(const char *fileName);
void listFiles();
void downloadFile(const char *fileName);

RSA *keypair;
BIO *bio_pub;
char *pub_key;
long pub_key_len;
//tostring format
char pub_key_len_str[KEY_SIZE];

char error_msg[] = "CANCEL";

BIO *bio_pub_server;
RSA *server_rsa_key;


int sendEncrypted(char *message, RSA *rsa_key, int port) {
    char res[BUFFER_SIZE];
    int message_len = strlen(message);
    unsigned char encrypted_text[BUFFER_SIZE];  // Utiliser la bonne taille de données chiffrées
    int encrypted_len = RSA_public_encrypt(message_len, (unsigned char *)message, encrypted_text, rsa_key, RSA_PKCS1_OAEP_PADDING);

    // Envoyer le message chiffré au serveur
    char *encrypted_len_str = malloc(BUFFER_SIZE);
    int hex_len = encrypted_len;
    string2hexString(encrypted_text, res, hex_len);
    sprintf(encrypted_len_str, "%d.0", hex_len);
    sndmsg(encrypted_len_str, port);
    sndmsg(res, port);
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
    RSA *keypair = RSA_generate_key(4096, 3, NULL, NULL);
    return keypair;
}

RSA *getServerKey(BIO *bio_pub) {
    // Recevoir la taille de la clé publique du client
    long pub_key_len;
    char pub_key_len_str[KEY_SIZE];
    getmsg(pub_key_len_str);
    pub_key_len = atoi(pub_key_len_str);
    // Recevoir la clé publique du client
    
    char pub_key[BUFFER_SIZE];
    getmsg(pub_key);
    printf("%s", pub_key);

    // Convertir la clé publique du client en format RSA
    bio_pub = BIO_new(BIO_s_mem());
    BIO_write(bio_pub, pub_key, pub_key_len);
    
    return PEM_read_bio_RSAPublicKey(bio_pub, NULL, NULL, NULL);
}

RSA *pairing(BIO *obtain_bio_key, char *current_key, char *current_key_size, int port) {
    char rsa_enter[BUFFER_SIZE];
    strcpy(rsa_enter, "rsa encrypt");
    sndmsg(rsa_enter, port);
    sndmsg(current_key_size, port);
    sndmsg(current_key, port);
    RSA *rsa = getServerKey(obtain_bio_key);
    return rsa;
}



// Updated authentication function
bool authentify(const char* username, const char* password) {

    char passwordHash[PASSWORD_HASH_MAX_LENGTH];
    hashPassword(password, passwordHash);

    char authMessage[BUFFER_SIZE];
    snprintf(authMessage, BUFFER_SIZE, "auth:%s:%s", username, passwordHash);

    if (sendEncrypted(authMessage, server_rsa_key, SERVER_PORT) == -1) {
        fprintf(stderr, "Failed to send authentication message.\n");
        sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
        return false;
    }

    char serverResponse[BUFFER_SIZE];
    int size = getDecrypted(serverResponse, keypair);
    if (size != -1) {
        if (strncmp(serverResponse, "AUTH_SUCCESS", size) == 0) {
            printf("Authentication successful.\n");
            return true;
        }
    }
    printf("%s\n", serverResponse);

    return false;
}


bool requestCredentialsAndAuthenticate() {
    char username[USERNAME_MAX_LENGTH];
    char password[PASSWORD_MAX_LENGTH]; // Définissez une taille maximale pour le mot de passe

    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);

    return authentify(username, password);
}

// Fonction principale qui traite les commandes de l'utilisateur
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s -up|-list|-down [file_name]\n", argv[0]);
        return 1;
    }

    // START RSA PAIRING
    startserver(CLIENT_PORT);
    // Initialisation des librairies OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();


    pub_key_len = -1;
    
    while(pub_key_len == -1) {
        // Génération RSA
        keypair = generate_keypair();
        bio_pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio_pub, keypair);
        pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);
        //tostring format
        sprintf(pub_key_len_str, "%d", pub_key_len);
    }
    server_rsa_key = pairing(bio_pub_server, pub_key, pub_key_len_str, SERVER_PORT);
    
    printf("Public Key Modulus Size: %d bytes\n", RSA_size(keypair));

    //END RSA PAIRING

    if (!requestCredentialsAndAuthenticate()) {
        fprintf(stderr, "Authentication failed.\n");
        return 1; // Termine le programme si l'authentification échoue
    }

    if (strcmp(argv[1], "-up") == 0 && argc == 3) {
        uploadFile(argv[2]);
    } else if (strcmp(argv[1], "-list") == 0) {
        listFiles();
    } else if (strcmp(argv[1], "-down") == 0 && argc == 3) {
        downloadFile(argv[2]);
    } else {
        fprintf(stderr, "Invalid command or arguments.\n");
    }

    return 0;
}




void uploadFile(const char *fileName) {
    char filePath[BUFFER_SIZE];

    snprintf(filePath, sizeof(filePath), "./files/%s", fileName); // Construire le chemin complet

    FILE *file = fopen(filePath, "rb");
    if (file == NULL) {
        perror("Cannot open file");
        sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
        return;
    }

    // Envoyer d'abord un message pour indiquer au serveur qu'un fichier va être transmis
    char initMsg[BUFFER_SIZE] = {0};
    snprintf(initMsg, sizeof(initMsg), "START UPLOAD %s", fileName);
    if (sendEncrypted(initMsg, server_rsa_key, SERVER_PORT) == -1) {
        fprintf(stderr, "Failed to initiate upload for '%s'.\n", fileName);
        fclose(file);
        sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
        return;
    }

    char tagBuffer[] = "up: ";
    size_t tagLength = strlen(tagBuffer);
    char dataBuffer[BUFFER_SIZE - tagLength];
    char buffer[BUFFER_SIZE];
    size_t bytesRead;
    
    memset(buffer, 0, sizeof(buffer));
    memset(dataBuffer, 0, sizeof(dataBuffer));

    while ((bytesRead = fread(dataBuffer, 1, KEY_SIZE/2, file)) > 0) {
        // Ajouter le tag "up: " à la variable distincte
        memcpy(buffer, tagBuffer, tagLength);
        memcpy(buffer + tagLength, dataBuffer, bytesRead);
        if(sendEncrypted(buffer, server_rsa_key, SERVER_PORT) == -1) {
            fprintf(stderr, "Failed to send file data for '%s'.\n", fileName);
            sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
            break;
        }
        memset(buffer, 0, sizeof(buffer));
    }

    // Envoyer un message pour signaler la fin du transfert
    char endMsg[BUFFER_SIZE] = "END UPLOAD";
    sendEncrypted(endMsg, server_rsa_key, SERVER_PORT);

    fclose(file);
}




void downloadFile(const char *fileName) {
    // Assurez-vous que le dossier 'files' existe
    struct stat st = {0};
    if (stat("files", &st) == -1) {
        mkdir("files", 0700);
    }
    printf("ici\n");
    // Envoyer la demande de téléchargement au serveur principal
    char request[BUFFER_SIZE];
    snprintf(request, BUFFER_SIZE, "down %s %s %d", fileName, "127.0.0.1", CLIENT_PORT);
    if (sendEncrypted(request, server_rsa_key, SERVER_PORT) == -1) {
        fprintf(stderr, "Failed to send download request for '%s'.\n", fileName);
        sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
        return;
    }
    printf("ici2\n");


    // Attendre et recevoir le fichier
    receiveFile(fileName);
}

void receiveFile(const char *fileName) {
    FILE *file = NULL;

    // Boucle pour recevoir les données du fichier
    while (1) {
        char buffer[BUFFER_SIZE];
        printf("ici3\n");
        int size = getDecrypted(buffer, keypair);
        printf("ici4\n");

        if (size != -1) {
            if (strncmp(buffer, "START", 5) == 0) {
                // Le serveur commence à envoyer le fichier.
                char savePath[PATH_MAX];
                snprintf(savePath, sizeof(savePath), "files/%s", fileName);
                file = fopen(savePath, "wb");
                if (file == NULL) {
                    perror("Cannot open file to write");
                    sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
                    return;
                }
            } else if (strncmp(buffer, "END OF FILE", 11) == 0) {
                if (file) {
                    printf("File '%s' received successfully.\n", fileName);
                    fclose(file); // Fermer le fichier.
                }
                break; // Fin du fichier, sortir de la boucle.
            } else if (file) {
                char buff[BUFFER_SIZE];
                strcpy(buff, buffer);
                size_t bytesWritten = fwrite(buff, 1, size, file);
                if (bytesWritten < size) {
                    perror("File write error");
                    fclose(file);
                    sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
                    return;
                }
            } else {
                // Afficher tout autre message reçu, qui n'est pas un message de contrôle.
                fprintf(stderr, "%.*s\n", size, buffer);
                return;
            }
        } else {
            fprintf(stderr, "Failed to receive file data.\n");
            sendEncrypted(error_msg, server_rsa_key, SERVER_PORT);
            if (file) {
                fclose(file); // Fermer le fichier en cas d'erreur.
            }
            return;
        }
    }
}



void receiveAndDisplayFileList() {
    char buffer[BUFFER_SIZE];
    char serverResponse[BUFFER_SIZE];

    while (1) {
        int size = getDecrypted(serverResponse, keypair);
        if (size == -1) {
            fprintf(stderr, "Error in receiving or decrypting message.\n");
            break;
        }

        serverResponse[size] = '\0'; 

        // Vérifier si c'est la fin de la liste
        if (strcmp(serverResponse, "END OF LIST") == 0) {
            break;
        }

        // Afficher le nom du fichier
        printf("File: %s\n", serverResponse);
        
    }
}



// Demande la liste des fichiers stockés sur le serveur
void listFiles() {
    char message[BUFFER_SIZE] = "list";
    if (sendEncrypted(message, server_rsa_key, SERVER_PORT) == -1) {
        fprintf(stderr, "Failed to send list request.\n");
        return;
    }

    receiveAndDisplayFileList();
}
