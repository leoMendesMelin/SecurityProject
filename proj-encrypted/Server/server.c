#include "server.h"
#include "login.h"
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <regex.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define SERVER_PORT 8080
#define CLIENT_PORT 8081
#define MAX_FILE_SIZE 10485760

#define KEY_SIZE 512

static size_t uploadedFileSize = 0;
#define MAX_FILE_SIZE 10485760 

static char* path = "./files/";


// Prototypes de fonctions
bool processRequest(char *buffer, int size);
void listFiles();
void uploadFile(char *fileName);
void downloadFile(char *fileName, int size);


RSA *client_rsa_key;
BIO *bio_pub_client;
static FILE *file = NULL;

RSA *keypair;
BIO *bio_pub;
char *pub_key;
long pub_key_len;

//tostring format
char pub_key_len_str[KEY_SIZE];

bool want_encrypted;

void listFiles() {
    DIR *d;
    struct dirent *dir;
    d = opendir("./files/");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            // verification
            if (dir->d_type == DT_REG) {
                char fileInfo[BUFFER_SIZE];
                snprintf(fileInfo, BUFFER_SIZE, "%s\n", dir->d_name);
                sendEncrypted(fileInfo, client_rsa_key, CLIENT_PORT);
            }
        }
        closedir(d);
    }
    sendEncrypted("END OF LIST", client_rsa_key, CLIENT_PORT);
    printf("Liste des fichiers envoyée au client.\n");
}


void printHex(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
}


int sendEncrypted(char *message, RSA *rsa_key, int port) {
    char res[BUFFER_SIZE];
    int message_len = strlen(message);
    unsigned char encrypted_text[BUFFER_SIZE]; 
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

    char encrypted_text[BUFFER_SIZE];
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

RSA *getClientKey() {
    char client_pub_key_len_str[KEY_SIZE];
    getmsg(client_pub_key_len_str);
    long client_pub_key_len = atol(client_pub_key_len_str);
    if (client_pub_key_len <= 0) {
        fprintf(stderr, "Erreur: Longueur de la clé publique invalide\n");
        return NULL;
    }

    char *client_pub_key = malloc(client_pub_key_len + 1);
    if (!client_pub_key) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        return NULL;
    }

    getmsg(client_pub_key);

    BIO *bio_pub_client = BIO_new_mem_buf(client_pub_key, client_pub_key_len);
    if (!bio_pub_client) {
        fprintf(stderr, "Erreur lors de la création de BIO\n");
        free(client_pub_key);
        return NULL;
    }

    RSA *rsa_pub_key = PEM_read_bio_RSAPublicKey(bio_pub_client, NULL, NULL, NULL);
    BIO_free(bio_pub_client);
    free(client_pub_key);

    if (!rsa_pub_key) {
        fprintf(stderr, "Erreur lors de la lecture de la clé RSA depuis BIO\n");
        return NULL;
    }

    return rsa_pub_key;
}



RSA *pairing(BIO *obtain_bio_key, char *current_key, char *current_key_size, int port) {
    RSA *obtain_rsa_key = getClientKey(obtain_bio_key);
    sndmsg(current_key_size, port);
    sndmsg(current_key, port);
    return obtain_rsa_key;
}

bool sanitizeFileName(char *fileName) {
    const char *pattern = "^[a-zA-Z0-9_\\-\\.]+$"; // Autoriser uniquement les lettres, chiffres, '_', '-', et '.'
    regex_t reg;
    
    if (regcomp(&reg, pattern, REG_EXTENDED) != 0) {
        return false;
    }
    
    int status = regexec(&reg, fileName, 0, NULL, 0);
    regfree(&reg);

    return (status == 0);
}

bool isValidExtension(const char *fileName) {
    const char *validExtensions[] = {".txt", ".pdf", ".jpg", ".png"};
    const int numValidExtensions = 4;
    
    const char *extension = strrchr(fileName, '.');
    if (!extension) {
        return false;
    }

    for (int i = 0; i < numValidExtensions; i++) {
        if (strcmp(extension, validExtensions[i]) == 0) {
            return true;
        }
    }
    return false;
}

bool verifyRequestDownload(const char *fileName, const char *clientAddr, unsigned short clientPort) {
    char errorMsg[BUFFER_SIZE];
    char fullPath[BUFFER_SIZE];

    if (strstr(fileName, "..") != NULL || fileName[0] == '/') {
        fprintf(stderr, "Access denied: %s\n", fileName);
        snprintf(errorMsg, sizeof(errorMsg), "Access denied: %s", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return false;
    }

    if (!sanitizeFileName(fileName) || !isValidExtension(fileName)) {
        fprintf(stderr, "Invalid file name or type: %s\n", fileName);
        snprintf(errorMsg, sizeof(errorMsg), "Invalid file name or type: %s", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return false;
    }

    snprintf(fullPath, sizeof(fullPath), "%s%s", path, fileName);

    struct stat st;
    if (stat(fullPath, &st) < 0) {
        perror("Erreur lors de la vérification de la taille du fichier");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: File size check failed for %s", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return false;
    }

    printf("File size: %ld\n", st.st_size);

    if (st.st_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Erreur: Taille du fichier trop grande\n");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: File size too large for %s", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return false;
    }

    
    FILE *file = fopen(fullPath, "rb");
    if (file == NULL) {
        perror("Cannot open file for reading");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Cannot open file %s for reading", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return false;
    }
    fclose(file);

    return true;
}

void downloadFile(char *buffer, int size) {
    // Extraire le nom du fichier de la commande
    char *fileName = strtok(buffer + 5, " ");
    char errorMsg[BUFFER_SIZE];

    char *clientAddr = strtok(NULL, " ");
    unsigned short clientPort = (unsigned short)atoi(strtok(NULL, " "));

    // Appel de la fonction de vérification
    if (!verifyRequestDownload(fileName, clientAddr, clientPort)) {
        return;
    }

    char fullPath[BUFFER_SIZE];
    snprintf(fullPath, sizeof(fullPath), "%s%s", path, fileName);


    // Ouvrir le fichier pour la lecture
    FILE *file = fopen(fullPath, "rb");
    if (file == NULL) {
        perror("Cannot open file for reading");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Cannot open file %s for reading", fileName);
        sendEncrypted(errorMsg, client_rsa_key, clientPort);
        return;
    }

    //start download
    char startMsg[] = "START";
    sendEncrypted(startMsg, client_rsa_key, clientPort);
    printf("Sending file %s to client %s:%d\n", fileName, clientAddr, clientPort);

    // Envoyer le contenu du fichier
    char fileBuffer[BUFFER_SIZE];
    memset(fileBuffer, 0, sizeof(fileBuffer));
    size_t bytesRead;
    while ((bytesRead = fread(fileBuffer, 1, KEY_SIZE/2, file)) > 0) {
        sendEncrypted(fileBuffer, client_rsa_key, clientPort);
        memset(fileBuffer, 0, sizeof(fileBuffer));
    }

    // Fermer le fichier après la lecture complète
    fclose(file);

    // fin download
    char endMsg[] = "END OF FILE";
    sendEncrypted(endMsg, client_rsa_key, clientPort);
    printf("File %s sent to client %s:%d\n", fileName, clientAddr, clientPort);
}




bool processAuthRequest(char *buffer, int size) {
    bool is_authent = false;
    char buff[BUFFER_SIZE];
    char* username = strtok(buffer, ":");
    char* password = strtok(NULL, ":"); 
    
    printf("Authenticating user %s...\n", username);
    
    // Vérifier si le nom d'utilisateur et le mot de passe ne sont pas nuls
    if (username == NULL || password == NULL) {
        fprintf(stderr, "Authentication failed: username or password is missing.\n");
        strcpy(buff, "AUTH_FAILED");
        sendEncrypted(buff, client_rsa_key, CLIENT_PORT);
        return false;
    }
    
    char salt[SALT_LENGTH * 2 + 1]; 
    if (!readSaltForUser(username, salt)) {
        fprintf(stderr, "Failed to read salt for user %s.\n", username);
        sendEncrypted("AUTH_FAILED", client_rsa_key, CLIENT_PORT);
        return false;
    }
    // Authentifier l'utilisateur en utilisant le mot de passe et le sel
    if (authenticateUser(username, password, salt)) {
        // Authentification réussie
        strcpy(buff, "AUTH_SUCCESS");
        printf("User %s authenticated.\n", username);
        is_authent = true;
    } else {
        // Authentification échouée
        strcpy(buff, "AUTH_FAILED");
        printf("Authentication failed for user %s.\n", username);
        is_authent = false;
    }
    
    // Envoyer la réponse cryptée au client
    sendEncrypted(buff, client_rsa_key, CLIENT_PORT);
    return is_authent;
}

// Gestion du début de l'upload
bool startUpload(char *buffer, int size) {
    printf("start upload\n");
    const char *uploadPath = "./files/";
    char fileName[BUFFER_SIZE];
    char errorMsg[BUFFER_SIZE];

    char *tmpFileName = buffer + 13;
    if (tmpFileName != NULL) {
        strncpy(fileName, tmpFileName, BUFFER_SIZE - 1);
        fileName[BUFFER_SIZE - 1] = '\0';
    } else {
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Invalid command format");
        printf("ERROR: Invalid command format\n");
        sendEncrypted(errorMsg, client_rsa_key, CLIENT_PORT);
        return false;
    }

    if (strstr(fileName, "..") != NULL || fileName[0] == '/' || !sanitizeFileName(fileName) || !isValidExtension(fileName)) {
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Invalid file name or type: %s", fileName);
        printf("ERROR: Invalid file name or type: %s\n", fileName);
        sendEncrypted(errorMsg, client_rsa_key, CLIENT_PORT);
        return false;
    }

    char fullPath[BUFFER_SIZE];
    snprintf(fullPath, sizeof(fullPath), "%s%s", uploadPath, fileName);

    file = fopen(fullPath, "wb");
    if (file == NULL) {
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Cannot create file %s", fileName);
        printf("ERROR: Cannot create file %s\n", fileName);
        sendEncrypted(errorMsg, client_rsa_key, CLIENT_PORT);
        return false;
    }
    printf("File %s created\n", fileName);

    uploadedFileSize = 0;
    return true;
}




// Gestion des données d'upload
bool processUploadData(char *buffer, int size) {
    if (file != NULL) {
        size_t dataSize = size - 4;

        if (uploadedFileSize + dataSize > MAX_FILE_SIZE) {
            fprintf(stderr, "Erreur: Taille du fichier d'upload dépassée\n");
            fclose(file);
            file = NULL;
            return false;
        }

        fwrite(buffer + 4, 1, dataSize, file);
        uploadedFileSize += dataSize;
    }
    return true;
}

bool endUpload() {
    if (file != NULL) {
        fclose(file);
        file = NULL;
        printf("File upload completed.\n");
        uploadedFileSize = 0;
    }
    return false;
}
  

// Traitement des requêtes
bool processRequest(char *buffer, int size) {

    static FILE *file = NULL;
    if(strncmp(buffer, "CANCEL", size) == 0) {
        return false;
    }
    if(strncmp(buffer, "rsa encrypt", 11) == 0)
    {
        client_rsa_key = pairing(bio_pub_client, pub_key, pub_key_len_str, CLIENT_PORT);
        return true;
    }
    else if (strncmp(buffer, "auth", 4) == 0) {
        return processAuthRequest(buffer + 5, size - 5); 
    }
    
    else if (strncmp(buffer, "list", 4) == 0) {
        listFiles();
        return false;
    } 
    else if (strncmp(buffer, "START UPLOAD", 12) == 0) {
        return startUpload(buffer, size);
    }
    else if(strncmp(buffer, "up: ", 4) == 0) {
        return processUploadData(buffer, size);
    }
    else if (strncmp(buffer, "END UPLOAD", 10) == 0) {
        return endUpload();
    } 
    else if (strncmp(buffer, "down", 4) == 0) {
        downloadFile(buffer, size);
    }
    return false;
}


// Fonction principale
int main(int argc, char const *argv[]) {
    printf("Serveur\n");
    
    if (startserver(SERVER_PORT) != 0) {
        fprintf(stderr, "Erreur lors du démarrage du serveur.\n");
        return 1;
    }

    // Initialisation des librairies OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    pub_key_len = -1;
    // Génération RSA
    RSA *keypair;
    BIO *bio_pub;
    
    while(pub_key_len == -1) {
        *pub_key;
        keypair = generate_keypair();
        bio_pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio_pub, keypair);
        pub_key_len = BIO_get_mem_data(bio_pub, &pub_key);
    }
    //tostring format
    pub_key_len_str[KEY_SIZE];
    sprintf(pub_key_len_str, "%d", pub_key_len);

    printf("Serveur démarré sur le port %d.\n", SERVER_PORT);
    want_encrypted = false;
    while(1) {
        char buffer[BUFFER_SIZE] = {0};
        if(!want_encrypted) {
            getmsg(buffer);
            want_encrypted = processRequest(buffer, strlen(buffer));
        }
        else {
            int size = getDecrypted(buffer, keypair);
            want_encrypted = processRequest(buffer, size);
        }
    }

    stopserver();
    return 0;
}
