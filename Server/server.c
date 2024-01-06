#include "server.h"
#include "login.h"
//#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>

#define BUFFER_SIZE 1024
#define SERVER_PORT 8080
#define CLIENT_LISTENING_PORT 8081

static char* path = "./files/";


// Prototypes de fonctions
void processRequest(char *buffer);
void listFiles();
void uploadFile(char *fileName);
void downloadFile(char *fileName);


void listFiles() {
    
}


bool verifyRequestDownload(const char *fileName, const char *clientAddr, unsigned short clientPort) {
    char errorMsg[BUFFER_SIZE];
    char fullPath[PATH_MAX];

    // Vérifier que le nom du fichier ne contient pas de '..' ou commence par '/'
    if (strstr(fileName, "..") != NULL || fileName[0] == '/') {
        fprintf(stderr, "Access denied: %s\n", fileName);
        snprintf(errorMsg, sizeof(errorMsg), "Access denied: %s", fileName);
        sndmsg(errorMsg, clientPort); // Envoie du message d'erreur au client
        return false;
    }

    // Construire le chemin complet en préfixant avec le chemin du dossier 'files'
    snprintf(fullPath, sizeof(fullPath), "%s%s", path, fileName);

    // Vérifier si le fichier existe
    FILE *file = fopen(fullPath, "rb");
    if (file == NULL) {
        perror("Cannot open file for reading");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Cannot open file %s for reading", fileName);
        sndmsg(errorMsg, clientPort); // Envoie du message d'erreur au client
        return false;
    }
    fclose(file); // Fermer le fichier car il sera réouvert dans downloadFile si nécessaire

    return true; // La demande est valide
}

void downloadFile(char *buffer) {
    // Extraire le nom du fichier de la commande
    char *fileName = strtok(buffer + 5, " ");
    char errorMsg[BUFFER_SIZE];


    // Extraire l'adresse IP du client et le port à partir du buffer
    char *clientAddr = strtok(NULL, " ");
    unsigned short clientPort = (unsigned short)atoi(strtok(NULL, " "));

    // Appel de la fonction de vérification
    if (!verifyRequestDownload(fileName, clientAddr, clientPort)) {
        return; // Arrêter le traitement si la vérification échoue
    }

    char fullPath[PATH_MAX];
    snprintf(fullPath, sizeof(fullPath), "%s%s", path, fileName);


    // Ouvrir le fichier pour la lecture
    FILE *file = fopen(fullPath, "rb");
    if (file == NULL) {
        perror("Cannot open file for reading");
        snprintf(errorMsg, sizeof(errorMsg), "ERROR: Cannot open file %s for reading", fileName);
        sndmsg(errorMsg, clientPort); // Envoie du message au client
        return;
    }

    // Envoyer un message au client pour indiquer le début du transfert
    char startMsg[] = "START";
    sndmsg(startMsg, clientPort);

    // Envoyer le contenu du fichier
    char fileBuffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(fileBuffer, 1, sizeof(fileBuffer), file)) > 0) {
        sndmsg(fileBuffer, clientPort);
        memset(fileBuffer, 0, sizeof(fileBuffer));
    }

    // Fermer le fichier après la lecture complète
    fclose(file);

    // Envoyer un message de fin de fichier au client
    char endMsg[] = "END OF FILE";
    sndmsg(endMsg, clientPort);
}


void processAuthRequest(char *buffer) {
    char* username = strtok(buffer, ":");
    char* passwordHash = strtok(NULL, ":");
    printf("Authenticating user %s...\n", username);
    
    // Check if username and passwordHash are not null
    if (username == NULL || passwordHash == NULL) {
        fprintf(stderr, "Authentication failed: username or password is missing.\n");
        sndmsg("AUTH_FAILED", CLIENT_PORT);
        return;
    }
    //Afficher le resultat de authenticateUser
    printf("authenticateUser(username, passwordHash) : %d\n", authenticateUser(username, passwordHash));
    if (authenticateUser(username, passwordHash)) {//Si renvoie 0 alors c'est bon
        // Authentication succeeded
        sndmsg("AUTH_SUCCESS", CLIENT_PORT);
        printf("User %s authenticated.\n", username);
    } else {//si renvoie 1 alors c'est pas bon
        // Authentication failed
        sndmsg("AUTH_FAILED", CLIENT_PORT);
        printf("Authentication failed for user %s.\n", username);
    }
}
  

// Traitement des requêtes
void processRequest(char *buffer) {

    static FILE *file = NULL;
    if (strncmp(buffer, "auth", 4) == 0) {
        processAuthRequest(buffer + 5); // Passer le buffer sans le préfixe "auth:"
    }
    
    else if (strncmp(buffer, "list", 4) == 0) {
        listFiles();
    } 
    else if (strncmp(buffer, "START UPLOAD", 12) == 0) {
        size_t lenpath = strlen(path);
        size_t lenbuffer = strlen(buffer + 13); 

        char fileName[lenpath + lenbuffer + 1];
        memcpy(fileName, path, lenpath);
        memcpy(fileName + lenpath, buffer + 13, lenbuffer);
        fileName[lenpath + lenbuffer] = '\0';

        file = fopen(fileName, "w");
        fclose(file);
        file = fopen(fileName, "ab");
        if (file == NULL) {
            perror("Cannot create file");
            return;
        }
    }
    else if(strncmp(buffer, "up: ", 4) == 0) {
        if(file != NULL)
        {
            fwrite(buffer + 4, 1, strlen(buffer+4), file);
        }
    }
    else if (strncmp(buffer, "END UPLOAD", 10) == 0) {
        if (file != NULL) {
            fclose(file);
            file = NULL;
            printf("File upload completed.\n");
        }
    } 
    else if (strncmp(buffer, "down", 4) == 0) {
        downloadFile(buffer);
    }
}


// Fonction principale
int main(int argc, char const *argv[]) {
    printf("Serveur\n");
    // Supposons que startserver initialise le serveur avec les librairies nécessaires
    char buffer[BUFFER_SIZE] = {0};
    int port = 8080; // Port sur lequel le serveur doit écouter
    if (startserver(port) != 0) {
        fprintf(stderr, "Erreur lors du démarrage du serveur.\n");
        return 1;
    }
    printf("Serveur démarré sur le port %d.\n", port);
    while (1) {
    
        getmsg(buffer);
        printf("----- Reçu: %s\n", buffer);
        processRequest(buffer);
    }

    stopserver();
    return 0;
}
