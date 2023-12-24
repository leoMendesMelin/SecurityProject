#include "server.h"
#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define SERVER_PORT 8080

// Prototypes de fonctions
void processRequest(char *buffer);
void listFiles();
void uploadFile(char *fileName);
void downloadFile(char *fileName);

static char* path = "./files/";

void listFiles() {
    
}

void downloadFile(char *buffer) {
    buffer = strtok(buffer + 5, " ");

    size_t lenpath = strlen(path);
    size_t lenbuffer = strlen(buffer); 

    char fileName[lenpath + lenbuffer + 1];
    memcpy(fileName, path, lenpath);
    memcpy(fileName + lenpath, buffer, lenbuffer);
    fileName[lenpath + lenbuffer] = '\0';

    char *clientAddr = strtok(NULL, " ");
    unsigned short clientPort = (unsigned short)atoi(strtok(NULL, " "));

    FILE *file = fopen(fileName, "rb");
    if (file == NULL) {
        perror("Cannot open file for reading");
        return;
    }

    char fileBuffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(fileBuffer, 1, sizeof(fileBuffer), file)) > 0) {
        // Envoyer les données lues au client
        sndmsg(fileBuffer, clientPort); // Envoyer les données formatées
        memset(fileBuffer, 0, sizeof(fileBuffer));
    }
    fclose(file);

    // Envoyer un message de fin de fichier au client
    char endMsg[] = "END OF FILE";
    sndmsg(endMsg, clientPort);
}

// Traitement des requêtes
void processRequest(char *buffer) {
    static FILE *file = NULL;
    
    if (strncmp(buffer, "list", 4) == 0) {
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
