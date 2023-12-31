#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define CLIENT_LISTENING_PORT 8081
#define SERVER_PORT 8080

// Prototypes de fonctions
void uploadFile(const char *fileName);
void listFiles();
void downloadFile(const char *fileName);

// Fonction principale qui traite les commandes de l'utilisateur
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s -up|-list|-down [file_name]\n", argv[0]);
        return 1;
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
    FILE *file = fopen(fileName, "rb");
    if (file == NULL) {
        perror("Cannot open file");
        return;
    }

    // Envoyer d'abord un message pour indiquer au serveur qu'un fichier va être transmis
    char initMsg[BUFFER_SIZE] = {0};
    snprintf(initMsg, sizeof(initMsg), "START UPLOAD %s", fileName);
    if (sndmsg(initMsg, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to initiate upload for '%s'.\n", fileName);
        fclose(file);
        return;
    }

    char tagBuffer[] = "up: ";
    size_t tagLength = strlen(tagBuffer);
    char dataBuffer[BUFFER_SIZE - tagLength];
    char buffer[BUFFER_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(dataBuffer, 1, sizeof(dataBuffer), file)) > 0) {
        // Ajouter le tag "up: " à la variable distincte
        memcpy(buffer, tagBuffer, tagLength);
        memcpy(buffer + tagLength, dataBuffer, bytesRead);

        // Envoyer le bloc avec le tag au serveur
        if (sndmsg(buffer, SERVER_PORT) != 0) {
            fprintf(stderr, "Failed to send file data for '%s'.\n", fileName);
            break;
        }
        memset(buffer, 0, sizeof(buffer));
    }

    // Envoyer un message pour signaler la fin du transfert
    char endMsg[BUFFER_SIZE] = "END UPLOAD";
    sndmsg(endMsg, SERVER_PORT);

    fclose(file);
}



void downloadFile(const char *fileName) {
    // Démarrer le serveur d'écoute sur le client
    if (startserver(CLIENT_LISTENING_PORT) != 0) {
        fprintf(stderr, "Could not start the client server to receive the file.\n");
        return;
    }

    // Envoyer la demande de téléchargement au serveur principal
    char request[BUFFER_SIZE];
    snprintf(request, BUFFER_SIZE, "down %s %s %d", fileName, "127.0.0.1", CLIENT_LISTENING_PORT);
    if (sndmsg(request, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send download request for '%s'.\n", fileName);
        stopserver();
        return;
    }

    // Attendre et recevoir le fichier
    receiveFile(fileName);

    // Arrêter le serveur d'écoute sur le client
    stopserver();
}

void receiveFile(const char *fileName) {
    FILE *file = fopen(fileName, "wb");
    if (file == NULL) {
        perror("Cannot open file to write");
        stopserver();
        return;
    }

    // Boucle pour recevoir les données du fichier
    char buffer[BUFFER_SIZE];
    while (1) {
        if (getmsg(buffer) == 0) {
            if (strcmp(buffer, "END OF FILE") == 0) {
                break;
            }
            size_t bytesWritten = fwrite(buffer, 1, strlen(buffer), file);
            if (bytesWritten < strlen(buffer)) {
                perror("File write error");
                break;
            }
        } else {
            fprintf(stderr, "Failed to receive file data.\n");
            break;
        }
        memset(buffer, 0, sizeof(buffer));
    }
    fclose(file);
}



// Demande la liste des fichiers stockés sur le serveur
void listFiles() {
    /*if (startserver(CLIENT_LISTENING_PORT) != 0) {
        fprintf(stderr, "Could not start the client server to receive the file.\n");
        return;
    }

    char message[BUFFER_SIZE] = "list";
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send list request.\n");
        stopserver();
        return;
    }

    while (1) {
        if (getmsg(buffer) == 0) {
            if (strcmp(buffer, "END OF LIST") == 0) {
                break;
            }
            size_t bytesWritten = fwrite(buffer, 1, strlen(buffer), file);
            if (bytesWritten < strlen(buffer)) {
                perror("File write error");
                break;
            }
        } else {
            fprintf(stderr, "Failed to receive file data.\n");
            break;
        }
    }


    // Arrêter le serveur d'écoute sur le client
    stopserver();*/
}
