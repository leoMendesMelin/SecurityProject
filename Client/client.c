#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
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

// Envoie une requête pour télécharger un fichier au serveur
void uploadFile(const char *fileName) {
    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "up %s", fileName);
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send upload request for '%s'.\n", fileName);
    }
}

// Demande la liste des fichiers stockés sur le serveur
void listFiles() {
    char message[BUFFER_SIZE] = "list";
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send list request.\n");
    }
}

// Envoie une requête pour télécharger un fichier du serveur
void downloadFile(const char *fileName) {
    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "down %s", fileName);
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send download request for '%s'.\n", fileName);
    }
}