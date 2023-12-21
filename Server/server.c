#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

// Prototypes de fonctions
void processRequest(char *buffer);
void listFiles();
void uploadFile(char *fileName);
void downloadFile(char *fileName);



void listFiles() {
    // Implémenter la logique pour lister les fichiers
}

void uploadFile(char *fileName) {
    // Implémenter la logique pour recevoir et stocker un fichier
}

void downloadFile(char *fileName) {
    // Implémenter la logique pour envoyer un fichier au client
}

// Traitement des requêtes
void processRequest(char *buffer) {
    if (strncmp(buffer, "list", 4) == 0) {
        listFiles();
    } else if (strncmp(buffer, "up", 2) == 0) {
        uploadFile(buffer + 3);
    } else if (strncmp(buffer, "down", 4) == 0) {
        downloadFile(buffer + 5);
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
        printf("Reçu: %s\n", buffer);
        printf("%s", buffer);
    }

    stopserver();
    return 0;
}
