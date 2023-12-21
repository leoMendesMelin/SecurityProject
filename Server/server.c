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
    printf("Liste des fichiers:\n");
    // Implémenter la logique pour lister les fichiers
}

void downloadFile(char *fileName) {
    printf("Requête de téléchargement du fichier '%s'.\n", fileName);
    // Implémenter la logique pour envoyer un fichier au client
}


// Traitement des requêtes
void processRequest(char *buffer){
    static FILE *file = NULL;
    if (strncmp(buffer, "list", 4) == 0) {
        listFiles();

    } 
    else if (strncmp(buffer, "START UPLOAD", 12) == 0) {
        // Extraire le nom de fichier du message
        char *fileName = buffer + 13;
        file = fopen(fileName, "wb");
        if (file == NULL) {
            perror("Cannot create file");
            return;
        }
        
    } else if (strncmp(buffer, "END UPLOAD", 10) == 0) {
        if (file != NULL) {
            fclose(file);
            file = NULL;
            printf("File upload completed.\n");
        }
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
        processRequest(buffer);
        printf("%s", buffer);
    }

    stopserver();
    return 0;
}
