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

    char buffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // Si bytesRead est inférieur à BUFFER_SIZE, nous sommes probablement au dernier bloc du fichier
        if (sndmsg(buffer, SERVER_PORT) != 0) {
            fprintf(stderr, "Failed to send file data for '%s'.\n", fileName);
            break;
        }
    }

    // Envoyer un message pour signaler la fin du transfert
    char endMsg[BUFFER_SIZE] = "END UPLOAD";
    sndmsg(endMsg, SERVER_PORT);

    fclose(file);
}



void downloadFile(const char *fileName) {
    // Demander au serveur d'envoyer le fichier
    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "down %s", fileName);
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send download request for '%s'.\n", fileName);
        return;
    }

    // Supposer que le serveur commence à envoyer le fichier immédiatement
    // La logique pour recevoir le fichier doit être implémentée ici.
    // Comme nous n'avons pas de méthode de réception directe, nous devons hypothétiquement
    // utiliser une fonction fournie par la bibliothèque pour recevoir des données.
    // Par exemple : receiveFile(fileName);
}



// Demande la liste des fichiers stockés sur le serveur
void listFiles() {
    char message[BUFFER_SIZE] = "list";
    if (sndmsg(message, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send list request.\n");
    }
}
