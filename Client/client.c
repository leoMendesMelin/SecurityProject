#include "client.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>

#define BUFFER_SIZE 1024
#define CLIENT_LISTENING_PORT 8081
#define SERVER_PORT 8080

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_MAX_LENGTH 64
#define PASSWORD_HASH_MAX_LENGTH 65

// Prototypes de fonctions
void uploadFile(const char *fileName);
void listFiles();
void downloadFile(const char *fileName);


bool startClientListeningServer() {
    if (startserver(CLIENT_PORT) != 0) {
        fprintf(stderr, "Could not start the client listening server.\n");
        return false;
    }
    return true;
}

// Updated authentication function
bool authentify(const char* username, const char* password) {
    if (!startClientListeningServer()) {
        return false;
    }

    char passwordHash[PASSWORD_HASH_MAX_LENGTH];
    hashPassword(password, passwordHash);

    char authMessage[BUFFER_SIZE];
    snprintf(authMessage, BUFFER_SIZE, "auth:%s:%s", username, passwordHash);
    if (sndmsg(authMessage, SERVER_PORT) != 0) {
        fprintf(stderr, "Failed to send authentication message.\n");
        stopserver(); // Stop the listening server before returning
        return false;
    }

    char serverResponse[BUFFER_SIZE];
    if (getmsg(serverResponse) == 0) {
        if (strcmp(serverResponse, "AUTH_SUCCESS") == 0) {
            printf("Authentication successful.\n");
            stopserver(); // Stop the listening server before returning
            return true;
        }
    }

    stopserver(); // Stop the listening server before returning
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
    // Assurez-vous que le dossier 'files' existe
    struct stat st = {0};
    if (stat("files", &st) == -1) {
        mkdir("files", 0700);
    }

    // Démarrer le serveur d'écoute sur le client
    if (startserver(CLIENT_PORT) != 0) {
        fprintf(stderr, "Could not start the client server to receive the file.\n");
        return;
    }

    // Envoyer la demande de téléchargement au serveur principal
    char request[BUFFER_SIZE];
    snprintf(request, BUFFER_SIZE, "down %s %s %d", fileName, "127.0.0.1", CLIENT_PORT);
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
    char buffer[BUFFER_SIZE];
    FILE *file = NULL;

    // Boucle pour recevoir les données du fichier
    while (1) {
        if (getmsg(buffer) == 0) {
            if (strncmp(buffer, "START", 5) == 0) {
                // Le serveur commence à envoyer le fichier.
                char savePath[PATH_MAX];
                snprintf(savePath, sizeof(savePath), "files/%s", fileName);
                file = fopen(savePath, "wb");
                if (file == NULL) {
                    perror("Cannot open file to write");
                    break;
                }
            } else if (strncmp(buffer, "END OF FILE", 11) == 0) {
                if (file) {
                    printf("File '%s' received successfully.\n", fileName);
                    fclose(file); // Fermer le fichier.
                }
                break; // Fin du fichier, sortir de la boucle.
            } else if (file) {
                size_t bytesToWrite = strlen(buffer);
                size_t bytesWritten = fwrite(buffer, 1, bytesToWrite, file);
                if (bytesWritten < bytesToWrite) {
                    perror("File write error");
                    fclose(file);
                    break;
                }
            } else {
                // Afficher tout autre message reçu, qui n'est pas un message de contrôle.
                fprintf(stderr, "%s\n", buffer);
            }
        } else {
            fprintf(stderr, "Failed to receive file data.\n");
            if (file) {
                fclose(file); // Fermer le fichier en cas d'erreur.
            }
            break;
        }
    }
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
