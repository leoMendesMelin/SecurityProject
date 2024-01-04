#include "login.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdbool.h>
//chiffrer le fichier credentials.txt
#define USERNAME_MAX_LENGTH 256
#define PASSWORD_HASH_MAX_LENGTH 65 // SHA-256 hash strings are 64 characters plus a null terminator

void readCredentials(char* username, char* passwordHash) {
    FILE* file = fopen("configuration/credentials.txt", "r");
    if (file != NULL) {
        fgets(username, USERNAME_MAX_LENGTH, file);
        // Remove newline and carriage return characters
        username[strcspn(username, "\r\n")] = 0;
        
        fgets(passwordHash, PASSWORD_HASH_MAX_LENGTH, file);
        // Remove newline and carriage return characters
        passwordHash[strcspn(passwordHash, "\r\n")] = 0;
        
        fclose(file);
    } else {
        perror("Failed to open credentials file");
    }
}

bool authenticateUser(const char* username, const char* passwordHash) {
    char storedUsername[USERNAME_MAX_LENGTH] = {0};
    char storedPasswordHash[PASSWORD_HASH_MAX_LENGTH] = {0};

    readCredentials(storedUsername, storedPasswordHash);

    int resultUsername = strcmp(username, storedUsername);
    int resultPassword = strcmp(passwordHash, storedPasswordHash);
    if(resultUsername == 0 && resultPassword == 0){
        printf("Authentification réussie\n");
        return true;
    }
    printf("Authentification échouée\n");
    return false;
}

void hashPassword(const char* password, char* passwordHash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(passwordHash + (i * 2), "%02x", hash[i]);
    }
    passwordHash[SHA256_DIGEST_LENGTH * 2] = '\0';
}
