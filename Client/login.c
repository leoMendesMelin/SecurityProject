#include "login.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
//chiffrer le fichier credentials.txt
#define USERNAME_MAX_LENGTH 256
#define PASSWORD_HASH_MAX_LENGTH 65 // SHA-256 hash strings are 64 characters plus a null terminator

void trimNewline(char* string) {
    char* newline = strchr(string, '\n');
    if (newline) *newline = '\0';
}

void readCredentials(char* username, char* passwordHash) {
    FILE* file = fopen("configuration/credentials.txt", "r");
    if (file != NULL) {
        fgets(username, USERNAME_MAX_LENGTH, file);
        trimNewline(username);
        fgets(passwordHash, PASSWORD_HASH_MAX_LENGTH, file);
        trimNewline(passwordHash);
        fclose(file);
    } else {
        perror("Failed to open credentials file");
    }
}

bool authenticateUser(const char* username, const char* passwordHash) {
    char storedUsername[USERNAME_MAX_LENGTH] = {0};
    char storedPasswordHash[PASSWORD_HASH_MAX_LENGTH] = {0};

    readCredentials(storedUsername, storedPasswordHash);

    // Debug print statements (remove from production code)
    printf("Stored Username: '%s'\n", storedUsername);
    printf("Stored Password Hash: '%s'\n", storedPasswordHash);
    printf("Given Username: '%s'\n", username);
    printf("Given Password Hash: '%s'\n", passwordHash);

    if (strcmp(username, storedUsername) == 0 && strcmp(passwordHash, storedPasswordHash) == 0) {
        printf("Authentication successful for user '%s'.\n", username);
        return true;
    } else {
        printf("Authentication failed for user '%s'.\n", username);
        return false;
    }
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
