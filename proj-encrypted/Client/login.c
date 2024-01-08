#include "login.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdbool.h>

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_HASH_MAX_LENGTH 65 // SHA-256 hash strings are 64 characters plus a null terminator
#define SALT_LENGTH 16
#define HASH_LENGTH 32

void readCredentials(char* username, char* passwordHash, char* salt) {
    FILE* file = fopen("configuration/credentials.txt", "r");
    if (file != NULL) {
        fgets(username, USERNAME_MAX_LENGTH, file);
        username[strcspn(username, "\r\n")] = 0;
        
        fgets(salt, SALT_LENGTH + 1, file);
        salt[strcspn(salt, "\r\n")] = 0;
        
        fgets(passwordHash, PASSWORD_HASH_MAX_LENGTH, file);
        passwordHash[strcspn(passwordHash, "\r\n")] = 0;
        printf("password hash: %s\n", passwordHash);
        
        fclose(file);
    } else {
        perror("Failed to open credentials file");
    }
}
bool readSaltForUser(const char* username, char* salt) {
    FILE* file = fopen("configuration/credentials.txt", "r");
    if (!file) {
        perror("Failed to open credentials file");
        return false;
    }

    char line[USERNAME_MAX_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        char storedUsername[USERNAME_MAX_LENGTH];
        char storedSalt[SALT_LENGTH * 2 + 1]; // SALT_LENGTH is in bytes

        // Assuming the username is on one line and the salt on the next
        strcpy(storedUsername, line);
        storedUsername[strcspn(storedUsername, "\r\n")] = 0; // Remove newline chars
        
        if (strcmp(storedUsername, username) == 0) {
            // Username matched, read the next line as salt
            if (fgets(storedSalt, sizeof(storedSalt), file)) {
                storedSalt[strcspn(storedSalt, "\r\n")] = 0; // Remove newline chars
                strcpy(salt, storedSalt);
                fclose(file);
                return true;
            }
        }

        // Skip the salt and password hash lines
        fgets(line, sizeof(line), file); // Salt line
        fgets(line, sizeof(line), file); // Password hash line
    }

    fclose(file);
    return false;
}

bool authenticateUser(const char* username, const char* password, char* storedSalt) {
    char storedUsername[USERNAME_MAX_LENGTH] = {0};
    char storedPasswordHash[PASSWORD_HASH_MAX_LENGTH] = {0};
    char salt[SALT_LENGTH + 1] = {0};

    readCredentials(storedUsername, storedPasswordHash, salt);

    char hash[PASSWORD_HASH_MAX_LENGTH];
    hashPassword(password, salt, hash);
    printf("hash: %s\n", hash);
    printf("storedPasswordHash: %s\n", storedPasswordHash);
    printf("username: %s\n", username);
    printf("storedUsername: %s\n", storedUsername);

    int resultUsername = strcmp(username, storedUsername);
    int resultPassword = strcmp(hash, storedPasswordHash);
    //afficher les valeurs de resultUsername et resultPassword
    if(resultUsername == 0 && resultPassword == 0){
        printf("Authentification réussie\n");
        return true;
    }
    printf("Authentification échouée\n");
    return false;
}

void hashPassword(const char* password, const char* salt, char* passwordHash) {
    unsigned char hash[HASH_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt, strlen(salt)); 
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < HASH_LENGTH; i++) {
        sprintf(passwordHash + (i * 2), "%02x", hash[i]);
    }
    passwordHash[HASH_LENGTH * 2] = '\0';
}

void generateSalt(char *salt) {
    unsigned char buffer[SALT_LENGTH];
    if (!RAND_bytes(buffer, sizeof(buffer))) {
        perror("Failed to generate random salt");
        exit(1); 
    }

    for (int i = 0; i < SALT_LENGTH; i++) {
        sprintf(salt + (i * 2), "%02x", buffer[i]);
    }
    salt[SALT_LENGTH * 2] = '\0';
}