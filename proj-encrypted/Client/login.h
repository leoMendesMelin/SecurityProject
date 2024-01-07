#ifndef LOGIN_H
#define LOGIN_H

#include <stdbool.h>

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_HASH_MAX_LENGTH 65 // SHA-256 hash strings are 64 characters plus a null terminator
#define SALT_LENGTH 16

// Update the function signatures to match the new parameters
void readCredentials(char* username, char* passwordHash, char* salt);
bool readSaltForUser(const char* username, char* salt);

bool authenticateUser(const char* username, const char* password, const char* storedSalt);
void hashPassword(const char* password, const char* salt, char* passwordHash);
void generateSalt(char *salt);

#endif // LOGIN_H