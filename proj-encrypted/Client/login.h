#ifndef LOGIN_H
#define LOGIN_H

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_HASH_MAX_LENGTH 65 // 64 pour le hash + 1 pour le '\0'

#include <stdbool.h>

bool authenticateUser(const char* username, const char* passwordHash);
void hashPassword(const char* password, char* passwordHash);
void readCredentials(char* username, char* passwordHash);

#endif
