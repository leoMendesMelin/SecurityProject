#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dh.h>

void generateKeyPair(DH **dh, unsigned char **pubKey, unsigned char **privKey);