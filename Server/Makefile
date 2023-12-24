CC=gcc
CFLAGS=-Wall
# Inclure à la fois libserver et libclient dans les bibliothèques liées
LIBS=-L. -lserver -lclient

TARGET=server

# 'all' construit l'exécutable final
all: $(TARGET)

# Édition de liens du fichier objet pour créer l'exécutable
$(TARGET): server.o
	$(CC) server.o -o $(TARGET) $(LIBS)

# Compilation du fichier source en fichier objet
server.o: encrypt.h server.c server.h
	$(CC) $(CFLAGS) -c server.c

encrypt.o: encrypt.c encrypt.h
	$(CC) $(CFLAGS) -c encrypt.c -I/usr/include/openssl -lssl -lcrypto

encrypt: encrypt.o
	$(CC) -g encrypt.o -o encrypt -I/usr/include/openssl -lssl -lcrypto


# 'clean' supprime les fichiers générés lors de la compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
