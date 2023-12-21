CC=gcc
CFLAGS=-Wall
LIBS=-L. -lclient  # Assurez-vous que libclient.so est dans le répertoire courant
TARGET=client

# 'all' construit l'exécutable final
all: $(TARGET)

# Édition de liens du fichier objet pour créer l'exécutable
$(TARGET): client.o
	$(CC) client.o -o $(TARGET) $(LIBS)

# Compilation du fichier source en fichier objet
client.o: client.c
	$(CC) $(CFLAGS) -c client.c

# 'clean' supprime les fichiers générés lors de la compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
