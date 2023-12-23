CC=gcc
CFLAGS=-Wall
# Assurez-vous que libclient.so et libserver.so se trouvent dans le répertoire courant
LIBS=-L. -lclient -lserver
TARGET=client

# 'all' construit l'exécutable final
all: $(TARGET)

# Édition de liens du fichier objet pour créer l'exécutable
$(TARGET): client.o
	$(CC) client.o -o $(TARGET) $(LIBS)

# Compilation du fichier source en fichier objet
client.o: client.c client.h  # Assurez-vous d'inclure client.h si le fichier client.c en dépend
	$(CC) $(CFLAGS) -c client.c

# 'clean' supprime les fichiers générés lors de la compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
