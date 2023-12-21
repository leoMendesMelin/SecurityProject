CC=gcc
CFLAGS=-Wall
# Le '-l' est suivi du nom de la bibliothèque sans 'lib' et '.so'
LIBS=-L. -lserver 

TARGET=server

# 'all' construit l'exécutable final
all: $(TARGET)

# Édition de liens du fichier objet pour créer l'exécutable
$(TARGET): server.o
	$(CC) server.o -o $(TARGET) $(LIBS)

# Compilation du fichier source en fichier objet
server.o: server.c server.h
	$(CC) $(CFLAGS) -c server.c

# 'clean' supprime les fichiers générés lors de la compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
