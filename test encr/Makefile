CC=gcc
CFLAGS=-Wall

# Inclure à la fois libserver et libclient dans les bibliothèques liées
LIBS=-L. -lserver -lclient

server : srv.c server.h client.h crypto.h
	$(CC) $(CFLAGS) srv.c -o srv $(LIBS) -lssl -lcrypto

client : cli.c client.h server.h crypto.h
	$(CC) $(CFLAGS) cli.c -o cli $(LIBS) -lssl -lcrypto
