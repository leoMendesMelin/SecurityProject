CC=gcc
CFLAGS=-Wall

# Inclure à la fois libserver et libclient dans les bibliothèques liées
LIBS=-L/usr/local/lib -lserver -lclient

server : srv.c server.h client.h crypto.h
	$(CC) $(CFLAGS) srv.c -o srv -lssl -lcrypto  $(LIBS)

client : cli.c client.h server.h crypto.h
	$(CC) $(CFLAGS) cli.c -o cli -lssl -lcrypto $(LIBS)
