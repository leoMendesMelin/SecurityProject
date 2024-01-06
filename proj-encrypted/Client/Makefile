CC=gcc
CFLAGS=-Wall
LIBS=-L. -lssl -lclient -lserver -lcrypto  # Ajout de -lcrypto pour SHA256

TARGET=client

# 'all' builds the final executable
all: $(TARGET)

# Linking object files to create the executable
$(TARGET): client.o login.o
	$(CC) client.o login.o -o $(TARGET) $(LIBS)

# Compiling source files into object files
client.o: client.c client.h
	$(CC) $(CFLAGS) -c client.c -lssl -lcrypto

login.o: login.c login.h
	$(CC) $(CFLAGS) -c login.c

# 'clean' removes generated files during compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
