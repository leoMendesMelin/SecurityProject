CC=gcc
CFLAGS=-Wall
LIBS=-L. -lserver -lclient -lssl -lcrypto

TARGET=server

# 'all' builds the final executable
all: $(TARGET)

# Linking object files to create the executable
$(TARGET): server.o login.o
	$(CC) server.o login.o -g -o $(TARGET) $(LIBS)

# Compiling source files into object files
server.o: server.c server.h
	$(CC) $(CFLAGS) -c server.c -lssl -lcrypto

login.o: login.c login.h
	$(CC) $(CFLAGS) -c login.c

# 'clean' removes generated files during compilation
clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
