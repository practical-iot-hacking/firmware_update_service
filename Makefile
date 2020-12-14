LIBS=-lcrypto
CC=gcc

# Release build, make the binary fast
CFLAGS=-Wall 

client: $(OBJ)
	$(CC) $(CFLAGS) client.c $(LIBS) -o client

server:
	$(CC) $(CFLAGS) server.c $(LIBS) -o server


.PHONY: clean
clean: 
	rm -rf *.o server client
