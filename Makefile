.PHONY: server client1 client2

CFLAGS = -I/opt/homebrew/opt/openssl/include
LDFLAGS = -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

server:
	gcc ./server.c -o server -pthread
	./server

client1:
	gcc client.c -o client $(CFLAGS) $(LDFLAGS) -pthread
	./client
	
client2:
	./client