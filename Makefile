.PHONY: server client1 client2

server:
	gcc ./server.c -o server -pthread
	./server

client1:
	gcc ./client.c -o client -pthread
	./client
client2:
	./client