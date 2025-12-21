#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#define PORT 6378

void *receiveMessage(void *socket_desc)
{
    int socket = *(int *)socket_desc;
    char buffer[1024];
    int readSize; // mesajdaki harf sayısı

    while ((readSize = recv(socket, buffer, 1024, 0)) > 0) // 0'dan fazla harf varken
    {
        buffer[readSize] = '\0';
        printf("\n -> Other Client: %s\nYou: ", buffer);
        fflush(stdout);
    }
    return NULL;
}

int main()
{
    int clientSocket, clientConnect, serverAddressSize;
    struct sockaddr_in serverAddress;
    char buffer[1024];
    pthread_t recvThread;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == -1)
    {
        printf("[-] Error: %s\n", strerror(errno));
    }
    else
    {
        printf("[+] Socket created successfully!\n");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // CONNECT

    serverAddressSize = sizeof(serverAddress);
    clientConnect = connect(clientSocket, (struct sockaddr *)&serverAddress, serverAddressSize);
    if (clientConnect == -1)
    {
        printf("[-] The client not connected to the server! Error: %s\n", strerror(errno));
    }
    else
    {
        printf("[+] Connected to the server successfully!\n");
    }

    // THREAD

    int createdThread = pthread_create(&recvThread, NULL, receiveMessage, (void *)&clientSocket);
    if (createdThread < 0)
    {
        printf("[-] Error: The thread is not created.\n");
    }
    else
    {
        printf("[+] The thread created successfully!\n");
    }

    while (1)
    {
        printf("You: ");
        fgets(buffer, 1024, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "/exit") == 0) // sohbetten çıkmak için
        {
            close(clientSocket);
            break;
        }

        if (strlen(buffer) > 0) // boş mesaj göndermemek için
        {
            send(clientSocket, buffer, strlen(buffer), 0);
        }
    }
}