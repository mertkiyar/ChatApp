#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>

#define PORT 6378

int main()
{
    int clientSocket, clientConnect, serverAddressSize;
    struct sockaddr_in serverAddress;
    char buffer[1024];

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == -1)
    {
        printf("Error: %s\n", strerror(errno));
    }
    else
    {
        printf("Socket created successfully!\n");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // CONNECT

    serverAddressSize = sizeof(serverAddress);
    clientConnect = connect(clientSocket, (struct sockaddr *)&serverAddress, serverAddressSize);
    if (clientConnect == -1)
    {
        printf("The client not connected to the server! Error: %s\n", strerror(errno));
    }
    else
    {
        printf("Connected to the server successfully!\n");
    }

    // READ / WRITE
}