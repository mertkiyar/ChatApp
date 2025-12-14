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
        printf("Socket created successfully");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddressSize = sizeof(serverAddress);
    clientConnect = connect(clientConnect, (struct sockaddr *)&serverAddress, (socklen_t *)&serverAddressSize);
    if (clientConnect == -1)
    {
        printf("The client not connected to the server!");
    }
    else
    {
        printf("Connected to the server successfully!");
    }
}