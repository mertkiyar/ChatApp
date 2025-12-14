#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>

#define PORT 6378

int main()
{
    int serverSocket, serverBind, serverListen, clientAddressSize, client1Accept, client2Accept;
    struct sockaddr_in socketAddress, clientAddress;
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket == -1)
    {
        printf("Error: %s\n", strerror(errno));
    }
    else
    {
        printf("Socket created successfully!\n");
    }

    socketAddress.sin_family = AF_INET;
    socketAddress.sin_port = htons(PORT);       // host to network short
    socketAddress.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1") olsaydı sadece local'den istek kabul ederdi. Şu an her yerden kabul ediyor.

    // BIND

    serverBind = bind(serverSocket, (struct sockaddr *)&socketAddress, sizeof(socketAddress));
    if (serverBind != 0)
    {
        printf("Error: The bind operation is failed.");
    }
    else
    {
        printf("The bind operation is success!\n");
    }

    // LISTEN

    serverListen = listen(serverSocket, 2); // 2 client dinleniyor
    if (serverListen != 0)
    {
        printf("Error: The listen operation is failed.");
    }
    else
    {
        printf("Porttt %d listening!\n", ntohs(socketAddress.sin_port));
        printf("Client 1 waiting...\n");
    }

    // CLIENT 1

    clientAddressSize = sizeof(clientAddress);
    client1Accept = accept(serverSocket, (struct sockaddr *)&clientAddress, (socklen_t *)&clientAddressSize);
    if (client1Accept != 0)
    {
        printf("Error: Client 1's request rejected.\n");
    }
    else
    {
        printf("Client 1's request accepted.\n");
        printf("Client 2 waiting...\n");
    }

    // CLIENT 2

    client2Accept = accept(serverSocket, (struct sockaddr *)&clientAddress, (socklen_t *)&clientAddressSize);
    if (client2Accept != 0)
    {
        printf("Client 2's request rejected.\n");
    }
    else
    {
        printf("Client 2's request accepted.\n");
    }
}