#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#define PORT 8080
int main()
{
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket == -1)
    {
        printf("Error: %s\n", strerror(errno));
    }
    else
    {
        printf("Socket created successfuly!\n");
    }
    struct sockaddr_in socketAdd;
    socketAdd.sin_addr.s_addr = inet_addr("127.0.0.1");
    socketAdd.sin_family = AF_INET;
    socketAdd.sin_port = htons(PORT);

    int serverBind = bind(serverSocket, (struct sockaddr *)&socketAdd, sizeof(socketAdd));
    if (serverBind == -1)
    {
        printf("Error: The bind operation is failed.");
    }
    else
    {
        printf("The bind operation is success!\n");
    }

    int serverListen = listen(serverSocket, 1);
    if (serverListen == -1)
    {
        printf("Error: The listen operation is failed.");
    }
    else
    {
        printf("Port %d listening!\n", ntohs(socketAdd.sin_port));
    }
}