#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h> // mem alloc için

#define PORT 6378

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

int client1 = 0;
int client2 = 0;

void *handleClient1(void *arg)
{
    char *buffer = (char *)malloc(15 * 1024 * 1024 + 1); // şu anlık 15mb olarak yeterli gibi artırılabilir.

    if (buffer == NULL)
    {
        printf(RED "[-] " RESET "Memory Error(server/buffer)\n");
        return NULL;
    }

    int readSize;

    while ((readSize = recv(client1, buffer, 15 * 1024 * 1024, 0)) > 0)
    {
        buffer[readSize] = '\0'; // önceki mesajların üzerine yazılmasını düzeltmek için

        if (strcmp(buffer, "/exit") == 0) // client 1 ayrılırsa client 2'ye söyler
        {
            if (client2 != 0)
            {
                char *msg = "\n" RED "[-]" RESET " Client 1 left the chat.\n";
                send(client2, msg, strlen(msg), 0);
            }
            break;
        }

        if (client2 != 0)
        {
            printf(GREEN "Client 1" RESET " to" YELLOW " Client 2:" RESET " %s\n", buffer); // sunucu tarafından da görünmesi için sonradan kaldırılabilir.
            send(client2, buffer, strlen(buffer), 0);
        }
    }
    free(buffer);
    close(client1);
    client1 = 0; // bağlantı koptu veya client1 ayrıldı
    printf(RED "[-]" RESET " Client 1 left the chat.\n");
    return NULL; // thread'ı sonlandırmak için
}

void *handleClient2(void *arg)
{
    // char buffer[1024];
    char *buffer = (char *)malloc(15 * 1024 * 1024 + 1);

    if (buffer == NULL)
    {
        printf(RED "[-] " RESET "Memory Error(server/buffer)\n");
        return NULL;
    }

    int readSize;

    while ((readSize = recv(client2, buffer, 15 * 1024 * 1024, 0)) > 0)
    {
        buffer[readSize] = '\0';

        if (strcmp(buffer, "/exit") == 0) // client 2 ayrılırsa client 1'e söyle
        {
            if (client1 != 0)
            {
                char *msg = "\n" RED "[-]" RESET " Client 2 left the chat.\n";
                send(client1, msg, strlen(msg), 0);
            }
            break;
        }

        if (client1 != 0)
        {
            printf(YELLOW "Client 2" RESET " to" GREEN " Client 1: " RESET "%s\n", buffer);
            send(client1, buffer, strlen(buffer), 0);
        }
    }
    free(buffer);
    close(client2);
    client2 = 0;
    printf(RED "[-]" RESET " Client 2 left the chat.\n");
    return NULL;
}

int main()
{
    int serverSocket, serverBind, serverListen, clientAddressSize;
    struct sockaddr_in socketAddress, clientAddress;
    pthread_t thread1, thread2;

    // SOCKET

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        printf(RED "[-]" RESET " Error: %s\n", strerror(errno));
    }
    else
    {
        printf(GREEN "[+]" RESET " Socket created successfully!\n");
    }

    socketAddress.sin_family = AF_INET;
    socketAddress.sin_port = htons(PORT);       // host to network short
    socketAddress.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1") olsaydı sadece local'den istek kabul ederdi. Şu an her yerden kabul ediyor.

    // BIND

    serverBind = bind(serverSocket, (struct sockaddr *)&socketAddress, sizeof(socketAddress));
    if (serverBind != 0)
    {
        printf(RED "[-]" RESET " The bind operation is failed.\n");
        return 1; // hata gelirse devam etmesin diye 1 döndü
    }
    else
    {
        printf(GREEN "[+]" RESET " The bind operation is success!\n");
    }

    // LISTEN

    serverListen = listen(serverSocket, 2);
    if (serverListen != 0)
    {
        printf(RED "[-]" RESET " The listen operation is failed.");
        return 1;
    }
    else
    {
        printf(GREEN "[+]" RESET " Port" YELLOW " %d " RESET "is listening!\n", ntohs(socketAddress.sin_port));
        printf(YELLOW "[*]" RESET " Client 1 waiting...\n");
    }

    // CLIENT 1

    clientAddressSize = sizeof(clientAddress);
    client1 = accept(serverSocket, (struct sockaddr *)&clientAddress, (socklen_t *)&clientAddressSize);
    if (client1 < 0) // accept() 4, 5 gibi pozitif sayı döner.
    {
        printf(RED "[-]" RESET " Error: Client 1's request rejected.\n");
    }
    else
    {
        printf(GREEN "[+]" RESET " Client 1's request accepted. Client 1's socket ID: %d\n", client1);
    }
    pthread_create(&thread1, NULL, handleClient1, NULL);
    printf(YELLOW "[*]" RESET " Client 2 waiting...\n");

    // CLIENT 2

    client2 = accept(serverSocket, (struct sockaddr *)&clientAddress, (socklen_t *)&clientAddressSize);
    if (client2 < 0)
    {
        printf(RED "[-]" RESET " Client 2's request rejected.\n");
    }
    else
    {
        printf(GREEN "[+]" RESET " Client 2's request accepted. Client 2's socket ID: %d\n", client2);
    }

    pthread_create(&thread2, NULL, handleClient2, NULL);
    printf(GREEN "[+] Client 1 " RESET "and " YELLOW "Client 2 " RESET "connected to the server with" YELLOW " %d " RESET "port!\n", ntohs(socketAddress.sin_port));

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
}