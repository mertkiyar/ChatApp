#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "crypt.c"

#define PORT 6378

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"

int chatActive = 1;

void *receiveMessage(void *socket_desc)
{
    int socket = *(int *)socket_desc;
    char buffer[1024];
    int readSize; // mesajdaki harf sayısı

    unsigned char decrypedText[1024];
    unsigned char *decodedData;
    int decodedLength;

    while ((readSize = recv(socket, buffer, 1024, 0)) > 0) // 0'dan fazla harf varken
    {
        buffer[readSize] = '\0';

        decodedData = decodeBase64(buffer, strlen(buffer), &decodedLength);
        decryptWithAES(decodedData, decodedLength, KEY, decrypedText);
        free(decodedData);

        if (strstr((char *)decrypedText, "left the chat") != NULL)
        {
            printf("\n" RED "-> %s" RESET "\n", decrypedText);
            chatActive = 0;
            close(socket);
            return NULL;
        }

        printf(YELLOW "\nOther Client:" RESET " %s \n", decrypedText);
        printf("You: ");
        fflush(stdout);
    }
    return NULL;
}

int main()
{
    int clientSocket, clientConnect, serverAddressSize;
    struct sockaddr_in serverAddress;
    char buffer[1024];

    unsigned char cipherText[1024];
    char *base64Text;
    int cipherLength;
    pthread_t recvThread;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == -1)
    {
        printf(RED "[-]" RESET " Error: %s\n", strerror(errno));
    }
    else
    {
        printf(GREEN "[+]" RESET " Socket created successfully!\n");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // CONNECT

    serverAddressSize = sizeof(serverAddress);
    clientConnect = connect(clientSocket, (struct sockaddr *)&serverAddress, serverAddressSize);
    if (clientConnect == -1)
    {
        printf(RED "[-]" RESET " The client not connected to the server! Error: %s\n", strerror(errno));
    }
    else
    {
        printf(GREEN "[+]" RESET " Connected to the server successfully!\n");
    }

    // THREAD

    int createdThread = pthread_create(&recvThread, NULL, receiveMessage, (void *)&clientSocket);
    if (createdThread < 0)
    {
        printf(RED "[-]" RESET " Error: The thread is not created.\n");
    }
    else
    {
        printf(GREEN "[+]" RESET " The thread created successfully!\n");
    }

    while (1)
    {
        printf("You: ");
        fgets(buffer, 1024, stdin);

        if (chatActive == 0)
            break;

        buffer[strcspn(buffer, "\n")] = 0;

        if (strlen(buffer) > 0)
        {
            if (strcmp(buffer, "/exit") == 0) // sohbetten çıkmak için
            {
                // send(clientSocket, buffer, strlen(buffer), 0);
                cipherLength = encryptWithAES((unsigned char *)buffer, strlen(buffer), KEY, cipherText);
                base64Text = encodeBase64(cipherText, cipherLength);

                send(clientConnect, base64Text, strlen(base64Text), 0);
                free(base64Text);

                printf("You left the chat.");
                close(clientSocket);
                break;
            }

            cipherLength = encryptWithAES((unsigned char *)buffer, strlen(buffer), KEY, cipherText);
            base64Text = encodeBase64(cipherText, cipherLength);

            send(clientSocket, base64Text, strlen(base64Text), 0);

            free(base64Text); // mesajı silmek için
        }
    }
}